use std::fmt;
use std::io::Write;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use tracing::field::{Field, Visit};
use tracing::span;
use tracing::{Event, Level, Metadata, Subscriber as TracingSubscriber};

use super::filter::Filter;
use super::format::{self, FieldValue, Fields, Timestamp};
use crate::cli::LogFormat;

pub(crate) struct Subscriber {
    filter: Filter,
    format: LogFormat,
    color: bool,
    next_span: AtomicU64,
    writer: Mutex<Box<dyn Write + Send>>,
}

impl Subscriber {
    pub(crate) fn new(
        filter: Filter,
        format: LogFormat,
        color: bool,
        writer: Box<dyn Write + Send>,
    ) -> Self {
        Self {
            filter,
            format,
            color,
            next_span: AtomicU64::new(0),
            writer: Mutex::new(writer),
        }
    }

    fn write(&self, level: Level, target: &str, fields: &Fields) {
        let timestamp = Timestamp::now();
        let mut writer = self
            .writer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _ = format::write(
            &mut **writer,
            self.format,
            timestamp,
            level,
            target,
            fields,
            self.color,
        );
        let _ = writer.flush();
    }

    pub(crate) fn write_log(&self, level: Level, target: &str, message: &str) {
        if !self.filter.enabled(level, target) {
            return;
        }
        let fields = Fields {
            message: Some(message.to_owned()),
            values: Vec::new(),
        };
        self.write(level, target, &fields);
    }

    pub(crate) fn max_log_level(&self) -> log::LevelFilter {
        match self.filter.max_level().into_level() {
            None => log::LevelFilter::Off,
            Some(Level::ERROR) => log::LevelFilter::Error,
            Some(Level::WARN) => log::LevelFilter::Warn,
            Some(Level::INFO) => log::LevelFilter::Info,
            Some(Level::DEBUG) => log::LevelFilter::Debug,
            Some(Level::TRACE) => log::LevelFilter::Trace,
        }
    }
}

impl TracingSubscriber for Subscriber {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        self.filter.enabled(*metadata.level(), metadata.target())
    }

    fn new_span(&self, _span: &span::Attributes<'_>) -> span::Id {
        span::Id::from_u64(self.next_span.fetch_add(1, Ordering::Relaxed) + 1)
    }

    fn record(&self, _span: &span::Id, _values: &span::Record<'_>) {}

    fn record_follows_from(&self, _span: &span::Id, _follows: &span::Id) {}

    fn event(&self, event: &Event<'_>) {
        let metadata = event.metadata();
        if !self.filter.enabled(*metadata.level(), metadata.target()) {
            return;
        }
        let mut visitor = FieldVisitor::default();
        event.record(&mut visitor);
        self.write(*metadata.level(), metadata.target(), &visitor.fields);
    }

    fn enter(&self, _span: &span::Id) {}

    fn exit(&self, _span: &span::Id) {}

    fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
        Some(self.filter.max_level())
    }
}

pub(crate) struct LogBridge {
    subscriber: Arc<Subscriber>,
}

impl LogBridge {
    pub(crate) fn new(subscriber: Arc<Subscriber>) -> Self {
        Self { subscriber }
    }
}

impl log::Log for LogBridge {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        self.subscriber
            .filter
            .enabled(log_level(metadata.level()), metadata.target())
    }

    fn log(&self, record: &log::Record<'_>) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let message = record.args().to_string();
        self.subscriber
            .write_log(log_level(record.level()), record.target(), &message);
    }

    fn flush(&self) {}
}

fn log_level(level: log::Level) -> Level {
    match level {
        log::Level::Error => Level::ERROR,
        log::Level::Warn => Level::WARN,
        log::Level::Info => Level::INFO,
        log::Level::Debug => Level::DEBUG,
        log::Level::Trace => Level::TRACE,
    }
}

#[derive(Default)]
struct FieldVisitor {
    fields: Fields,
}

impl FieldVisitor {
    fn push(&mut self, field: &Field, value: FieldValue) {
        if field.name() == "message" {
            self.fields.message = Some(value.text());
        } else {
            self.fields.values.push((field.name().to_owned(), value));
        }
    }
}

impl Visit for FieldVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.push(field, FieldValue::Text(format!("{value:?}")));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.push(field, FieldValue::Text(value.to_owned()));
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.push(field, FieldValue::I64(value));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.push(field, FieldValue::U64(value));
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        self.push(field, FieldValue::F64(value));
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.push(field, FieldValue::Bool(value));
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.push(field, FieldValue::Text(value.to_string()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use log::Log as _;
    use std::io;

    struct Buffer(Arc<Mutex<Vec<u8>>>);

    impl Write for Buffer {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn setup(filter: &str, format: LogFormat) -> (Arc<Subscriber>, Arc<Mutex<Vec<u8>>>) {
        let buffer = Arc::new(Mutex::new(Vec::new()));
        let subscriber = Arc::new(Subscriber::new(
            Filter::parse(filter).expect("filter"),
            format,
            false,
            Box::new(Buffer(Arc::clone(&buffer))),
        ));
        (subscriber, buffer)
    }

    fn output(buffer: &Arc<Mutex<Vec<u8>>>) -> String {
        String::from_utf8(
            buffer
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone(),
        )
        .expect("utf-8")
    }

    #[test]
    fn text_event_matches_the_expected_format() {
        let (subscriber, buffer) = setup("info", LogFormat::Text);
        tracing::subscriber::with_default(subscriber, || {
            let action = "BLOCK";
            tracing::info!(
                target: "kunato::test",
                answer = 42,
                action = ?action,
                "hello"
            );
        });
        let output = output(&buffer);
        assert!(
            output.contains(" INFO kunato::test: hello answer=42 action=\"BLOCK\""),
            "{output}"
        );
    }

    #[test]
    fn filter_suppresses_disabled_events() {
        let (subscriber, buffer) = setup("warn", LogFormat::Text);
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!("hidden");
            tracing::warn!("shown");
        });
        let output = output(&buffer);
        assert!(!output.contains("hidden"), "{output}");
        assert!(output.contains("shown"), "{output}");
    }

    #[test]
    fn target_filter_applies_to_events() {
        let (subscriber, buffer) = setup("kunato=debug", LogFormat::Text);
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(target: "hyper", "hidden");
            tracing::debug!(target: "kunato::proxy", "shown");
        });
        let output = output(&buffer);
        assert!(!output.contains("hidden"), "{output}");
        assert!(output.contains("shown"), "{output}");
    }

    #[test]
    fn json_event_matches_the_expected_schema() {
        let (subscriber, buffer) = setup("info", LogFormat::Json);
        tracing::subscriber::with_default(subscriber, || {
            tracing::error!(target: "kunato", "boom");
        });
        let output = output(&buffer);
        let value: serde_json::Value = serde_json::from_str(output.trim()).expect("valid json");
        assert_eq!(value["level"], "ERROR");
        assert_eq!(value["target"], "kunato");
        assert_eq!(value["fields"]["message"], "boom");
    }

    #[test]
    fn log_bridge_writes_dependency_records() {
        let (subscriber, buffer) = setup("info", LogFormat::Text);
        let bridge = LogBridge::new(Arc::clone(&subscriber));
        let record = log::Record::builder()
            .args(format_args!("tls alert"))
            .level(log::Level::Warn)
            .target("rustls")
            .build();
        bridge.log(&record);
        assert!(output(&buffer).contains(" WARN rustls: tls alert"));
    }

    #[test]
    fn spans_are_accepted() {
        let (subscriber, buffer) = setup("info", LogFormat::Text);
        tracing::subscriber::with_default(subscriber, || {
            tracing::info_span!("test").in_scope(|| tracing::info!("inside"));
        });
        assert!(output(&buffer).contains("inside"));
    }

    #[test]
    fn log_max_level_tracks_the_filter() {
        let (subscriber, _) = setup("kunato=debug", LogFormat::Text);
        assert_eq!(subscriber.max_log_level(), log::LevelFilter::Debug);
    }
}
