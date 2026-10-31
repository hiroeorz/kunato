use std::ffi::OsString;
use std::fmt;
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;

use super::{
    BannerArgs, Cli, Command, DEFAULT_CONFIG_PATH, DEFAULT_METRICS_LISTEN, DEFAULT_RULES_FILE,
    DEFAULT_RULES_URL, InitArgs, LogArgs, LogFormat, LogOutputFormat, MetricsArgs, UpgradeArgs,
};

const VERSION: &str = env!("CARGO_PKG_VERSION");

const GLOBAL_OPTIONS: &str = r#"Global options:
  -c, --config <PATH>        Path to the YAML configuration file
      --validate             Validate the configuration and exit
      --disable-protection   Disable DoS/DDoS protection for server mode
      --log-level <LEVEL>    Service log level filter (overrides RUST_LOG)
      --log-format <FORMAT>  Service log output format [default: text] [possible values: text, json]
  -h, --help                 Print help
"#;

#[derive(Debug)]
pub enum ParseError {
    Help(String),
    Version(String),
    Message(String),
}

impl ParseError {
    fn exit(self) -> ! {
        match self {
            Self::Help(text) | Self::Version(text) => {
                let mut stdout = std::io::stdout();
                let _ = stdout.write_all(text.as_bytes());
                let _ = stdout.flush();
                std::process::exit(0);
            }
            Self::Message(message) => {
                eprintln!("error: {message}");
                eprintln!();
                eprintln!("For more information, try '--help'.");
                std::process::exit(2);
            }
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Help(text) | Self::Version(text) | Self::Message(text) => {
                formatter.write_str(text)
            }
        }
    }
}

impl std::error::Error for ParseError {}

impl Cli {
    pub fn parse() -> Self {
        match Self::try_parse_from(std::env::args_os()) {
            Ok(cli) => cli,
            Err(error) => error.exit(),
        }
    }

    pub fn try_parse_from<I, T>(args: I) -> Result<Self, ParseError>
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString>,
    {
        let mut args = args.into_iter().map(Into::into);
        let _ = args.next();
        Parser::new(args.collect()).parse()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Init,
    Validate,
    UpdateRules,
    Upgrade,
    Log,
    Metrics,
    Banner,
}

fn kind_from_name(name: &str) -> Option<Kind> {
    match name {
        "init" => Some(Kind::Init),
        "validate" => Some(Kind::Validate),
        "update-rules" => Some(Kind::UpdateRules),
        "upgrade" => Some(Kind::Upgrade),
        "log" => Some(Kind::Log),
        "metrics" => Some(Kind::Metrics),
        "banner" => Some(Kind::Banner),
        _ => None,
    }
}

#[derive(Default)]
struct InitState {
    upstream: Option<String>,
    listen: Option<SocketAddr>,
    cert_file: Option<PathBuf>,
    key_file: Option<PathBuf>,
    acme_domains: Vec<String>,
    acme_contact: Option<String>,
    acme_staging: bool,
    allowed_hosts: Vec<String>,
    rules_file: Option<PathBuf>,
    rules_url: Option<String>,
    overrides_file: Option<PathBuf>,
    output: Option<PathBuf>,
    force: bool,
}

#[derive(Default)]
struct UpgradeState {
    version: Option<String>,
    dry_run: bool,
}

#[derive(Default)]
struct LogState {
    follow: bool,
    lines: Option<usize>,
    since: Option<String>,
    until: Option<String>,
    ips: Vec<String>,
    peer_ips: Vec<String>,
    attacks: Vec<String>,
    categories: Vec<String>,
    rules: Vec<String>,
    actions: Vec<String>,
    methods: Vec<String>,
    statuses: Vec<u16>,
    path: Option<String>,
    format: Option<LogOutputFormat>,
    no_color: bool,
    unit: Option<String>,
    journalctl: Option<String>,
    list_attacks: bool,
}

#[derive(Default)]
struct MetricsState {
    listen: Option<SocketAddr>,
}

#[derive(Default)]
struct BannerState {
    no_color: bool,
}

struct Parser {
    tokens: Vec<OsString>,
    index: usize,
    kind: Option<Kind>,
    config: Option<PathBuf>,
    validate: bool,
    disable_protection: bool,
    log_level: Option<String>,
    log_format: Option<LogFormat>,
    init: InitState,
    upgrade: UpgradeState,
    log: LogState,
    metrics: MetricsState,
    banner: BannerState,
}

impl Parser {
    fn new(tokens: Vec<OsString>) -> Self {
        Self {
            tokens,
            index: 0,
            kind: None,
            config: None,
            validate: false,
            disable_protection: false,
            log_level: None,
            log_format: None,
            init: InitState::default(),
            upgrade: UpgradeState::default(),
            log: LogState::default(),
            metrics: MetricsState::default(),
            banner: BannerState::default(),
        }
    }

    fn parse(mut self) -> Result<Cli, ParseError> {
        while self.index < self.tokens.len() {
            let token = self.tokens[self.index].clone();
            self.index += 1;
            let Some(text) = token.to_str() else {
                return Err(ParseError::Message(
                    "arguments must be valid UTF-8".to_owned(),
                ));
            };
            if text == "--" {
                return Err(self.unexpected("--"));
            }
            if let Some(long) = text.strip_prefix("--") {
                self.parse_long(long)?;
            } else if text.len() > 1 && text.starts_with('-') {
                self.parse_short(&text[1..])?;
            } else {
                self.parse_positional(text)?;
            }
        }
        self.finish()
    }

    fn parse_long(&mut self, spec: &str) -> Result<(), ParseError> {
        let (name, inline) = match spec.split_once('=') {
            Some((name, value)) => (name, Some(value)),
            None => (spec, None),
        };
        match name {
            "config" => {
                let value = self.value_path(inline, "--config <PATH>")?;
                set_once(&mut self.config, value, "--config <PATH>")?;
            }
            "validate" => {
                self.no_value(inline, "--validate")?;
                self.validate = true;
            }
            "disable-protection" => {
                self.no_value(inline, "--disable-protection")?;
                self.disable_protection = true;
            }
            "log-level" => {
                let value = self.value_string(inline, "--log-level <LEVEL>")?;
                set_once(&mut self.log_level, value, "--log-level <LEVEL>")?;
            }
            "log-format" => {
                let value = self.value_string(inline, "--log-format <FORMAT>")?;
                let format = parse_log_format(&value)?;
                set_once(&mut self.log_format, format, "--log-format <FORMAT>")?;
            }
            "help" => {
                self.no_value(inline, "--help")?;
                return Err(ParseError::Help(self.help()));
            }
            "version" if self.kind.is_none() => {
                self.no_value(inline, "--version")?;
                return Err(ParseError::Version(version_text()));
            }
            "version" if self.kind == Some(Kind::Upgrade) => {
                let value = self.value_string(inline, "--version <TAG>")?;
                set_once(&mut self.upgrade.version, value, "--version <TAG>")?;
            }
            _ => self.parse_subcommand_long(name, inline)?,
        }
        Ok(())
    }

    fn parse_subcommand_long(
        &mut self,
        name: &str,
        inline: Option<&str>,
    ) -> Result<(), ParseError> {
        match self.kind {
            Some(Kind::Init) => self.parse_init_long(name, inline),
            Some(Kind::Log) => self.parse_log_long(name, inline),
            Some(Kind::Upgrade) => self.parse_upgrade_long(name, inline),
            Some(Kind::Metrics) => self.parse_metrics_long(name, inline),
            Some(Kind::Banner) => self.parse_banner_long(name, inline),
            Some(Kind::Validate | Kind::UpdateRules) | None => {
                Err(self.unexpected(format!("--{name}")))
            }
        }
    }

    fn parse_init_long(&mut self, name: &str, inline: Option<&str>) -> Result<(), ParseError> {
        match name {
            "upstream" => {
                let value = self.value_string(inline, "--upstream <URL>")?;
                set_once(&mut self.init.upstream, value, "--upstream <URL>")?;
            }
            "listen" => {
                let value = self.value_string(inline, "--listen <ADDR>")?;
                let address = value.parse::<SocketAddr>().map_err(|_| {
                    invalid_value(&value, "--listen <ADDR>", "an IP address and port")
                })?;
                set_once(&mut self.init.listen, address, "--listen <ADDR>")?;
            }
            "cert-file" => {
                let value = self.value_path(inline, "--cert-file <PATH>")?;
                set_once(&mut self.init.cert_file, value, "--cert-file <PATH>")?;
            }
            "key-file" => {
                let value = self.value_path(inline, "--key-file <PATH>")?;
                set_once(&mut self.init.key_file, value, "--key-file <PATH>")?;
            }
            "acme-domain" => {
                let value = self.value_string(inline, "--acme-domain <DOMAIN>")?;
                self.init.acme_domains.push(value);
            }
            "acme-contact" => {
                let value = self.value_string(inline, "--acme-contact <EMAIL>")?;
                set_once(&mut self.init.acme_contact, value, "--acme-contact <EMAIL>")?;
            }
            "acme-staging" => {
                self.no_value(inline, "--acme-staging")?;
                self.init.acme_staging = true;
            }
            "allowed-host" => {
                let value = self.value_string(inline, "--allowed-host <HOST>")?;
                self.init.allowed_hosts.push(value);
            }
            "rules-file" => {
                let value = self.value_path(inline, "--rules-file <PATH>")?;
                set_once(&mut self.init.rules_file, value, "--rules-file <PATH>")?;
            }
            "rules-url" => {
                let value = self.value_string(inline, "--rules-url <URL>")?;
                set_once(&mut self.init.rules_url, value, "--rules-url <URL>")?;
            }
            "overrides-file" => {
                let value = self.value_path(inline, "--overrides-file <PATH>")?;
                set_once(
                    &mut self.init.overrides_file,
                    value,
                    "--overrides-file <PATH>",
                )?;
            }
            "output" => {
                let value = self.value_path(inline, "--output <PATH>")?;
                set_once(&mut self.init.output, value, "--output <PATH>")?;
            }
            "force" => {
                self.no_value(inline, "--force")?;
                self.init.force = true;
            }
            _ => return Err(self.unexpected(format!("--{name}"))),
        }
        Ok(())
    }

    fn parse_upgrade_long(&mut self, name: &str, inline: Option<&str>) -> Result<(), ParseError> {
        match name {
            "version" => {
                let value = self.value_string(inline, "--version <TAG>")?;
                set_once(&mut self.upgrade.version, value, "--version <TAG>")?;
            }
            "dry-run" => {
                self.no_value(inline, "--dry-run")?;
                self.upgrade.dry_run = true;
            }
            _ => return Err(self.unexpected(format!("--{name}"))),
        }
        Ok(())
    }

    fn parse_banner_long(&mut self, name: &str, inline: Option<&str>) -> Result<(), ParseError> {
        match name {
            "no-color" => {
                self.no_value(inline, "--no-color")?;
                self.banner.no_color = true;
            }
            _ => return Err(self.unexpected(format!("--{name}"))),
        }
        Ok(())
    }

    fn parse_metrics_long(&mut self, name: &str, inline: Option<&str>) -> Result<(), ParseError> {
        match name {
            "listen" => {
                let value = self.value_string(inline, "--listen <ADDR>")?;
                let address = parse_loopback_address(&value)?;
                set_once(&mut self.metrics.listen, address, "--listen <ADDR>")?;
            }
            _ => return Err(self.unexpected(format!("--{name}"))),
        }
        Ok(())
    }

    fn parse_log_long(&mut self, name: &str, inline: Option<&str>) -> Result<(), ParseError> {
        match name {
            "follow" => {
                self.no_value(inline, "--follow")?;
                self.log.follow = true;
            }
            "lines" => {
                let value = self.value_string(inline, "--lines <N>")?;
                let lines = parse_usize(&value, "--lines <N>")?;
                set_once(&mut self.log.lines, lines, "--lines <N>")?;
            }
            "since" => {
                let value = self.value_string(inline, "--since <TIME>")?;
                set_once(&mut self.log.since, value, "--since <TIME>")?;
            }
            "until" => {
                let value = self.value_string(inline, "--until <TIME>")?;
                set_once(&mut self.log.until, value, "--until <TIME>")?;
            }
            "ip" => {
                let value = self.value_string(inline, "--ip <IP|CIDR>")?;
                self.log.ips.extend(split_list(&value));
            }
            "peer-ip" => {
                let value = self.value_string(inline, "--peer-ip <IP|CIDR>")?;
                self.log.peer_ips.extend(split_list(&value));
            }
            "attack" => {
                let value = self.value_string(inline, "--attack <CLASS>")?;
                self.log.attacks.extend(split_list(&value));
            }
            "category" => {
                let value = self.value_string(inline, "--category <NAME>")?;
                self.log.categories.extend(split_list(&value));
            }
            "rule" => {
                let value = self.value_string(inline, "--rule <NAME>")?;
                self.log.rules.extend(split_list(&value));
            }
            "action" => {
                let value = self.value_string(inline, "--action <ACTION>")?;
                self.log.actions.extend(parse_actions(&value)?);
            }
            "method" => {
                let value = self.value_string(inline, "--method <METHOD>")?;
                self.log.methods.extend(split_list(&value));
            }
            "status" => {
                let value = self.value_string(inline, "--status <CODE>")?;
                self.log.statuses.extend(parse_statuses(&value)?);
            }
            "path" => {
                let value = self.value_string(inline, "--path <REGEX>")?;
                set_once(&mut self.log.path, value, "--path <REGEX>")?;
            }
            "format" => {
                let value = self.value_string(inline, "--format <FORMAT>")?;
                let format = parse_log_output_format(&value)?;
                set_once(&mut self.log.format, format, "--format <FORMAT>")?;
            }
            "no-color" => {
                self.no_value(inline, "--no-color")?;
                self.log.no_color = true;
            }
            "unit" => {
                let value = self.value_string(inline, "--unit <UNIT>")?;
                set_once(&mut self.log.unit, value, "--unit <UNIT>")?;
            }
            "journalctl" => {
                let value = self.value_string(inline, "--journalctl <PATH>")?;
                set_once(&mut self.log.journalctl, value, "--journalctl <PATH>")?;
            }
            "list-attacks" => {
                self.no_value(inline, "--list-attacks")?;
                self.log.list_attacks = true;
            }
            _ => return Err(self.unexpected(format!("--{name}"))),
        }
        Ok(())
    }

    fn parse_short(&mut self, cluster: &str) -> Result<(), ParseError> {
        let bytes = cluster.as_bytes();
        let mut position = 0;
        while position < bytes.len() {
            let option = bytes[position] as char;
            position += 1;
            match option {
                'c' => {
                    let inline = short_inline(cluster, position);
                    let value = self.value_path(inline, "-c <PATH>")?;
                    set_once(&mut self.config, value, "-c <PATH>")?;
                    return Ok(());
                }
                'f' if self.kind == Some(Kind::Log) => self.log.follow = true,
                'n' if self.kind == Some(Kind::Log) => {
                    let inline = short_inline(cluster, position);
                    let value = self.value_string(inline, "-n <N>")?;
                    let lines = parse_usize(&value, "-n <N>")?;
                    set_once(&mut self.log.lines, lines, "-n <N>")?;
                    return Ok(());
                }
                'u' if self.kind == Some(Kind::Log) => {
                    let inline = short_inline(cluster, position);
                    let value = self.value_string(inline, "-u <UNIT>")?;
                    set_once(&mut self.log.unit, value, "-u <UNIT>")?;
                    return Ok(());
                }
                'h' => return Err(ParseError::Help(self.help())),
                'V' if self.kind.is_none() => return Err(ParseError::Version(version_text())),
                _ => return Err(self.unexpected(format!("-{option}"))),
            }
        }
        Ok(())
    }

    fn parse_positional(&mut self, value: &str) -> Result<(), ParseError> {
        if self.kind.is_some() {
            return Err(self.unexpected(value));
        }
        if value == "help" {
            let next = self
                .tokens
                .get(self.index)
                .and_then(|token| token.to_str())
                .map(str::to_owned);
            if next.is_some() {
                self.index += 1;
            }
            let kind = match next.as_deref() {
                None => None,
                Some(name) => match kind_from_name(name) {
                    Some(kind) => Some(kind),
                    None => {
                        return Err(ParseError::Message(format!(
                            "unrecognized subcommand '{name}'"
                        )));
                    }
                },
            };
            return Err(ParseError::Help(help_for(kind)));
        }
        match kind_from_name(value) {
            Some(kind) => {
                self.kind = Some(kind);
                Ok(())
            }
            None => Err(ParseError::Message(format!(
                "unrecognized subcommand '{value}'"
            ))),
        }
    }

    fn finish(self) -> Result<Cli, ParseError> {
        let command = match self.kind {
            None => None,
            Some(Kind::Validate) => Some(Command::Validate),
            Some(Kind::UpdateRules) => Some(Command::UpdateRules),
            Some(Kind::Upgrade) => Some(Command::Upgrade(UpgradeArgs {
                version: self.upgrade.version,
                dry_run: self.upgrade.dry_run,
            })),
            Some(Kind::Metrics) => Some(Command::Metrics(MetricsArgs {
                listen: self.metrics.listen.unwrap_or(DEFAULT_METRICS_LISTEN),
            })),
            Some(Kind::Banner) => Some(Command::Banner(BannerArgs {
                no_color: self.banner.no_color,
            })),
            Some(Kind::Log) => Some(Command::Log(Box::new(LogArgs {
                follow: self.log.follow,
                lines: self.log.lines,
                since: self.log.since,
                until: self.log.until,
                ips: self.log.ips,
                peer_ips: self.log.peer_ips,
                attacks: self.log.attacks,
                categories: self.log.categories,
                rules: self.log.rules,
                actions: self.log.actions,
                methods: self.log.methods,
                statuses: self.log.statuses,
                path: self.log.path,
                format: self.log.format.unwrap_or(LogOutputFormat::Raw),
                no_color: self.log.no_color,
                unit: self.log.unit.unwrap_or_else(|| "kunato".to_owned()),
                journalctl: self
                    .log
                    .journalctl
                    .unwrap_or_else(|| "journalctl".to_owned()),
                list_attacks: self.log.list_attacks,
            }))),
            Some(Kind::Init) => {
                let init = self.init;
                let Some(upstream) = init.upstream else {
                    return Err(ParseError::Message(
                        "the following required arguments were not provided:\n  --upstream <URL>"
                            .to_owned(),
                    ));
                };
                if !init.acme_domains.is_empty()
                    && (init.cert_file.is_some() || init.key_file.is_some())
                {
                    return Err(ParseError::Message(
                        "the argument '--acme-domain <DOMAIN>' cannot be used with '--cert-file <PATH>' or '--key-file <PATH>'"
                            .to_owned(),
                    ));
                }
                if init.cert_file.is_some() && init.key_file.is_none() {
                    return Err(ParseError::Message(
                        "the argument '--cert-file <PATH>' requires '--key-file <PATH>'".to_owned(),
                    ));
                }
                if init.key_file.is_some() && init.cert_file.is_none() {
                    return Err(ParseError::Message(
                        "the argument '--key-file <PATH>' requires '--cert-file <PATH>'".to_owned(),
                    ));
                }
                if init.acme_contact.is_some() && init.acme_domains.is_empty() {
                    return Err(ParseError::Message(
                        "the argument '--acme-contact <EMAIL>' requires '--acme-domain <DOMAIN>'"
                            .to_owned(),
                    ));
                }
                if init.acme_staging && init.acme_domains.is_empty() {
                    return Err(ParseError::Message(
                        "the argument '--acme-staging' requires '--acme-domain <DOMAIN>'"
                            .to_owned(),
                    ));
                }
                Some(Command::Init(Box::new(InitArgs {
                    upstream,
                    listen: init
                        .listen
                        .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 443))),
                    cert_file: init.cert_file,
                    key_file: init.key_file,
                    acme_domains: init.acme_domains,
                    acme_contact: init.acme_contact,
                    acme_staging: init.acme_staging,
                    allowed_hosts: init.allowed_hosts,
                    rules_file: init
                        .rules_file
                        .unwrap_or_else(|| PathBuf::from(DEFAULT_RULES_FILE)),
                    rules_url: init
                        .rules_url
                        .unwrap_or_else(|| DEFAULT_RULES_URL.to_owned()),
                    overrides_file: init.overrides_file,
                    output: init.output.unwrap_or_else(|| PathBuf::from("kunato.yaml")),
                    force: init.force,
                })))
            }
        };

        Ok(Cli {
            config: self
                .config
                .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH)),
            validate: self.validate,
            disable_protection: self.disable_protection,
            log_level: self.log_level,
            log_format: self.log_format.unwrap_or(LogFormat::Text),
            command,
        })
    }

    fn value(&mut self, inline: Option<&str>, option: &str) -> Result<OsString, ParseError> {
        if let Some(inline) = inline {
            return Ok(OsString::from(inline));
        }
        let Some(value) = self.tokens.get(self.index).cloned() else {
            return Err(ParseError::Message(format!(
                "a value is required for '{option}' but none was supplied"
            )));
        };
        self.index += 1;
        Ok(value)
    }

    fn value_string(&mut self, inline: Option<&str>, option: &str) -> Result<String, ParseError> {
        self.value(inline, option)?
            .into_string()
            .map_err(|_| ParseError::Message(format!("invalid UTF-8 in the value for '{option}'")))
    }

    fn value_path(&mut self, inline: Option<&str>, option: &str) -> Result<PathBuf, ParseError> {
        Ok(PathBuf::from(self.value(inline, option)?))
    }

    fn no_value(&self, inline: Option<&str>, option: &str) -> Result<(), ParseError> {
        if inline.is_some() {
            return Err(ParseError::Message(format!(
                "unexpected value for '{option}'"
            )));
        }
        Ok(())
    }

    fn unexpected(&self, argument: impl Into<String>) -> ParseError {
        ParseError::Message(format!("unexpected argument '{}' found", argument.into()))
    }

    fn help(&self) -> String {
        help_for(self.kind)
    }
}

fn short_inline(cluster: &str, position: usize) -> Option<&str> {
    (position < cluster.len()).then(|| {
        cluster[position..]
            .strip_prefix('=')
            .unwrap_or(&cluster[position..])
    })
}

fn set_once<T>(slot: &mut Option<T>, value: T, option: &str) -> Result<(), ParseError> {
    if slot.is_some() {
        return Err(ParseError::Message(format!(
            "the argument '{option}' cannot be used multiple times"
        )));
    }
    *slot = Some(value);
    Ok(())
}

fn split_list(value: &str) -> impl Iterator<Item = String> + '_ {
    value.split(',').map(str::to_owned)
}

fn parse_actions(value: &str) -> Result<Vec<String>, ParseError> {
    let mut actions = Vec::new();
    for action in value.split(',') {
        if !action.eq_ignore_ascii_case("BLOCK") && !action.eq_ignore_ascii_case("LOG") {
            return Err(invalid_value(action, "--action <ACTION>", "BLOCK or LOG"));
        }
        actions.push(action.to_owned());
    }
    Ok(actions)
}

fn parse_statuses(value: &str) -> Result<Vec<u16>, ParseError> {
    let mut statuses = Vec::new();
    for status in value.split(',') {
        let parsed = status
            .parse::<u16>()
            .map_err(|_| invalid_value(status, "--status <CODE>", "an integer in 100..=599"))?;
        if !(100..=599).contains(&parsed) {
            return Err(invalid_value(
                status,
                "--status <CODE>",
                "an integer in 100..=599",
            ));
        }
        statuses.push(parsed);
    }
    Ok(statuses)
}

fn parse_usize(value: &str, option: &str) -> Result<usize, ParseError> {
    value
        .parse()
        .map_err(|_| invalid_value(value, option, "a non-negative integer"))
}

fn parse_loopback_address(value: &str) -> Result<SocketAddr, ParseError> {
    let address = value
        .parse::<SocketAddr>()
        .map_err(|_| invalid_value(value, "--listen <ADDR>", "an IP address and port"))?;
    if !address.ip().is_loopback() {
        return Err(invalid_value(
            value,
            "--listen <ADDR>",
            "a loopback address",
        ));
    }
    Ok(address)
}

fn parse_log_format(value: &str) -> Result<LogFormat, ParseError> {
    match value {
        "text" => Ok(LogFormat::Text),
        "json" => Ok(LogFormat::Json),
        _ => Err(invalid_value(
            value,
            "--log-format <FORMAT>",
            "text or json",
        )),
    }
}

fn parse_log_output_format(value: &str) -> Result<LogOutputFormat, ParseError> {
    match value {
        "raw" => Ok(LogOutputFormat::Raw),
        "table" => Ok(LogOutputFormat::Table),
        "json" => Ok(LogOutputFormat::Json),
        _ => Err(invalid_value(
            value,
            "--format <FORMAT>",
            "raw, table, or json",
        )),
    }
}

fn invalid_value(value: &str, option: &str, expected: &str) -> ParseError {
    ParseError::Message(format!(
        "invalid value '{value}' for '{option}': expected {expected}"
    ))
}

fn version_text() -> String {
    format!("kunato {VERSION}\n")
}

fn help_for(kind: Option<Kind>) -> String {
    match kind {
        None => top_help(),
        Some(Kind::Init) => init_help(),
        Some(Kind::Validate) => validate_help(),
        Some(Kind::UpdateRules) => update_rules_help(),
        Some(Kind::Upgrade) => upgrade_help(),
        Some(Kind::Log) => log_help(),
        Some(Kind::Metrics) => metrics_help(),
        Some(Kind::Banner) => banner_help(),
    }
}

fn top_help() -> String {
    format!(
        r#"Personal-use WAF reverse proxy

Usage: kunato [OPTIONS] [COMMAND]

Commands:
  init          Write a starter configuration file and exit
  validate      Validate the configuration (including rules_file and overrides_file) and exit
  update-rules  Download the rules file once and exit
  upgrade       Upgrade the installed binary and systemd unit from a release
  log           Read the systemd journal for the Kunato service
  metrics       Print the Prometheus metrics served by the admin listener
  banner        Print the Kunato banner
  help          Print this message or the help of the given subcommand(s)

Options:
  -c, --config <PATH>        Path to the YAML configuration file [default: {}]
      --validate             Validate the configuration and exit (server/config modes)
      --disable-protection   Disable DoS/DDoS protection for server mode
      --log-level <LEVEL>    Service log level filter (overrides RUST_LOG)
      --log-format <FORMAT>  Service log output format [default: text] [possible values: text, json]
  -h, --help                 Print help
  -V, --version              Print version
"#,
        DEFAULT_CONFIG_PATH
    )
}

fn init_help() -> String {
    format!(
        r#"Write a starter configuration file and exit.

Usage: kunato init --upstream <URL> [OPTIONS]

Options:
      --upstream <URL>          Upstream URL that Kunato forwards requests to
      --listen <ADDR>           Address to listen on [default: 0.0.0.0:443]
      --cert-file <PATH>        TLS certificate chain in PEM format (requires --key-file)
      --key-file <PATH>         TLS private key in PEM format (requires --cert-file)
      --acme-domain <DOMAIN>    Obtain certificates automatically through ACME; repeat per domain
      --acme-contact <EMAIL>    Contact email registered with the ACME account (requires --acme-domain)
      --acme-staging            Use the Let's Encrypt staging directory (requires --acme-domain)
      --allowed-host <HOST>     Extra Host name or IP literal; repeat for more names
      --rules-file <PATH>       Rules file refreshed by the daily updater [default: {}]
      --rules-url <URL>         URL to download the rules file from [default: {}]
      --overrides-file <PATH>   Optional local overrides file
      --output <PATH>           Output configuration path [default: kunato.yaml]
      --force                   Overwrite an existing configuration file

{}"#,
        DEFAULT_RULES_FILE, DEFAULT_RULES_URL, GLOBAL_OPTIONS
    )
}

fn upgrade_help() -> String {
    format!(
        r#"Upgrade the installed binary and systemd unit from a release,
keeping the configuration, by rerunning the official installer.

Usage: kunato upgrade [OPTIONS]

Options:
      --version <TAG>  Release tag to install (default: the latest release)
      --dry-run        Print what would be downloaded and run without changing anything

{}"#,
        GLOBAL_OPTIONS
    )
}

fn log_help() -> String {
    format!(
        r#"Read the systemd journal for the Kunato service.

Usage: kunato log [OPTIONS]

Options:
  -f, --follow               Follow new journal entries
  -n, --lines <N>            Number of journal lines to read
      --since <TIME>         Start time passed to journalctl
      --until <TIME>         End time passed to journalctl
      --ip <IP|CIDR>         Filter by resolved client IP address or CIDR; repeat or comma-separate
      --peer-ip <IP|CIDR>    Filter by transport peer address or CIDR
      --attack <CLASS>       Filter by category-based attack type
      --category <NAME>      Filter by exact rule category name
      --rule <NAME>          Filter by exact rule name
      --action <ACTION>      Filter by logged action [possible values: BLOCK, LOG]
      --method <METHOD>      Filter by HTTP method
      --status <CODE>        Filter by recorded status code (100-599)
      --path <REGEX>         Filter by request path using a Rust regular expression
      --format <FORMAT>      Viewer output format [default: raw] [possible values: raw, table, json]
      --no-color             Disable ANSI colors in table output
  -u, --unit <UNIT>          systemd unit name to read [default: kunato]
      --journalctl <PATH>    journalctl executable to run [default: journalctl]
      --list-attacks         List supported attack types and exit

{}"#,
        GLOBAL_OPTIONS
    )
}

fn metrics_help() -> String {
    format!(
        r#"Print the metrics served by the admin listener as a bordered table.

Each sample from `GET /metrics` becomes one row of a metric name and its value,
with values right-aligned. The `# HELP` and `# TYPE` comment lines are omitted,
and timestamp gauges also show the local date and time.

Usage: kunato metrics [OPTIONS]

Options:
      --listen <ADDR>  Admin listener address serving /metrics [default: {}]

{}"#,
        DEFAULT_METRICS_LISTEN, GLOBAL_OPTIONS
    )
}

fn banner_help() -> String {
    format!(
        r#"Print the Kunato banner: the mascot drawn with terminal colors and the
Kunato wordmark.

Usage: kunato banner [OPTIONS]

Options:
      --no-color  Disable ANSI colors (NO_COLOR and a non-terminal stdout do the same)

{}"#,
        GLOBAL_OPTIONS
    )
}

fn validate_help() -> String {
    format!(
        r#"Validate the configuration (including rules_file and overrides_file) and exit.

Usage: kunato validate

{}"#,
        GLOBAL_OPTIONS
    )
}

fn update_rules_help() -> String {
    format!(
        r#"Download the rules file once and exit.

Usage: kunato update-rules

{}"#,
        GLOBAL_OPTIONS
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Cli, ParseError> {
        Cli::try_parse_from(args.iter().copied())
    }

    #[test]
    fn defaults_are_applied() {
        let cli = parse(&["kunato"]).expect("parse");
        assert!(cli.command.is_none());
        assert_eq!(cli.config, PathBuf::from(DEFAULT_CONFIG_PATH));
        assert_eq!(cli.log_format, LogFormat::Text);
        assert!(!cli.validate);
        assert!(!cli.disable_protection);
    }

    #[test]
    fn accepts_global_options_before_the_subcommand() {
        let cli = parse(&["kunato", "--config", "before.yaml", "log"]).expect("parse");
        assert_eq!(cli.config, PathBuf::from("before.yaml"));
    }

    #[test]
    fn short_flags_cover_help_version_and_config() {
        assert!(matches!(parse(&["kunato", "-h"]), Err(ParseError::Help(_))));
        assert!(matches!(
            parse(&["kunato", "-V"]),
            Err(ParseError::Version(_))
        ));
        let cli = parse(&["kunato", "-c", "short.yaml", "log"]).expect("parse");
        assert_eq!(cli.config, PathBuf::from("short.yaml"));
    }

    #[test]
    fn accepts_global_options_after_the_subcommand() {
        let cli = parse(&[
            "kunato",
            "log",
            "--config",
            "local.yaml",
            "--log-format",
            "json",
        ])
        .expect("parse");
        assert_eq!(cli.config, PathBuf::from("local.yaml"));
        assert_eq!(cli.log_format, LogFormat::Json);
    }

    #[test]
    fn parses_short_flags_and_values() {
        let cli = parse(&[
            "kunato",
            "log",
            "-fn10",
            "-u",
            "kunato-test",
            "--status",
            "429,403",
            "--action",
            "block,LOG",
        ])
        .expect("parse");
        let Some(Command::Log(args)) = cli.command else {
            panic!("expected the log command");
        };
        assert!(args.follow);
        assert_eq!(args.lines, Some(10));
        assert_eq!(args.unit, "kunato-test");
        assert_eq!(args.statuses, vec![429, 403]);
        assert_eq!(args.actions, vec!["block".to_owned(), "LOG".to_owned()]);
    }

    #[test]
    fn parses_init_defaults_and_requirements() {
        let cli = parse(&["kunato", "init", "--upstream", "http://127.0.0.1:3000"]).expect("parse");
        let Some(Command::Init(args)) = cli.command else {
            panic!("expected the init command");
        };
        assert_eq!(args.listen, SocketAddr::from(([0, 0, 0, 0], 443)));
        assert_eq!(args.rules_file, PathBuf::from(DEFAULT_RULES_FILE));
        assert_eq!(args.rules_url, DEFAULT_RULES_URL);
        assert_eq!(args.output, PathBuf::from("kunato.yaml"));
    }

    #[test]
    fn init_requires_upstream() {
        let error = parse(&["kunato", "init"]).expect_err("upstream is required");
        assert!(error.to_string().contains("--upstream <URL>"));
    }

    #[test]
    fn init_cert_and_key_require_each_other() {
        let error = parse(&[
            "kunato",
            "init",
            "--upstream",
            "http://127.0.0.1:3000",
            "--cert-file",
            "/tmp/cert.pem",
        ])
        .expect_err("key file is required");
        assert!(error.to_string().contains("requires '--key-file <PATH>'"));

        let error = parse(&[
            "kunato",
            "init",
            "--upstream",
            "http://127.0.0.1:3000",
            "--key-file",
            "/tmp/key.pem",
        ])
        .expect_err("cert file is required");
        assert!(error.to_string().contains("requires '--cert-file <PATH>'"));
    }

    #[test]
    fn init_acme_conflicts_with_manual_tls() {
        let error = parse(&[
            "kunato",
            "init",
            "--upstream",
            "http://127.0.0.1:3000",
            "--acme-domain",
            "example.com",
            "--cert-file",
            "/tmp/cert.pem",
            "--key-file",
            "/tmp/key.pem",
        ])
        .expect_err("acme and manual TLS conflict");
        assert!(error.to_string().contains("cannot be used with"));
    }

    #[test]
    fn init_acme_contact_requires_a_domain() {
        let error = parse(&[
            "kunato",
            "init",
            "--upstream",
            "http://127.0.0.1:3000",
            "--acme-contact",
            "admin@example.com",
        ])
        .expect_err("acme domains are required");
        assert!(
            error
                .to_string()
                .contains("requires '--acme-domain <DOMAIN>'")
        );
    }

    #[test]
    fn upgrade_version_is_a_value() {
        let cli = parse(&["kunato", "upgrade", "--version", "v0.9.0", "--dry-run"]).expect("parse");
        let Some(Command::Upgrade(args)) = cli.command else {
            panic!("expected the upgrade command");
        };
        assert_eq!(args.version.as_deref(), Some("v0.9.0"));
        assert!(args.dry_run);
    }

    #[test]
    fn parses_banner_and_no_color() {
        let cli = parse(&["kunato", "banner"]).expect("parse");
        let Some(Command::Banner(args)) = cli.command else {
            panic!("expected the banner command");
        };
        assert!(!args.no_color);

        let cli = parse(&["kunato", "banner", "--no-color"]).expect("parse");
        let Some(Command::Banner(args)) = cli.command else {
            panic!("expected the banner command");
        };
        assert!(args.no_color);

        assert!(parse(&["kunato", "banner", "--unknown"]).is_err());
    }

    #[test]
    fn banner_help_is_available() {
        let error = parse(&["kunato", "help", "banner"]).expect_err("help exits");
        match error {
            ParseError::Help(text) => {
                assert!(text.contains("Usage: kunato banner"));
                assert!(text.contains("--no-color"));
            }
            other => panic!("expected help, got {other:?}"),
        }
    }

    #[test]
    fn parses_metrics_defaults_and_listen() {
        let cli = parse(&["kunato", "metrics"]).expect("parse");
        let Some(Command::Metrics(args)) = cli.command else {
            panic!("expected the metrics command");
        };
        assert_eq!(args.listen, DEFAULT_METRICS_LISTEN);

        let cli = parse(&["kunato", "metrics", "--listen", "127.0.0.1:9100"]).expect("parse");
        let Some(Command::Metrics(args)) = cli.command else {
            panic!("expected the metrics command");
        };
        assert_eq!(args.listen, SocketAddr::from(([127, 0, 0, 1], 9100)));

        let cli = parse(&["kunato", "metrics", "--listen", "[::1]:9100"]).expect("parse");
        let Some(Command::Metrics(args)) = cli.command else {
            panic!("expected the metrics command");
        };
        assert_eq!(
            args.listen,
            SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 9100))
        );
    }

    #[test]
    fn metrics_requires_a_loopback_listener() {
        let error =
            parse(&["kunato", "metrics", "--listen", "0.0.0.0:9090"]).expect_err("public address");
        assert!(error.to_string().contains("loopback"));
        assert!(parse(&["kunato", "metrics", "--listen", "nope"]).is_err());
        assert!(parse(&["kunato", "metrics", "--unknown"]).is_err());
    }

    #[test]
    fn help_and_version_are_distinguished() {
        let error = parse(&["kunato", "--help"]).expect_err("help exits");
        assert!(matches!(error, ParseError::Help(_)));

        let error = parse(&["kunato", "log", "--help"]).expect_err("help exits");
        match error {
            ParseError::Help(text) => assert!(text.contains("Usage: kunato log")),
            other => panic!("expected help, got {other:?}"),
        }

        let error = parse(&["kunato", "--version"]).expect_err("version exits");
        match error {
            ParseError::Version(text) => assert!(text.contains(VERSION)),
            other => panic!("expected version, got {other:?}"),
        }
    }

    #[test]
    fn help_subcommand_selects_the_subcommand() {
        let error = parse(&["kunato", "help", "upgrade"]).expect_err("help exits");
        match error {
            ParseError::Help(text) => assert!(text.contains("Usage: kunato upgrade")),
            other => panic!("expected help, got {other:?}"),
        }
    }

    #[test]
    fn metrics_help_mentions_the_default_listener() {
        let error = parse(&["kunato", "help", "metrics"]).expect_err("help exits");
        match error {
            ParseError::Help(text) => {
                assert!(text.contains("Usage: kunato metrics"));
                assert!(text.contains("127.0.0.1:9090"));
            }
            other => panic!("expected help, got {other:?}"),
        }
    }

    #[test]
    fn rejects_unknown_arguments_and_subcommands() {
        assert!(parse(&["kunato", "--unknown"]).is_err());
        assert!(parse(&["kunato", "unknown"]).is_err());
        assert!(parse(&["kunato", "init", "--unknown"]).is_err());
        assert!(parse(&["kunato", "log", "--config"]).is_err());
    }

    #[test]
    fn rejects_duplicate_scalar_options() {
        let error = parse(&["kunato", "--config", "a.yaml", "--config", "b.yaml"])
            .expect_err("duplicate config");
        assert!(error.to_string().contains("cannot be used multiple times"));
    }

    #[test]
    fn rejects_invalid_values() {
        assert!(parse(&["kunato", "log", "--status", "99"]).is_err());
        assert!(parse(&["kunato", "log", "--status", "600"]).is_err());
        assert!(parse(&["kunato", "log", "--action", "ALLOW"]).is_err());
        assert!(parse(&["kunato", "log", "--format", "yaml"]).is_err());
        assert!(parse(&["kunato", "--log-format", "yaml"]).is_err());
        assert!(parse(&["kunato", "init", "--upstream", "x", "--listen", "nope"]).is_err());
    }

    #[test]
    fn accepts_equals_and_attached_short_values() {
        let cli = parse(&[
            "kunato",
            "--config=local.yaml",
            "log",
            "-n=25",
            "--format=json",
        ])
        .expect("parse");
        assert_eq!(cli.config, PathBuf::from("local.yaml"));
        let Some(Command::Log(args)) = cli.command else {
            panic!("expected the log command");
        };
        assert_eq!(args.lines, Some(25));
        assert_eq!(args.format, LogOutputFormat::Json);
    }
}
