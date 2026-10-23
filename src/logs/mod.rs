mod attack;
mod filter;
mod output;
mod parse;

use std::io::{self, IsTerminal, Write};
use std::process::Stdio;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;

use crate::cli::{LogArgs, LogOutputFormat};
use crate::error::Error;

use filter::Filters;

/// Read the systemd journal for the Kunato unit. `journalctl` does the reading;
/// this command only parses, filters, and renders its lines.
pub async fn run(args: LogArgs) -> Result<(), Error> {
    if args.list_attacks {
        print!("{}", attack::list());
        return Ok(());
    }

    let filters = Filters::from_args(&args)?;
    let journal_args = journal_args(&args)?;
    let mut command = Command::new(&args.journalctl);
    command
        .args(&journal_args)
        .kill_on_drop(true)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    let mut child = command.spawn().map_err(|err| {
        if err.kind() == io::ErrorKind::NotFound {
            Error::Message(format!(
                "`{}` was not found; install systemd or pass --journalctl PATH",
                args.journalctl
            ))
        } else {
            Error::Message(format!("failed to run `{}`: {err}", args.journalctl))
        }
    })?;
    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill().await;
        return Err(Error::Message(
            "journalctl did not provide a readable stdout".to_owned(),
        ));
    };

    let color = args.format == LogOutputFormat::Table
        && !args.no_color
        && io::stdout().is_terminal()
        && std::env::var_os("NO_COLOR").is_none();
    let mut reader = BufReader::new(stdout);
    let mut line = Vec::new();
    let mut stdout = io::stdout();
    let mut saw_entry = false;
    let mut wrote_entry = false;
    let mut header_written = false;

    loop {
        line.clear();
        let read = reader.read_until(b'\n', &mut line).await?;
        if read == 0 {
            break;
        }
        if line.last() == Some(&b'\n') {
            line.pop();
        }
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        let text = String::from_utf8_lossy(&line);
        if text.trim().is_empty() || text.trim() == "-- No entries --" {
            continue;
        }
        saw_entry = true;
        let entry = parse::parse_line(&text);
        if !filters.matches(&entry) {
            continue;
        }
        wrote_entry = true;
        if args.format == LogOutputFormat::Table && !header_written {
            if let Err(err) = output::write_header(&mut stdout) {
                let _ = child.kill().await;
                return handle_write_error(err);
            }
            header_written = true;
        }
        if let Err(err) = output::write_entry(&mut stdout, &entry, args.format, color) {
            let _ = child.kill().await;
            return handle_write_error(err);
        }
        if args.follow
            && let Err(err) = stdout.flush()
        {
            let _ = child.kill().await;
            return handle_write_error(err);
        }
    }

    let status = child.wait().await?;
    if !status.success() {
        return Err(Error::Message(format!("journalctl exited with {status}")));
    }
    if args.follow {
        if !saw_entry {
            eprintln!(
                "no journal entries for unit `{}`; check --unit and journal permissions \
                 (sudo or the systemd-journal group)",
                args.unit
            );
        }
        return Ok(());
    }
    if args.lines == Some(0) {
        return Ok(());
    }
    if !saw_entry {
        eprintln!(
            "no journal entries for unit `{}`; check --unit and journal permissions \
             (sudo or the systemd-journal group)",
            args.unit
        );
    } else if !wrote_entry && filters.active() {
        eprintln!("no matching log entries");
    }
    Ok(())
}

fn handle_write_error(err: io::Error) -> Result<(), Error> {
    if err.kind() == io::ErrorKind::BrokenPipe {
        Ok(())
    } else {
        Err(Error::Io(err))
    }
}

fn journal_args(args: &LogArgs) -> Result<Vec<String>, Error> {
    if args.journalctl.trim().is_empty() {
        return Err(Error::Message("--journalctl must not be empty".to_owned()));
    }
    if args.unit.trim().is_empty() || args.unit.starts_with('-') {
        return Err(Error::Message(
            "--unit must be a unit name, not an option".to_owned(),
        ));
    }
    for (name, value) in [("--since", &args.since), ("--until", &args.until)] {
        if let Some(value) = value
            && (value.trim().is_empty() || value.starts_with('-'))
        {
            return Err(Error::Message(format!(
                "{name} must not be empty or start with `-`"
            )));
        }
    }

    let mut out = vec![
        "--unit".to_owned(),
        args.unit.clone(),
        "--no-pager".to_owned(),
        "--output=short-iso".to_owned(),
    ];
    let lines = match args.lines {
        Some(lines) => Some(lines),
        None if args.since.is_some() => None,
        None if args.follow => Some(0),
        None => Some(100),
    };
    if let Some(lines) = lines {
        out.push("--lines".to_owned());
        out.push(lines.to_string());
    }
    if let Some(since) = &args.since {
        out.push("--since".to_owned());
        out.push(since.clone());
    }
    if let Some(until) = &args.until {
        out.push("--until".to_owned());
        out.push(until.clone());
    }
    if args.follow {
        out.push("--follow".to_owned());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::LogArgs;

    fn base() -> LogArgs {
        LogArgs {
            follow: false,
            lines: None,
            since: None,
            until: None,
            ips: Vec::new(),
            peer_ips: Vec::new(),
            attacks: Vec::new(),
            categories: Vec::new(),
            rules: Vec::new(),
            actions: Vec::new(),
            methods: Vec::new(),
            statuses: Vec::new(),
            path: None,
            format: LogOutputFormat::Raw,
            no_color: false,
            unit: "kunato".to_owned(),
            journalctl: "journalctl".to_owned(),
            list_attacks: false,
        }
    }

    #[test]
    fn defaults_to_the_recent_history() {
        let args = journal_args(&base()).expect("valid args");
        assert!(args.contains(&"--output=short-iso".to_owned()));
        assert!(args.windows(2).any(|pair| pair == ["--lines", "100"]));
        assert!(!args.contains(&"--follow".to_owned()));
    }

    #[test]
    fn follow_starts_at_the_end_without_a_line_option() {
        let mut args = base();
        args.follow = true;
        let journal = journal_args(&args).expect("valid args");
        assert!(journal.windows(2).any(|pair| pair == ["--lines", "0"]));
        assert!(journal.contains(&"--follow".to_owned()));
    }

    #[test]
    fn follow_with_explicit_lines_keeps_the_backlog() {
        let mut args = base();
        args.follow = true;
        args.lines = Some(25);
        let journal = journal_args(&args).expect("valid args");
        assert!(journal.windows(2).any(|pair| pair == ["--lines", "25"]));
    }

    #[test]
    fn since_disables_the_implicit_line_limit() {
        let mut args = base();
        args.since = Some("1 hour ago".to_owned());
        let journal = journal_args(&args).expect("valid args");
        assert!(!journal.contains(&"--lines".to_owned()));
        assert!(
            journal
                .windows(2)
                .any(|pair| pair == ["--since", "1 hour ago"])
        );
    }

    #[test]
    fn rejects_option_like_values() {
        let mut args = base();
        args.unit = "--all".to_owned();
        assert!(journal_args(&args).is_err());

        let mut args = base();
        args.since = Some("--all".to_owned());
        assert!(journal_args(&args).is_err());
    }
}
