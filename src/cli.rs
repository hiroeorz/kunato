use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;

mod parse;

pub use parse::ParseError;

use crate::allowed_hosts::AllowedHosts;
use crate::error::Error;

pub const DEFAULT_RULES_URL: &str =
    "https://raw.githubusercontent.com/hiroeorz/kunato/main/dist/rules.yaml";
pub const DEFAULT_RULES_FILE: &str = "/var/lib/kunato/rules.yaml";
pub const DEFAULT_CONFIG_PATH: &str = "/etc/kunato/kunato.yaml";

/// Admin listener queried by `kunato metrics`.
pub const DEFAULT_METRICS_LISTEN: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9090));

#[derive(Debug)]
pub struct Cli {
    /// Path to the YAML configuration file (used by server/config modes).
    pub config: PathBuf,

    /// Validate the configuration and exit (server/config modes).
    pub validate: bool,

    /// Disable DoS/DDoS protection for server mode.
    ///
    /// Disables rate limits, bans, and connection budgets. Not used by the log
    /// subcommand.
    pub disable_protection: bool,

    /// Service log level filter (overrides RUST_LOG).
    ///
    /// Examples: error, warn, info, debug, trace, kunato::proxy=debug,info.
    /// This does not filter the output of the log subcommand.
    pub log_level: Option<String>,

    /// Service log output format (not the log viewer; use --format there).
    pub log_format: LogFormat,

    pub command: Option<Command>,
}

#[derive(Debug)]
pub enum Command {
    /// Write a starter configuration file and exit.
    Init(Box<InitArgs>),

    /// Validate the configuration (including rules_file and overrides_file) and exit.
    Validate,

    /// Download the rules file once and exit.
    UpdateRules,

    /// Upgrade the installed binary and systemd unit from a release,
    /// keeping the configuration, by rerunning the official installer.
    Upgrade(UpgradeArgs),

    /// Read the systemd journal for the Kunato service.
    Log(Box<LogArgs>),

    /// Print the Prometheus metrics served by the admin listener.
    Metrics(MetricsArgs),
}

#[derive(Debug)]
pub struct UpgradeArgs {
    /// Release tag to install (default: the latest release).
    pub version: Option<String>,

    /// Print what would be downloaded and run without changing anything.
    pub dry_run: bool,
}

#[derive(Debug)]
pub struct MetricsArgs {
    /// Admin listener address serving `GET /metrics`.
    ///
    /// Only loopback addresses are accepted; the admin listener never binds a
    /// public interface.
    pub listen: SocketAddr,
}

#[derive(Debug)]
pub struct LogArgs {
    /// Follow new journal entries.
    ///
    /// Without --lines or --since, starts at the current end and shows only
    /// new entries. With either option, shows that backlog first and then
    /// follows.
    pub follow: bool,

    /// Number of journal lines to read.
    ///
    /// This limits the lines read from journalctl before filtering, not the
    /// number of matching events. 0 disables the history. The non-follow
    /// default is 100; the follow default is 0. Examples: 20, 100, 1000.
    pub lines: Option<usize>,

    /// Start time passed to journalctl.
    ///
    /// Accepts journalctl time syntax, for example "2026-10-21 10:00:00",
    /// "yesterday", "today", or "1 hour ago". Quote values containing spaces.
    /// If --lines is not given, a --since range is not limited to the implicit
    /// 100 lines.
    pub since: Option<String>,

    /// End time passed to journalctl.
    ///
    /// Accepts the same syntax as --since, for example "now", "today", or
    /// "2026-10-21 18:00:00". Quote values containing spaces.
    pub until: Option<String>,

    /// Filter by resolved client IP address or CIDR.
    ///
    /// Accepts exact IPv4/IPv6 addresses and CIDR ranges, for example
    /// 203.0.113.9, 2001:db8::1, 203.0.113.0/24, or 2001:db8::/32.
    /// Events without a client field fall back to the transport peer.
    /// Repeat the flag or comma-separate values; values are ORed.
    pub ips: Vec<String>,

    /// Filter by transport peer address or CIDR.
    ///
    /// This is the direct connection address before client_ip resolution.
    /// Accepts the same forms as --ip: 203.0.113.9, 2001:db8::1,
    /// 203.0.113.0/24, or 2001:db8::/32. Repeat or comma-separate.
    pub peer_ips: Vec<String>,

    /// Filter by category-based attack type.
    ///
    /// Injection and browser classes (aliases in parentheses):
    ///   sql-injection (sqli), nosql-injection (nosql),
    ///   ldap-injection (ldap), xpath-injection (xpath),
    ///   jdbc-injection (jdbc), command-injection (command, rce), ssti,
    ///   config-injection (config), xss, css-injection (css),
    ///   open-redirect (redirect).
    ///
    /// Server-side and file classes:
    ///   path-traversal (traversal, lfi),
    ///   remote-file-inclusion (rfi), malicious-upload (upload), ssrf, xxe,
    ///   deserialization, prototype-pollution (prototype), jwt.
    ///
    /// Access, reconnaissance, and exploit classes:
    ///   scanner (scanners), brute-force (bruteforce, login-throttle),
    ///   discovery, exposure,
    ///   info-disclosure (infodisclosure, leaks), bypass, exploit, protocol.
    ///
    /// Vulnerability classes:
    ///   cve, cve-YYYY, cve-YYYY-MM.
    ///
    /// Examples: sqli, xss, scanner, cve-2025. Use --list-attacks for the
    /// full class-to-category mapping. Repeat or comma-separate values.
    pub attacks: Vec<String>,

    /// Filter by exact rule category name.
    ///
    /// Case-insensitive. Examples: sql-injection, scanners-and-bots,
    /// cve-2025-signatures, response-leaks. Use --list-attacks to see how
    /// classes map to categories. Repeat or comma-separate values.
    pub categories: Vec<String>,

    /// Filter by exact rule name.
    ///
    /// Case-insensitive. Examples: union-select, log4shell,
    /// seo-and-ai-crawlers, private-key-material. Repeat or comma-separate.
    pub rules: Vec<String>,

    /// Filter by logged action.
    ///
    /// Accepted values: BLOCK, LOG. ALLOW rule matches are not logged, so
    /// ALLOW is not accepted. Repeat or comma-separate.
    pub actions: Vec<String>,

    /// Filter by HTTP method.
    ///
    /// Case-insensitive. Common values: GET, POST, PUT, PATCH, DELETE, HEAD,
    /// OPTIONS. Extension methods are also accepted. Repeat or comma-separate.
    pub methods: Vec<String>,

    /// Filter by recorded HTTP status code.
    ///
    /// Accepts 100-599. Examples: 403, 404, 429. Only events that recorded a
    /// status match (rule blocks, rejections, rate limits, response events).
    /// Repeat or comma-separate.
    pub statuses: Vec<u16>,

    /// Filter by request path using a Rust regular expression.
    ///
    /// Matched against the recorded path only; the query string is not logged.
    /// Examples: ^/api/, (?i)login, \.php$, /admin/.
    pub path: Option<String>,

    /// Viewer output format.
    ///
    /// raw: the journalctl line unchanged (default).
    /// table: normalized columns TIME, LEVEL, EVENT, ACTION, ATTACK, CLIENT,
    ///        METHOD, PATH, STATUS, RULE, DETAIL.
    /// json: one JSON object per line, with normalized fields and a fields map.
    /// This does not change the service logging format; use the global
    /// --log-format option for that.
    pub format: LogOutputFormat,

    /// Disable ANSI colors in table output.
    ///
    /// Colors are used only when stdout is a terminal and NO_COLOR is not set.
    pub no_color: bool,

    /// systemd unit name to read.
    ///
    /// For example kunato or kunato.service. The default is kunato.
    pub unit: String,

    /// journalctl executable to run.
    ///
    /// For example /usr/bin/journalctl. The default searches PATH for
    /// journalctl. This option is mainly for non-standard installations and
    /// tests.
    pub journalctl: String,

    /// List supported attack types and exit.
    ///
    /// Prints every class, alias, and the categories it matches; does not read
    /// the journal or require journal permissions.
    pub list_attacks: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogOutputFormat {
    Raw,
    Table,
    Json,
}

#[derive(Debug)]
pub struct InitArgs {
    /// Upstream URL that Kunato forwards requests to.
    pub upstream: String,

    /// Address to listen on.
    pub listen: SocketAddr,

    /// TLS certificate chain in PEM format.
    pub cert_file: Option<PathBuf>,

    /// TLS private key in PEM format.
    pub key_file: Option<PathBuf>,

    /// Obtain certificates automatically through ACME (Let's Encrypt); repeat
    /// for every domain.
    pub acme_domains: Vec<String>,

    /// Contact email registered with the ACME account.
    pub acme_contact: Option<String>,

    /// Use the Let's Encrypt staging directory (untrusted test certificates).
    pub acme_staging: bool,

    /// Extra Host names or IP literals clients use to reach this server. The
    /// ACME domains are added automatically; repeat the flag for more names.
    pub allowed_hosts: Vec<String>,

    /// Rules file refreshed by the daily updater.
    pub rules_file: PathBuf,

    /// URL to download the rules file from.
    pub rules_url: String,

    /// Optional local overrides file, evaluated before every other rule source.
    pub overrides_file: Option<PathBuf>,

    /// Output configuration path.
    pub output: PathBuf,

    /// Overwrite an existing configuration file.
    pub force: bool,
}

impl InitArgs {
    pub fn render(&self) -> Result<String, Error> {
        let mut out = String::with_capacity(1024);
        out.push_str("# Kunato configuration, generated by `kunato init`.\n");
        out.push_str("# See docs/development.md for the full field reference.\n\n");
        out.push_str(&format!(
            "listen: {}\n",
            yaml_scalar(&self.listen.to_string())
        ));
        if matches!(self.listen.ip(), IpAddr::V4(address) if address.is_unspecified()) {
            let ipv6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), self.listen.port());
            out.push_str(
                "# Dual-stack alternative on Linux: `[::]` also accepts IPv4 clients\n\
                 # (as IPv4-mapped addresses), even without a routable IPv6 address.\n\
                 # Avoid it if IPv6 is disabled in the kernel or net.ipv6.bindv6only=1.\n",
            );
            out.push_str(&format!("# listen: {}\n", yaml_scalar(&ipv6.to_string())));
        }
        out.push_str(&format!("upstream: {}\n", yaml_scalar(&self.upstream)));

        let allowed_hosts = self.render_allowed_hosts()?;
        if allowed_hosts.is_empty() {
            out.push_str(
                "\n# Host allowlisting is disabled. List every name and IP address clients\n\
                 # use to reach this server to reject other Host headers with 421:\n\
                 # allowed_hosts:\n\
                 #   - example.com\n\
                 #   - 127.0.0.1\n",
            );
        } else {
            out.push_str(
                "\n# Requests whose Host header is not listed here are rejected with 421 (a\n\
                 # missing or malformed Host gets 400) before rule evaluation. ACME\n\
                 # domains are added automatically; add every other name and IP address\n\
                 # clients use to reach this server.\n",
            );
            out.push_str("allowed_hosts:\n");
            for host in &allowed_hosts {
                out.push_str(&format!("  - {}\n", yaml_scalar(host)));
            }
        }

        if !self.acme_domains.is_empty() {
            out.push_str(
                "\n# Automatic certificates through ACME (TLS-ALPN-01 on :443). Every domain\n\
                 # must resolve to this server and TCP port 443 must stay reachable.\n",
            );
            out.push_str("tls:\n");
            out.push_str("  acme:\n");
            out.push_str("    enabled: true\n");
            out.push_str("    domains:\n");
            for domain in &self.acme_domains {
                out.push_str(&format!("      - {}\n", yaml_scalar(domain)));
            }
            if let Some(contact) = &self.acme_contact {
                out.push_str(&format!("    contact: {}\n", yaml_scalar(contact)));
            }
            if self.acme_staging {
                out.push_str("    staging: true\n");
            }
        } else if let (Some(cert), Some(key)) = (&self.cert_file, &self.key_file) {
            out.push_str("\n# Server certificate and key. Required when listening on :443.\n");
            out.push_str("tls:\n");
            out.push_str(&format!("  cert_file: {}\n", yaml_scalar(&path_str(cert))));
            out.push_str(&format!("  key_file: {}\n", yaml_scalar(&path_str(key))));
        }

        out.push_str("\n# Local rules. Evaluated after overrides_file and before rules_file,\n");
        out.push_str("# so keep this list for rules that must beat the managed rule set.\n");
        out.push_str("categories: []\n");

        out.push_str(
            "\n# Managed rule set (categories only). The daily updater replaces this file\n\
             # atomically after checksum verification and validation. Do not edit it.\n",
        );
        out.push_str(&format!(
            "rules_file: {}\n",
            yaml_scalar(&path_str(&self.rules_file))
        ));

        if let Some(overrides) = &self.overrides_file {
            out.push_str(
                "\n# Local overrides, evaluated before every other source. Use it for ALLOW\n\
                 # exceptions and `disabled_rules`.\n",
            );
            out.push_str(&format!(
                "overrides_file: {}\n",
                yaml_scalar(&path_str(overrides))
            ));
        }

        out.push_str(
            "\n# Behind a CDN/load balancer, trust only its actual IPs/CIDRs. Requests\n\
             # from these peers must carry a valid client identity header.\n\
             # client_ip:\n\
             #   trusted_proxies: [10.0.0.10/32]\n\
             #   header: x-forwarded-for\n",
        );

        out.push_str(
            "\n# Behavioral detection observes upstream response statuses and can flag\n\
             # sources that probe missing paths or fail authentication repeatedly. It\n\
             # starts in LOG mode; uncomment and raise a signal's action to BLOCK after\n\
             # reviewing the logs.\n\
             # protection:\n\
             #   behavior:\n\
             #     enabled: true\n\
             #     enumeration: { action: LOG }\n\
             #     auth: { action: LOG }\n",
        );

        out.push_str("\nrules_update:\n");
        out.push_str("  enabled: true\n");
        out.push_str(&format!("  url: {}\n", yaml_scalar(&self.rules_url)));
        out.push_str(&format!(
            "  checksum_url: {}\n",
            yaml_scalar(&format!("{}.sha256", self.rules_url))
        ));
        out.push_str("  interval: 24h\n");
        out.push_str("  jitter_percent: 10\n");
        out.push_str("  max_bytes: 1048576\n");
        Ok(out)
    }

    fn render_allowed_hosts(&self) -> Result<Vec<String>, Error> {
        let combined: Vec<String> = self
            .acme_domains
            .iter()
            .chain(self.allowed_hosts.iter())
            .cloned()
            .collect();
        if combined.is_empty() {
            return Ok(combined);
        }

        let mut issues = Vec::new();
        if AllowedHosts::validate(&combined, &mut issues).is_none() {
            return Err(Error::Message(issues.join("; ")));
        }

        let mut seen = BTreeSet::new();
        let mut hosts = Vec::new();
        for host in combined {
            if seen.insert(host.trim_end_matches('.').to_ascii_lowercase()) {
                hosts.push(host);
            }
        }
        Ok(hosts)
    }
}

fn path_str(path: &std::path::Path) -> String {
    path.to_string_lossy().into_owned()
}

fn yaml_scalar(value: &str) -> String {
    let plain = !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/' | b':' | b'@')
        });
    if plain {
        value.to_owned()
    } else {
        format!("'{}'", value.replace('\'', "''"))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Text,
    Json,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;

    fn args() -> InitArgs {
        InitArgs {
            upstream: "http://127.0.0.1:3000".to_owned(),
            listen: "0.0.0.0:443".parse().expect("addr"),
            cert_file: Some(PathBuf::from("/etc/kunato/tls/cert.pem")),
            key_file: Some(PathBuf::from("/etc/kunato/tls/key.pem")),
            acme_domains: Vec::new(),
            acme_contact: None,
            acme_staging: false,
            allowed_hosts: Vec::new(),
            rules_file: PathBuf::from(DEFAULT_RULES_FILE),
            rules_url: DEFAULT_RULES_URL.to_owned(),
            overrides_file: Some(PathBuf::from("/etc/kunato/overrides.yaml")),
            output: PathBuf::from("kunato.yaml"),
            force: false,
        }
    }

    #[test]
    fn renders_a_valid_configuration() {
        let text = args().render().expect("render");
        let compiled = config::parse(&text).expect("generated config must be valid");
        assert_eq!(compiled.listen.port(), 443);
        assert!(compiled.tls.is_some());
        assert!(compiled.rules_update.enabled);
        assert_eq!(
            compiled.rules_file.as_deref(),
            Some(std::path::Path::new(DEFAULT_RULES_FILE))
        );
        assert_eq!(
            compiled.overrides_file.as_deref(),
            Some(std::path::Path::new("/etc/kunato/overrides.yaml"))
        );
    }

    #[test]
    fn renders_without_tls_when_not_requested() {
        let mut args = args();
        args.cert_file = None;
        args.key_file = None;
        let text = args.render().expect("render");
        let compiled = config::parse(&text).expect("generated config must be valid");
        assert!(compiled.tls.is_none());
    }

    #[test]
    fn renders_acme_configuration() {
        let mut args = args();
        args.cert_file = None;
        args.key_file = None;
        args.acme_domains = vec!["example.com".to_owned(), "www.example.com".to_owned()];
        args.acme_contact = Some("admin@example.com".to_owned());
        let text = args.render().expect("render");
        let compiled = config::parse(&text).expect("generated config must be valid");
        let acme = compiled
            .tls
            .expect("tls block")
            .acme
            .expect("acme settings");
        assert_eq!(acme.domains, vec!["example.com", "www.example.com"]);
        assert_eq!(acme.contact.as_deref(), Some("admin@example.com"));
        let allowed = compiled.allowed_hosts.expect("allowed hosts");
        assert!(allowed.matches("example.com"));
        assert!(allowed.matches("www.example.com"));
    }

    #[test]
    fn renders_allowed_hosts_from_acme_and_explicit_flags() {
        let mut args = args();
        args.cert_file = None;
        args.key_file = None;
        args.acme_domains = vec!["example.com".to_owned(), "www.example.com".to_owned()];
        args.allowed_hosts = vec!["127.0.0.1".to_owned(), "EXAMPLE.COM".to_owned()];
        let text = args.render().expect("render");
        assert!(text.contains("allowed_hosts:\n"));

        let compiled = config::parse(&text).expect("generated config must be valid");
        let allowed = compiled.allowed_hosts.expect("allowed hosts");
        assert!(allowed.matches("example.com"));
        assert!(allowed.matches("www.example.com"));
        assert!(allowed.matches("127.0.0.1:8080"));
        assert!(!allowed.matches("evil.example"));
        assert_eq!(text.matches("allowed_hosts:\n  - example.com\n").count(), 1);
    }

    #[test]
    fn renders_a_commented_hint_when_host_checking_is_disabled() {
        let text = args().render().expect("render");
        assert!(text.contains("# allowed_hosts:"));
        let compiled = config::parse(&text).expect("generated config must be valid");
        assert!(compiled.allowed_hosts.is_none());
    }

    #[test]
    fn renders_allowed_hosts_with_ports_and_ipv6() {
        let mut args = args();
        args.allowed_hosts = vec!["example.com:8443".to_owned(), "[::1]".to_owned()];
        let text = args.render().expect("render");
        let compiled = config::parse(&text).expect("generated config must be valid");
        let allowed = compiled.allowed_hosts.expect("allowed hosts");
        assert!(allowed.matches("example.com:8443"));
        assert!(allowed.matches("[::1]"));
        assert!(!allowed.matches("example.com"));
    }

    #[test]
    fn rejects_an_invalid_allowed_host_during_init() {
        let mut invalid = args();
        invalid.allowed_hosts = vec!["bad host".to_owned()];
        let error = invalid.render().expect_err("must fail");
        assert!(error.to_string().contains("allowed_hosts"));

        // An invalid duplicate must not be masked by a valid entry during
        // deduplication.
        let mut duplicate = args();
        duplicate.acme_domains = vec!["example.com".to_owned()];
        duplicate.allowed_hosts = vec!["example.com..".to_owned()];
        let error = duplicate.render().expect_err("must fail");
        assert!(error.to_string().contains("allowed_hosts"));
    }

    #[test]
    fn parses_repeated_allowed_host_flags() {
        let cli = Cli::try_parse_from([
            "kunato",
            "init",
            "--upstream",
            "http://127.0.0.1:3000",
            "--allowed-host",
            "app.example.com",
            "--allowed-host",
            "127.0.0.1",
        ])
        .expect("parse");
        let Some(Command::Init(args)) = cli.command else {
            panic!("expected the init command");
        };
        assert_eq!(
            args.allowed_hosts,
            vec!["app.example.com".to_owned(), "127.0.0.1".to_owned()]
        );
    }

    #[test]
    fn renders_an_ipv4_listener_with_a_dual_stack_alternative() {
        let text = args().render().expect("render");
        assert!(text.contains("listen: 0.0.0.0:443\n"));
        assert!(text.contains("# listen: '[::]:443'\n"));
        let compiled = config::parse(&text).expect("generated config must be valid");
        assert!(compiled.listen.is_ipv4());
    }

    #[test]
    fn renders_ipv6_listeners_without_an_alternative() {
        let mut args = args();
        args.listen = "[::]:443".parse().expect("addr");
        let text = args.render().expect("render");
        assert!(text.contains("listen: '[::]:443'\n"));
        assert!(!text.contains("# listen:"));
    }

    #[test]
    fn init_defaults_to_an_ipv4_listener() {
        let cli = Cli::try_parse_from(["kunato", "init", "--upstream", "http://127.0.0.1:3000"])
            .expect("parse");
        let Some(Command::Init(args)) = cli.command else {
            panic!("expected the init command");
        };
        assert_eq!(
            args.listen,
            "0.0.0.0:443".parse::<SocketAddr>().expect("addr")
        );
    }

    #[test]
    fn config_defaults_to_the_installed_path() {
        let cli = Cli::try_parse_from(["kunato"]).expect("parse");
        assert_eq!(cli.config, PathBuf::from(DEFAULT_CONFIG_PATH));

        let cli = Cli::try_parse_from(["kunato", "--config", "local.yaml"]).expect("parse");
        assert_eq!(cli.config, PathBuf::from("local.yaml"));
    }

    #[test]
    fn parses_log_filters() {
        let cli = Cli::try_parse_from([
            "kunato",
            "log",
            "-f",
            "--ip",
            "203.0.113.9,10.0.0.0/8",
            "--attack",
            "sqli,xss",
            "--category",
            "sql-injection",
            "--action",
            "BLOCK",
            "--status",
            "429",
            "--format",
            "json",
        ])
        .expect("parse");
        let Some(Command::Log(args)) = cli.command else {
            panic!("expected the log command");
        };
        assert!(args.follow);
        assert_eq!(
            args.ips,
            vec!["203.0.113.9".to_owned(), "10.0.0.0/8".to_owned()]
        );
        assert_eq!(args.attacks, vec!["sqli".to_owned(), "xss".to_owned()]);
        assert_eq!(args.categories, vec!["sql-injection".to_owned()]);
        assert_eq!(args.actions, vec!["BLOCK".to_owned()]);
        assert_eq!(args.statuses, vec![429]);
        assert_eq!(args.format, LogOutputFormat::Json);
        assert_eq!(args.unit, "kunato");
    }

    #[test]
    fn log_defaults_to_raw_output() {
        let cli = Cli::try_parse_from(["kunato", "log"]).expect("parse");
        let Some(Command::Log(args)) = cli.command else {
            panic!("expected the log command");
        };
        assert!(!args.follow);
        assert_eq!(args.lines, None);
        assert_eq!(args.format, LogOutputFormat::Raw);
    }

    #[test]
    fn log_validates_action_and_status_values() {
        let cli = Cli::try_parse_from(["kunato", "log", "--action", "block,log"])
            .expect("actions are case-insensitive");
        let Some(Command::Log(args)) = cli.command else {
            panic!("expected the log command");
        };
        assert_eq!(args.actions.len(), 2);
        assert!(args.actions.iter().all(|action| {
            action.eq_ignore_ascii_case("BLOCK") || action.eq_ignore_ascii_case("LOG")
        }));

        assert!(Cli::try_parse_from(["kunato", "log", "--action", "ALLOW"]).is_err());
        assert!(Cli::try_parse_from(["kunato", "log", "--status", "99"]).is_err());
        assert!(Cli::try_parse_from(["kunato", "log", "--status", "429"]).is_ok());
    }

    #[test]
    fn quotes_scalars_that_need_quoting() {
        assert_eq!(yaml_scalar("plain/path.yaml"), "plain/path.yaml");
        assert_eq!(yaml_scalar("http://a?b=c"), "'http://a?b=c'");
        assert_eq!(yaml_scalar("it's"), "'it''s'");
    }
}
