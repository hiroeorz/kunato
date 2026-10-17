mod h2c;
mod hpack;

use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

const DEFAULT_ADDR: &str = "127.0.0.1:8080";
const DEFAULT_PARALLELISM: usize = 5;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_HPACK_BOMB: usize = 100_000;
const MAX_PAD_HEADER: usize = 8 * 1024 * 1024;
const USER_AGENT: &str = "kunato-blackbox/0.1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Protocol {
    Http1,
    H2c,
}

#[derive(Debug, Clone)]
struct RequestSpec {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    body: Option<Vec<u8>>,
    protocol: Protocol,
    chunked: bool,
    hpack_bomb: Option<usize>,
    pad_header: Option<usize>,
}

struct Args {
    blocked: Option<PathBuf>,
    allowed: Option<PathBuf>,
    addr: String,
    parallelism: usize,
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<ExitCode, String> {
    let args = parse_args()?;
    let addr = resolve_addr(&args.addr)?;

    let blocked = args.blocked.as_deref().map(load_requests).transpose()?;
    let allowed = args.allowed.as_deref().map(load_requests).transpose()?;

    println!("kunato black-box test");
    println!("target: {addr}");
    println!("parallelism: {}", args.parallelism);
    if let (Some(path), Some(requests)) = (&args.blocked, &blocked) {
        println!(
            "blocked list: {} ({} requests)",
            path.display(),
            requests.len()
        );
    }
    if let (Some(path), Some(requests)) = (&args.allowed, &allowed) {
        println!(
            "allowed list: {} ({} requests)",
            path.display(),
            requests.len()
        );
    }
    println!();

    let mut errors = 0usize;
    if let Some(requests) = &blocked {
        errors += run_phase("blocked", addr, requests, args.parallelism);
    }
    if let Some(requests) = &allowed {
        errors += run_phase("allowed", addr, requests, args.parallelism);
    }

    println!();
    println!("cross-check the logs:");
    println!("  - upstream access log: only the requests from the allowed list should appear");
    println!(
        "  - kunato log: blocked requests should be logged as blocked, allowed ones forwarded"
    );
    println!("  - if blocked requests reached the upstream, make sure this client is not");
    println!("    listed in `trusted-sources` in the running configuration");

    if errors > 0 {
        eprintln!("{errors} request(s) failed at the transport level");
        Ok(ExitCode::FAILURE)
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

fn run_phase(label: &str, addr: SocketAddr, requests: &[RequestSpec], parallelism: usize) -> usize {
    println!("--- phase: {label} ({}) ---", requests.len());
    if requests.is_empty() {
        return 0;
    }

    let next = AtomicUsize::new(0);
    let outcomes = Mutex::new(Vec::with_capacity(requests.len()));
    let workers = parallelism.clamp(1, requests.len());

    thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    let Some(request) = requests.get(index) else {
                        break;
                    };
                    let started = Instant::now();
                    let result = send(addr, request);
                    let elapsed = started.elapsed();

                    match &result {
                        Ok(status) => println!(
                            "[{label}] {:>2}/{} {} {} -> {} ({} ms)",
                            index + 1,
                            requests.len(),
                            request.method,
                            request.target,
                            status,
                            elapsed.as_millis()
                        ),
                        Err(error) => eprintln!(
                            "[{label}] {:>2}/{} {} {} -> error: {} ({} ms)",
                            index + 1,
                            requests.len(),
                            request.method,
                            request.target,
                            error,
                            elapsed.as_millis()
                        ),
                    }

                    outcomes
                        .lock()
                        .expect("outcomes lock")
                        .push(result.is_err());
                }
            });
        }
    });

    let outcomes = outcomes.into_inner().expect("outcomes lock");
    let errors = outcomes.iter().filter(|failed| **failed).count();
    println!(
        "phase {label}: {} request(s), {errors} transport error(s)",
        requests.len()
    );
    println!();
    errors
}

fn send(addr: SocketAddr, request: &RequestSpec) -> Result<String, String> {
    let mut stream = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)
        .map_err(|err| format!("connect: {err}"))?;
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|err| format!("set read timeout: {err}"))?;
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|err| format!("set write timeout: {err}"))?;

    match request.protocol {
        Protocol::Http1 => send_http1(&mut stream, addr, request),
        Protocol::H2c => h2c::send(
            &mut stream,
            &h2c::H2Request {
                method: &request.method,
                target: &request.target,
                authority: &addr.to_string(),
                headers: &request.headers,
                body: request.body.as_deref().unwrap_or(&[]),
                hpack_bomb: request.hpack_bomb,
                pad_header: request.pad_header,
            },
        ),
    }
}

fn send_http1(
    stream: &mut TcpStream,
    addr: SocketAddr,
    request: &RequestSpec,
) -> Result<String, String> {
    let mut message = String::new();
    message.push_str(&format!(
        "{} {} HTTP/1.1\r\n",
        request.method, request.target
    ));
    message.push_str(&format!("Host: {addr}\r\n"));
    message.push_str("Connection: close\r\n");

    let mut has_user_agent = false;
    for (name, value) in &request.headers {
        if name.eq_ignore_ascii_case("user-agent") {
            has_user_agent = true;
        }
        message.push_str(&format!("{name}: {value}\r\n"));
    }
    if !has_user_agent {
        message.push_str(&format!("User-Agent: {USER_AGENT}\r\n"));
    }
    if let Some(length) = request.pad_header {
        message.push_str(&format!("x-pad: {}\r\n", "a".repeat(length)));
    }

    let body = request.body.as_deref().unwrap_or(&[]);
    if !request.chunked && !body.is_empty() {
        message.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    if request.chunked {
        message.push_str("Transfer-Encoding: chunked\r\n");
    }
    message.push_str("\r\n");

    stream
        .write_all(message.as_bytes())
        .map_err(|err| format!("write: {err}"))?;
    if request.chunked {
        const CHUNK_BYTES: usize = 4096;
        let mut remaining = body;
        while !remaining.is_empty() {
            let (chunk, rest) = remaining.split_at(remaining.len().min(CHUNK_BYTES));
            stream
                .write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
                .map_err(|err| format!("write chunk header: {err}"))?;
            stream
                .write_all(chunk)
                .map_err(|err| format!("write chunk: {err}"))?;
            stream
                .write_all(b"\r\n")
                .map_err(|err| format!("write chunk terminator: {err}"))?;
            remaining = rest;
        }
        stream
            .write_all(b"0\r\n\r\n")
            .map_err(|err| format!("write final chunk: {err}"))?;
    } else if !body.is_empty() {
        stream
            .write_all(body)
            .map_err(|err| format!("write body: {err}"))?;
    }
    stream.flush().map_err(|err| format!("flush: {err}"))?;

    let mut response = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => {
                response.extend_from_slice(&chunk[..read]);
                if response.len() >= MAX_RESPONSE_BYTES {
                    break;
                }
            }
            Err(err) => return Err(format!("read: {err}")),
        }
    }

    if response.is_empty() {
        return Err("empty response".to_owned());
    }

    let line_end = response
        .iter()
        .position(|byte| *byte == b'\n')
        .unwrap_or(response.len());
    let status_line = String::from_utf8_lossy(&response[..line_end]);
    let status = status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| format!("malformed status line: {}", status_line.trim()))?;

    Ok(status.to_owned())
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        blocked: None,
        allowed: None,
        addr: DEFAULT_ADDR.to_owned(),
        parallelism: DEFAULT_PARALLELISM,
    };

    let mut iter = env::args().skip(1);
    while let Some(argument) = iter.next() {
        match argument.as_str() {
            "--blocked" => args.blocked = Some(PathBuf::from(next_value(&mut iter, "--blocked")?)),
            "--allowed" => args.allowed = Some(PathBuf::from(next_value(&mut iter, "--allowed")?)),
            "--addr" => args.addr = next_value(&mut iter, "--addr")?,
            "--parallelism" => {
                let value = next_value(&mut iter, "--parallelism")?;
                let parallelism: usize = value
                    .parse()
                    .map_err(|_| format!("invalid --parallelism `{value}`"))?;
                if parallelism == 0 {
                    return Err("--parallelism must be at least 1".to_owned());
                }
                args.parallelism = parallelism;
            }
            "-h" | "--help" => {
                print_usage();
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument `{other}` (try --help)")),
        }
    }

    if args.blocked.is_none() && args.allowed.is_none() {
        return Err("provide at least one of --blocked or --allowed".to_owned());
    }

    Ok(args)
}

fn next_value(iter: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    iter.next()
        .ok_or_else(|| format!("{flag} requires a value"))
}

fn print_usage() {
    println!(
        "kunato black-box test driver

USAGE:
  kunato-blackbox --blocked <FILE> [--allowed <FILE>] [OPTIONS]

OPTIONS:
  --blocked <FILE>     request list that must be stopped by Kunato
  --allowed <FILE>     request list that must reach the upstream
  --addr <HOST:PORT>   Kunato address (default {DEFAULT_ADDR})
  --parallelism <N>    concurrent workers (default {DEFAULT_PARALLELISM})
  -h, --help           print this help

REQUEST LIST FORMAT:
  METHOD TARGET [attribute ...]
    ua=<value>          User-Agent header
    body=<value>        request body, as text
    bodyhex=<hex>       request body, as even-length hex bytes
    body_file=<path>    request body read from a file, relative to the list
    chunked=1           send the body with Transfer-Encoding: chunked (HTTP/1.1)
    header=\"Name: value\"  arbitrary request header
    proto=http1|h2c     wire protocol; h2c is HTTP/2 cleartext with prior knowledge
    hpack_bomb=<n>      add an HPACK compression bomb expanding to n extra fields
                        (requires proto=h2c)
    pad_header=<n>      add an `x-pad` header with n bytes of padding
    <name>=<value>      any other name becomes a request header

  Quote values that contain spaces or quotes with \"...\"; inside a quoted
  value use \\\" for a literal quote and \\\\ for a backslash. Blank lines and
  lines starting with `#` are ignored."
    );
}

fn resolve_addr(raw: &str) -> Result<SocketAddr, String> {
    raw.to_socket_addrs()
        .map_err(|err| format!("invalid --addr `{raw}`: {err}"))?
        .next()
        .ok_or_else(|| format!("failed to resolve --addr `{raw}`"))
}

fn load_requests(path: &Path) -> Result<Vec<RequestSpec>, String> {
    let text = fs::read_to_string(path)
        .map_err(|err| format!("failed to read `{}`: {err}", path.display()))?;
    let base = path.parent().unwrap_or_else(|| Path::new("."));

    let mut requests = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let request = parse_request(line, base)
            .map_err(|message| format!("{}:{}: {message}", path.display(), index + 1))?;
        requests.push(request);
    }

    Ok(requests)
}

fn parse_request(line: &str, base: &Path) -> Result<RequestSpec, String> {
    let tokens = split_tokens(line)?;
    let mut tokens = tokens.into_iter();

    let method = tokens.next().ok_or("missing method")?;
    let target = tokens.next().ok_or("missing target")?;
    if !target.starts_with('/') {
        return Err(format!("target must start with `/`: `{target}`"));
    }

    let mut headers = Vec::new();
    let mut body = None;
    let mut protocol = Protocol::Http1;
    let mut chunked = false;
    let mut hpack_bomb = None;
    let mut pad_header = None;

    for token in tokens {
        let (key, value) = token
            .split_once('=')
            .ok_or_else(|| format!("attributes must be key=value: `{token}`"))?;
        if key.is_empty() || value.is_empty() {
            return Err(format!("empty attribute: `{token}`"));
        }
        match key {
            "ua" => headers.push(("User-Agent".to_owned(), value.to_owned())),
            "body" => body = Some(value.as_bytes().to_vec()),
            "bodyhex" => body = Some(decode_hex(value)?),
            "body_file" => body = Some(read_body_file(base, value)?),
            "proto" => {
                protocol = match value {
                    "http1" => Protocol::Http1,
                    "h2c" => Protocol::H2c,
                    other => {
                        return Err(format!(
                            "unknown proto `{other}` (expected `http1` or `h2c`)"
                        ));
                    }
                }
            }
            "chunked" => {
                if value != "1" {
                    return Err(format!("`chunked` must be `1`, got `{value}`"));
                }
                chunked = true;
            }
            "hpack_bomb" => hpack_bomb = Some(parse_count(value, "hpack_bomb", MAX_HPACK_BOMB)?),
            "pad_header" => pad_header = Some(parse_count(value, "pad_header", MAX_PAD_HEADER)?),
            "header" => {
                let (name, header_value) = value
                    .split_once(':')
                    .ok_or_else(|| format!("`header` must be `Name: value`, got `{value}`"))?;
                let name = name.trim();
                if name.is_empty() {
                    return Err(format!("empty header name in `{value}`"));
                }
                headers.push((name.to_owned(), header_value.trim().to_owned()));
            }
            name => headers.push((name.to_owned(), value.to_owned())),
        }
    }

    if hpack_bomb.is_some() && protocol != Protocol::H2c {
        return Err("`hpack_bomb` requires `proto=h2c`".to_owned());
    }
    if chunked && protocol != Protocol::Http1 {
        return Err("`chunked` requires the HTTP/1.1 protocol".to_owned());
    }

    Ok(RequestSpec {
        method,
        target,
        headers,
        body,
        protocol,
        chunked,
        hpack_bomb,
        pad_header,
    })
}

fn parse_count(value: &str, name: &str, max: usize) -> Result<usize, String> {
    let count: usize = value
        .parse()
        .map_err(|_| format!("invalid `{name}` value `{value}`"))?;
    if count == 0 || count > max {
        return Err(format!("`{name}` must be between 1 and {max}"));
    }
    Ok(count)
}

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    let digits = value.as_bytes();
    if !digits.len().is_multiple_of(2) {
        return Err(format!(
            "`bodyhex` must contain an even number of hex digits: `{value}`"
        ));
    }
    let mut bytes = Vec::with_capacity(digits.len() / 2);
    for pair in digits.chunks(2) {
        let high = hex_value(pair[0])
            .ok_or_else(|| format!("invalid hex digit in `bodyhex`: `{value}`"))?;
        let low = hex_value(pair[1])
            .ok_or_else(|| format!("invalid hex digit in `bodyhex`: `{value}`"))?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn read_body_file(base: &Path, value: &str) -> Result<Vec<u8>, String> {
    let path = Path::new(value);
    let resolved = if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    };
    fs::read(&resolved)
        .map_err(|err| format!("failed to read `body_file` `{}`: {err}", resolved.display()))
}

fn split_tokens(line: &str) -> Result<Vec<String>, String> {
    let mut tokens = Vec::new();
    let mut chars = line.chars().peekable();

    while let Some(&character) = chars.peek() {
        if character.is_whitespace() {
            chars.next();
            continue;
        }

        let mut token = String::new();
        let mut in_quotes = false;
        while let Some(&character) = chars.peek() {
            if character == '\\' {
                chars.next();
                let Some(escaped) = chars.next() else {
                    return Err("dangling escape".to_owned());
                };
                token.push(escaped);
                continue;
            }
            if character == '"' {
                chars.next();
                in_quotes = !in_quotes;
                continue;
            }
            if character.is_whitespace() && !in_quotes {
                break;
            }
            token.push(character);
            chars.next();
        }

        if in_quotes {
            return Err("unterminated quoted value".to_owned());
        }
        tokens.push(token);
    }

    Ok(tokens)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_text_body() {
        let request = parse_request("POST /submit body=hello", Path::new(".")).expect("parses");
        assert_eq!(request.body.as_deref(), Some(b"hello".as_slice()));
    }

    #[test]
    fn parses_hex_body() {
        let request =
            parse_request("POST /submit bodyhex=410d0a00ff", Path::new(".")).expect("parses");
        assert_eq!(
            request.body.as_deref(),
            Some([0x41, 0x0d, 0x0a, 0x00, 0xff].as_slice())
        );
    }

    #[test]
    fn rejects_odd_length_hex() {
        let error = parse_request("POST /submit bodyhex=abc", Path::new(".")).expect_err("errs");
        assert!(error.contains("even number"), "unexpected error: {error}");
    }

    #[test]
    fn rejects_non_hex_digits() {
        let error = parse_request("POST /submit bodyhex=zz", Path::new(".")).expect_err("errs");
        assert!(error.contains("invalid hex"), "unexpected error: {error}");
    }

    #[test]
    fn reads_body_file_relative_to_list() {
        let dir = env::temp_dir().join(format!("kunato-blackbox-{}", std::process::id()));
        fs::create_dir_all(&dir).expect("create temp dir");
        fs::write(dir.join("blob.bin"), [0x00, 0x1b, 0xff]).expect("write blob");

        let request =
            parse_request("POST /submit body_file=blob.bin", &dir).expect("parses body file");
        assert_eq!(request.body.as_deref(), Some([0x00, 0x1b, 0xff].as_slice()));

        fs::remove_dir_all(&dir).expect("remove temp dir");
    }

    #[test]
    fn reports_missing_body_file() {
        let error =
            parse_request("POST /submit body_file=missing.bin", Path::new(".")).expect_err("errs");
        assert!(error.contains("body_file"), "unexpected error: {error}");
    }

    #[test]
    fn quoted_values_keep_escapes() {
        let request = parse_request(
            r#"POST /submit body="a\"b\\c" header="X-Test: a b""#,
            Path::new("."),
        )
        .expect("parses");
        assert_eq!(request.body.as_deref(), Some(b"a\"b\\c".as_slice()));
        assert_eq!(
            request.headers,
            vec![("X-Test".to_owned(), "a b".to_owned())]
        );
    }

    #[test]
    fn parses_h2c_attributes() {
        let request = parse_request(
            "GET /check proto=h2c hpack_bomb=40 pad_header=70000",
            Path::new("."),
        )
        .expect("parses");
        assert_eq!(request.protocol, Protocol::H2c);
        assert_eq!(request.hpack_bomb, Some(40));
        assert_eq!(request.pad_header, Some(70000));
    }

    #[test]
    fn parses_chunked_requests() {
        let request =
            parse_request("POST /upload chunked=1 body=hello", Path::new(".")).expect("parses");
        assert!(request.chunked);
        assert_eq!(request.protocol, Protocol::Http1);
    }

    #[test]
    fn rejects_chunked_with_h2c() {
        let error = parse_request("POST /upload proto=h2c chunked=1 body=x", Path::new("."))
            .expect_err("errs");
        assert!(error.contains("HTTP/1.1"), "unexpected error: {error}");
    }

    #[test]
    fn rejects_invalid_chunked_values() {
        let error = parse_request("POST /upload chunked=0", Path::new(".")).expect_err("errs");
        assert!(
            error.contains("`chunked` must be `1`"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn defaults_to_http1() {
        let request = parse_request("GET /", Path::new(".")).expect("parses");
        assert_eq!(request.protocol, Protocol::Http1);
        assert_eq!(request.hpack_bomb, None);
        assert_eq!(request.pad_header, None);
    }

    #[test]
    fn rejects_unknown_protocol() {
        let error = parse_request("GET / proto=h3", Path::new(".")).expect_err("errs");
        assert!(error.contains("unknown proto"), "unexpected error: {error}");
    }

    #[test]
    fn rejects_hpack_bomb_without_h2c() {
        let error = parse_request("GET / hpack_bomb=10", Path::new(".")).expect_err("errs");
        assert!(
            error.contains("requires `proto=h2c`"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn rejects_zero_counts() {
        let error =
            parse_request("GET / proto=h2c hpack_bomb=0", Path::new(".")).expect_err("errs");
        assert!(error.contains("between 1"), "unexpected error: {error}");
    }
}
