//! Console authentication: the operator token, sessions, and login limiting.

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use ring::rand::{SecureRandom, SystemRandom};
use tokio::sync::watch;
use tracing::warn;

use crate::error::Error;

pub const SESSION_TTL: Duration = Duration::from_secs(12 * 60 * 60);
pub const MAX_SESSIONS: usize = 64;
pub const MAX_ATTEMPT_ENTRIES: usize = 1024;
pub const ATTEMPT_WINDOW: Duration = Duration::from_secs(60);
pub const MAX_FAILURES: u32 = 5;

const MIN_TOKEN_BYTES: usize = 32;
const MAX_TOKEN_BYTES: usize = 512;
const SESSION_BYTES: usize = 32;

/// Server-side authentication state.
pub struct Auth {
    token: Vec<u8>,
    sessions: Mutex<Sessions>,
    attempts: Mutex<Attempts>,
    revocations: watch::Sender<u64>,
}

pub enum Login {
    Accepted(String),
    Rejected,
    TooMany { retry_after_secs: u64 },
}

impl Auth {
    /// Read the token file, creating a random credential when it is missing.
    pub fn load(path: &Path) -> Result<Self, Error> {
        let token = match read_token(path)? {
            Some(token) => token,
            None => create_token(path)?,
        };
        Ok(Self {
            token,
            sessions: Mutex::new(Sessions::default()),
            attempts: Mutex::new(Attempts::default()),
            revocations: watch::channel(0).0,
        })
    }

    pub fn token_matches(&self, candidate: &[u8]) -> bool {
        constant_time_eq(&self.token, candidate)
    }

    pub fn login(&self, client: IpAddr, presented: &str, now: Instant) -> Login {
        let mut attempts = self.lock_attempts();
        if !attempts.allow(client, now) {
            return Login::TooMany {
                retry_after_secs: attempts.retry_after_secs(client, now),
            };
        }
        if !self.token_matches(presented.as_bytes()) {
            attempts.failure(client, now);
            return Login::Rejected;
        }
        attempts.success(client);
        drop(attempts);
        match self.lock_sessions().issue(now) {
            Some(session) => Login::Accepted(session),
            None => Login::Rejected,
        }
    }

    pub fn validate_session(&self, session: &str, now: Instant) -> bool {
        self.lock_sessions().validate(session, now)
    }

    /// Expiry of a live session. A stream uses this to bound its own lifetime
    /// even when no further requests arrive to validate the cookie.
    pub fn session_expiry(&self, session: &str, now: Instant) -> Option<Instant> {
        self.lock_sessions().expiry(session, now)
    }

    pub fn revoke_session(&self, session: &str) {
        self.lock_sessions().revoke(session);
        // Wake every live stream so a revoked session stops receiving state
        // immediately instead of at the next heartbeat.
        self.revocations.send_modify(|revision| {
            *revision = revision.wrapping_add(1);
        });
    }

    /// Subscribe to session revocations. A live stream revalidates its own
    /// session when the revision changes, so a logout closes only the streams
    /// that used the revoked session.
    pub fn subscribe_revocations(&self) -> watch::Receiver<u64> {
        self.revocations.subscribe()
    }

    fn lock_sessions(&self) -> std::sync::MutexGuard<'_, Sessions> {
        self.sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn lock_attempts(&self) -> std::sync::MutexGuard<'_, Attempts> {
        self.attempts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// The cookie name; the `__Host-` prefix is only valid with `Secure`.
pub fn session_cookie_name(tls: bool) -> &'static str {
    if tls {
        "__Host-kunato_console"
    } else {
        "kunato_console"
    }
}

fn read_token(path: &Path) -> Result<Option<Vec<u8>>, Error> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(Error::Message(format!(
                "failed to inspect console credential `{}`: {error}",
                path.display()
            )));
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(Error::Message(format!(
            "console credential `{}` must be a regular file",
            path.display()
        )));
    }
    if metadata.len() > (MAX_TOKEN_BYTES + 2) as u64 {
        return Err(Error::Message(format!(
            "console credential `{}` is larger than {MAX_TOKEN_BYTES} bytes",
            path.display()
        )));
    }
    let bytes = std::fs::read(path).map_err(|error| {
        Error::Message(format!(
            "failed to read console credential `{}`: {error}",
            path.display()
        ))
    })?;
    let token = trim(&bytes).to_vec();
    validate_token(&token, path)?;
    warn_token_permissions(path);
    Ok(Some(token))
}

fn create_token(path: &Path) -> Result<Vec<u8>, Error> {
    let token = random_hex(32)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(path) {
        Ok(mut file) => {
            file.write_all(token.as_bytes())?;
            file.write_all(b"\n")?;
            file.sync_all()?;
            Ok(token.into_bytes())
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => read_token(path)?
            .ok_or_else(|| {
                Error::Message(format!(
                    "console credential `{}` disappeared during creation",
                    path.display()
                ))
            }),
        Err(error) => Err(Error::Message(format!(
            "failed to create console credential `{}`: {error}",
            path.display()
        ))),
    }
}

/// Length-checked byte comparison whose duration does not depend on where the
/// first difference occurs.
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (left, right) in left.iter().zip(right) {
        difference |= left ^ right;
    }
    std::hint::black_box(difference) == 0
}

fn trim(value: &[u8]) -> &[u8] {
    let is_space = |byte: u8| matches!(byte, b' ' | b'\t' | b'\r' | b'\n');
    let mut start = 0;
    let mut end = value.len();
    while start < end && is_space(value[start]) {
        start += 1;
    }
    while end > start && is_space(value[end - 1]) {
        end -= 1;
    }
    &value[start..end]
}

fn validate_token(token: &[u8], path: &Path) -> Result<(), Error> {
    if !(MIN_TOKEN_BYTES..=MAX_TOKEN_BYTES).contains(&token.len())
        || !token.iter().all(|byte| (0x21..=0x7e).contains(byte))
    {
        return Err(Error::Message(format!(
            "console credential `{}` must be 32 to 512 printable ASCII bytes",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn warn_token_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    let Ok(metadata) = std::fs::metadata(path) else {
        return;
    };
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        warn!(
            path = %path.display(),
            mode = %format!("{mode:04o}"),
            "console credential is readable by users outside its owner; install it with mode 0600"
        );
    }
}

#[cfg(not(unix))]
fn warn_token_permissions(_path: &Path) {}

fn random_hex(bytes: usize) -> Result<String, Error> {
    let mut buffer = vec![0u8; bytes];
    SystemRandom::new()
        .fill(&mut buffer)
        .map_err(|_| Error::Message("failed to generate random console material".to_owned()))?;
    Ok(hex(&buffer))
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

#[derive(Default)]
struct Sessions {
    /// Session identifier to expiry.
    entries: BTreeMap<String, Instant>,
}

impl Sessions {
    fn issue(&mut self, now: Instant) -> Option<String> {
        self.prune(now);
        while self.entries.len() >= MAX_SESSIONS {
            let oldest = self
                .entries
                .iter()
                .min_by_key(|(_, expiry)| **expiry)
                .map(|(id, _)| id.clone())?;
            self.entries.remove(&oldest);
        }
        for _ in 0..4 {
            let id = random_hex(SESSION_BYTES).ok()?;
            if !self.entries.contains_key(&id) {
                self.entries.insert(id.clone(), now + SESSION_TTL);
                return Some(id);
            }
        }
        None
    }

    fn validate(&mut self, session: &str, now: Instant) -> bool {
        match self.entries.get(session).copied() {
            Some(expiry) if expiry > now => true,
            Some(_) => {
                self.entries.remove(session);
                false
            }
            None => false,
        }
    }

    fn expiry(&mut self, session: &str, now: Instant) -> Option<Instant> {
        match self.entries.get(session).copied() {
            Some(expiry) if expiry > now => Some(expiry),
            Some(_) => {
                self.entries.remove(session);
                None
            }
            None => None,
        }
    }

    fn revoke(&mut self, session: &str) {
        self.entries.remove(session);
    }

    fn prune(&mut self, now: Instant) {
        self.entries.retain(|_, expiry| *expiry > now);
    }
}

#[derive(Default)]
struct Attempts {
    /// Client to window start and failure count.
    entries: BTreeMap<IpAddr, (Instant, u32)>,
}

impl Attempts {
    fn allow(&mut self, client: IpAddr, now: Instant) -> bool {
        self.prune(now);
        match self.entries.get(&client) {
            Some((start, failures)) => {
                now.saturating_duration_since(*start) >= ATTEMPT_WINDOW || *failures < MAX_FAILURES
            }
            None => true,
        }
    }

    fn failure(&mut self, client: IpAddr, now: Instant) {
        self.prune(now);
        match self.entries.get_mut(&client) {
            Some((start, failures)) if now.saturating_duration_since(*start) < ATTEMPT_WINDOW => {
                *failures = failures.saturating_add(1);
            }
            Some(entry) => *entry = (now, 1),
            None => {
                if self.entries.len() >= MAX_ATTEMPT_ENTRIES {
                    self.evict_oldest();
                }
                self.entries.insert(client, (now, 1));
            }
        }
    }

    fn success(&mut self, client: IpAddr) {
        self.entries.remove(&client);
    }

    fn retry_after_secs(&mut self, client: IpAddr, now: Instant) -> u64 {
        match self.entries.get(&client) {
            Some((start, _)) => {
                let elapsed = now.saturating_duration_since(*start);
                ATTEMPT_WINDOW.saturating_sub(elapsed).as_secs().max(1)
            }
            None => 1,
        }
    }

    fn prune(&mut self, now: Instant) {
        self.entries
            .retain(|_, (start, _)| now.saturating_duration_since(*start) < ATTEMPT_WINDOW);
    }

    fn evict_oldest(&mut self) {
        if let Some(client) = self
            .entries
            .iter()
            .min_by_key(|(_, (start, _))| *start)
            .map(|(client, _)| *client)
        {
            self.entries.remove(&client);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth(dir: &Path) -> Auth {
        Auth::load(&dir.join("token")).expect("auth")
    }

    #[test]
    fn creates_a_private_token_once_and_reloads_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("token");
        let first = Auth::load(&path).expect("create");
        let second = Auth::load(&path).expect("reload");
        assert!(first.token_matches(&second.token));
        assert_eq!(first.token.len(), 64);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn rejects_a_short_credential() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("token");
        std::fs::write(&path, b"short\n").expect("write");
        assert!(Auth::load(&path).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_a_symlinked_credential() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("target");
        std::fs::write(&target, format!("{}\n", "a".repeat(64))).expect("write");
        let path = dir.path().join("token");
        std::os::unix::fs::symlink(&target, &path).expect("symlink");
        assert!(Auth::load(&path).is_err());
    }

    #[test]
    fn rejects_an_oversized_credential() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("token");
        std::fs::write(&path, "a".repeat(MAX_TOKEN_BYTES + 3)).expect("write");
        assert!(Auth::load(&path).is_err());
    }

    #[test]
    fn login_accepts_the_configured_token_and_rejects_others() {
        let dir = tempfile::tempdir().expect("tempdir");
        let auth = auth(dir.path());
        let token = String::from_utf8(auth.token.clone()).expect("utf8");
        let now = Instant::now();
        assert!(matches!(
            auth.login("127.0.0.1".parse().unwrap(), "wrong", now),
            Login::Rejected
        ));
        let Login::Accepted(session) = auth.login("127.0.0.1".parse().unwrap(), &token, now) else {
            panic!("correct token must authenticate");
        };
        assert!(auth.validate_session(&session, now));
        assert!(!auth.validate_session(&session, now + SESSION_TTL + Duration::from_secs(1)));
        auth.revoke_session(&session);
        assert!(!auth.validate_session(&session, now));
    }

    #[test]
    fn revocation_wakes_streams_and_expiry_is_exposed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let auth = auth(dir.path());
        let token = String::from_utf8(auth.token.clone()).expect("utf8");
        let now = Instant::now();
        let Login::Accepted(session) = auth.login("127.0.0.1".parse().unwrap(), &token, now) else {
            panic!("correct token must authenticate");
        };
        assert!(auth.session_expiry(&session, now).is_some());
        assert!(
            auth.session_expiry(&session, now + SESSION_TTL + Duration::from_secs(1))
                .is_none()
        );

        let revocations = auth.subscribe_revocations();
        auth.revoke_session(&session);
        assert!(revocations.has_changed().expect("watch"));
        assert!(!auth.validate_session(&session, now));
    }

    #[test]
    fn repeated_failures_are_limited_per_client() {
        let dir = tempfile::tempdir().expect("tempdir");
        let auth = auth(dir.path());
        let now = Instant::now();
        let client = "192.0.2.10".parse().unwrap();
        for _ in 0..MAX_FAILURES {
            assert!(matches!(auth.login(client, "wrong", now), Login::Rejected));
        }
        assert!(matches!(
            auth.login(client, "wrong", now),
            Login::TooMany { .. }
        ));
        let other: IpAddr = "192.0.2.11".parse().unwrap();
        assert!(matches!(auth.login(other, "wrong", now), Login::Rejected));
        assert!(matches!(
            auth.login(client, "wrong", now + ATTEMPT_WINDOW),
            Login::Rejected
        ));
    }
}
