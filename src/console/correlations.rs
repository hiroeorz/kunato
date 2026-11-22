//! Compact selected decoy evidence; never an authoritative request counter.

use super::model::{DecoyContext, Disposition, EventRecord, SourceIdentity};
use super::{Error, Store};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

pub const MAX_CORRELATIONS: usize = 4096;
pub const MAX_CORRELATION_BYTES: usize = 4 * 1024 * 1024;
pub(super) const SCHEMA:&str="
CREATE TABLE decoy_correlations (
 source TEXT NOT NULL,generation TEXT NOT NULL,site TEXT NOT NULL,credential_id TEXT NOT NULL,
 first_seen INTEGER NOT NULL,payload TEXT NOT NULL,
 PRIMARY KEY(source,generation,site,credential_id)
) STRICT;
CREATE INDEX decoy_correlations_age ON decoy_correlations(first_seen,source,generation);
CREATE TABLE correlation_state (singleton INTEGER PRIMARY KEY CHECK(singleton=1),evictions INTEGER NOT NULL);
INSERT INTO correlation_state VALUES(1,0);
";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecoyCorrelation {
    pub source: SourceIdentity,
    pub site: Option<String>,
    pub credential_id: String,
    pub first_seen_ms: u64,
    pub issued_at_ms: Option<u64>,
    pub first_credential_ms: Option<u64>,
    pub last_credential_ms: Option<u64>,
    pub credential_evidence_count: u64,
    pub occurrence_evidence_count: u64,
    pub blocked_evidence_count: u64,
    pub issuance_clients: Vec<std::net::IpAddr>,
    pub reuse_clients: Vec<std::net::IpAddr>,
    pub transport_peers: Vec<std::net::IpAddr>,
    pub addresses_incomplete: bool,
    pub inspection_incomplete: bool,
    pub lure: Option<String>,
    pub template: Option<String>,
}

#[derive(Clone, Debug)]
pub struct CorrelationQuery {
    pub source: String,
    pub credential_id: Option<String>,
    /// Restrict the original first-seen time, not the most recent reuse time.
    pub from_ms: u64,
    pub until_ms: u64,
    pub limit: usize,
}
impl CorrelationQuery {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        super::model::identifier(&self.source, 128)?;
        super::model::timestamp(self.from_ms)?;
        super::model::timestamp(self.until_ms)?;
        if self.from_ms >= self.until_ms || self.limit == 0 || self.limit > 128 {
            return Err(Error::Invalid("invalid correlation query"));
        }
        if self
            .credential_id
            .as_ref()
            .is_some_and(|id| id.len() != 32 || !id.bytes().all(|ch| ch.is_ascii_hexdigit()))
        {
            return Err(Error::Invalid("invalid correlation credential ID"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct CorrelationPage {
    pub records: Vec<DecoyCorrelation>,
    pub expiry_ms: u64,
    pub evicted_records: u64,
    pub has_more: bool,
}

fn address(
    values: &mut Vec<std::net::IpAddr>,
    value: Option<std::net::IpAddr>,
    incomplete: &mut bool,
) {
    if let Some(value) = value
        && !values.contains(&value)
    {
        if values.len() < 4 {
            values.push(value);
        } else {
            *incomplete = true;
        }
    }
}

pub(super) fn record(
    connection: &Connection,
    source: &SourceIdentity,
    event: &EventRecord,
    expiry: u64,
) -> Result<(), Error> {
    let Some(evidence) = &event.decoy else {
        return Ok(());
    };
    if event.occurred_at_ms < expiry {
        return Ok(());
    }
    let id = evidence.credential_id.to_ascii_lowercase();
    let site = event.site.as_deref().unwrap_or("");
    let prior:Option<String>=connection.query_row("SELECT payload FROM decoy_correlations WHERE source=?1 AND generation=?2 AND site=?3 AND credential_id=?4",params![source.instance,source.generation,site,id],|row|row.get(0)).optional()?;
    let old_bytes = prior.as_ref().map_or(0, String::len);
    let mut value = match prior {
        Some(payload) => decode(&payload)?,
        None => DecoyCorrelation {
            source: source.clone(),
            site: event.site.clone(),
            credential_id: id.clone(),
            first_seen_ms: event.occurred_at_ms,
            issued_at_ms: None,
            first_credential_ms: None,
            last_credential_ms: None,
            credential_evidence_count: 0,
            occurrence_evidence_count: 0,
            blocked_evidence_count: 0,
            issuance_clients: vec![],
            reuse_clients: vec![],
            transport_peers: vec![],
            addresses_incomplete: false,
            inspection_incomplete: false,
            lure: None,
            template: None,
        },
    };
    value.first_seen_ms = value.first_seen_ms.min(event.occurred_at_ms);
    if value.first_seen_ms < expiry {
        return Ok(());
    }
    value.inspection_incomplete |= event.incomplete;
    match evidence.context {
        DecoyContext::Issued => {
            value.issued_at_ms = Some(
                value
                    .issued_at_ms
                    .map_or(event.occurred_at_ms, |at| at.min(event.occurred_at_ms)),
            );
            address(
                &mut value.issuance_clients,
                event.client,
                &mut value.addresses_incomplete,
            );
        }
        DecoyContext::Credential => {
            value.credential_evidence_count = value
                .credential_evidence_count
                .checked_add(1)
                .ok_or(Error::Invalid("correlation count overflow"))?;
            value.first_credential_ms = Some(
                value
                    .first_credential_ms
                    .map_or(event.occurred_at_ms, |at| at.min(event.occurred_at_ms)),
            );
            value.last_credential_ms = Some(
                value
                    .last_credential_ms
                    .map_or(event.occurred_at_ms, |at| at.max(event.occurred_at_ms)),
            );
            if event.disposition == Disposition::Block {
                value.blocked_evidence_count = value
                    .blocked_evidence_count
                    .checked_add(1)
                    .ok_or(Error::Invalid("correlation count overflow"))?;
            }
            address(
                &mut value.reuse_clients,
                event.client,
                &mut value.addresses_incomplete,
            );
        }
        DecoyContext::Occurrence => {
            value.occurrence_evidence_count = value
                .occurrence_evidence_count
                .checked_add(1)
                .ok_or(Error::Invalid("correlation count overflow"))?;
            address(
                &mut value.reuse_clients,
                event.client,
                &mut value.addresses_incomplete,
            );
        }
    }
    address(
        &mut value.transport_peers,
        event.peer,
        &mut value.addresses_incomplete,
    );
    if value.lure.is_none() {
        value.lure = evidence.lure.clone();
    }
    if value.template.is_none() {
        value.template = evidence.template.clone();
    }
    let payload =
        serde_json::to_string(&value).map_err(|_| Error::Invalid("correlation encoding failed"))?;
    if payload.len() > 4096 {
        return Err(Error::Invalid("correlation record exceeds byte limit"));
    }
    let (mut count, mut bytes): (i64, i64) = connection.query_row(
        "SELECT count(*),coalesce(sum(length(CAST(payload AS BLOB))),0) FROM decoy_correlations",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    count += i64::from(old_bytes == 0);
    bytes = bytes - old_bytes as i64 + payload.len() as i64;
    let victims: Vec<(i64, i64)> = {
        let mut statement=connection.prepare("SELECT rowid,length(CAST(payload AS BLOB)) FROM decoy_correlations WHERE NOT(source=?1 AND generation=?2 AND site=?3 AND credential_id=?4) ORDER BY first_seen,source,generation LIMIT 16")?;
        statement
            .query_map(
                params![source.instance, source.generation, site, id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?
            .collect::<Result<_, _>>()?
    };
    for (rowid, size) in victims {
        if count <= MAX_CORRELATIONS as i64 && bytes <= MAX_CORRELATION_BYTES as i64 {
            break;
        }
        connection.execute("DELETE FROM decoy_correlations WHERE rowid=?1", [rowid])?;
        connection.execute(
            "UPDATE correlation_state SET evictions=evictions+1 WHERE singleton=1",
            [],
        )?;
        count -= 1;
        bytes -= size;
    }
    if count > MAX_CORRELATIONS as i64 || bytes > MAX_CORRELATION_BYTES as i64 {
        connection.execute(
            "UPDATE correlation_state SET evictions=evictions+1 WHERE singleton=1",
            [],
        )?;
        return Ok(());
    }
    connection.execute("INSERT INTO decoy_correlations(source,generation,site,credential_id,first_seen,payload) VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(source,generation,site,credential_id) DO UPDATE SET first_seen=excluded.first_seen,payload=excluded.payload",params![source.instance,source.generation,site,id,value.first_seen_ms as i64,payload])?;
    Ok(())
}

impl Store {
    pub fn correlations(&mut self, query: &CorrelationQuery) -> Result<CorrelationPage, Error> {
        query.validate()?;
        self.guarded(|store|{
            super::storage::check_files(&store.config)?;
            let expiry=super::history_store::statistics_expiry(&store.connection,(store.config.clock)())?;
            let id=query.credential_id.as_ref().map(|id|id.to_ascii_lowercase());
            let raw:Vec<String>={let mut statement=store.connection.prepare("SELECT payload FROM decoy_correlations WHERE source=?1 AND first_seen>=?2 AND first_seen<?3 AND (?4 IS NULL OR credential_id=?4) ORDER BY first_seen,generation,site,credential_id LIMIT ?5")?;statement.query_map(params![query.source,query.from_ms.max(expiry) as i64,query.until_ms as i64,id,(query.limit+1) as i64],|row|row.get(0))?.collect::<Result<_,_>>()?};
            let has_more=raw.len()>query.limit;let records=raw.into_iter().take(query.limit).map(|payload|decode(&payload)).collect::<Result<_,_>>()?;
            let evicted_records=store.connection.query_row("SELECT evictions FROM correlation_state WHERE singleton=1",[],|row|row.get::<_,i64>(0))? as u64;
            Ok(CorrelationPage {records,expiry_ms:expiry,evicted_records,has_more})
        })
    }
}

fn decode(payload: &str) -> Result<DecoyCorrelation, Error> {
    if payload.len() > 4096 {
        return Err(Error::Invalid("oversized stored correlation"));
    }
    let value: DecoyCorrelation =
        serde_json::from_str(payload).map_err(|_| Error::Invalid("invalid stored correlation"))?;
    value.source.validate()?;
    if let Some(site) = &value.site {
        super::model::identifier(site, 64)?;
    }
    if let Some(lure) = &value.lure {
        super::model::redacted_path(lure)?;
    }
    if let Some(template) = &value.template {
        super::model::identifier(template, 64)?;
    }
    super::model::timestamp(value.first_seen_ms)?;
    for at in [
        value.issued_at_ms,
        value.first_credential_ms,
        value.last_credential_ms,
    ]
    .into_iter()
    .flatten()
    {
        super::model::timestamp(at)?;
        if at < value.first_seen_ms {
            return Err(Error::Invalid("invalid correlation ordering"));
        }
    }
    if value.credential_id.len() != 32
        || !value.credential_id.bytes().all(|ch| ch.is_ascii_hexdigit())
        || value.issuance_clients.len() > 4
        || value.reuse_clients.len() > 4
        || value.transport_peers.len() > 4
        || value.blocked_evidence_count > value.credential_evidence_count
        || value.first_credential_ms > value.last_credential_ms
    {
        return Err(Error::Invalid("invalid stored correlation bounds"));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::console::model::{DecoyEvidence, EventKind, Phase};

    #[test]
    fn correlation_capacity_evicts_old_evidence_with_an_explicit_counter() {
        let connection = Connection::open_in_memory().unwrap();
        connection.execute_batch(SCHEMA).unwrap();
        let source = SourceIdentity {
            instance: "source".into(),
            generation: "boot".into(),
        };
        let mut event = EventRecord {
            id: "issued".into(),
            sequence: 1,
            occurred_at_ms: 60_000,
            kind: EventKind::Decoy,
            disposition: Disposition::Log,
            phase: Phase::Request,
            site: None,
            client: None,
            peer: None,
            country: None,
            method: None,
            path: None,
            status: None,
            category: None,
            rule: None,
            attack_class: None,
            reason: None,
            decoy: Some(DecoyEvidence {
                credential_id: "00000000000000000000000000000000".into(),
                context: DecoyContext::Issued,
                issued_at_ms: None,
                age_seconds: None,
                lure: None,
                template: None,
            }),
            gap: None,
            incomplete: false,
        };
        record(&connection, &source, &event, 0).unwrap();
        let payload: String = connection
            .query_row("SELECT payload FROM decoy_correlations", [], |row| {
                row.get(0)
            })
            .unwrap();
        {
            let mut insert=connection.prepare("INSERT INTO decoy_correlations(source,generation,site,credential_id,first_seen,payload) VALUES('source','boot','',?1,60000,?2)").unwrap();
            for index in 1..MAX_CORRELATIONS {
                let mut value = decode(&payload).unwrap();
                value.credential_id = format!("{index:032x}");
                insert
                    .execute(params![
                        value.credential_id,
                        serde_json::to_string(&value).unwrap()
                    ])
                    .unwrap();
            }
        }
        event.occurred_at_ms = 120_000;
        event.decoy.as_mut().unwrap().credential_id = format!("{:032x}", MAX_CORRELATIONS);
        record(&connection, &source, &event, 0).unwrap();
        let (count, bytes): (i64, i64) = connection
            .query_row(
                "SELECT count(*),sum(length(CAST(payload AS BLOB))) FROM decoy_correlations",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(count, MAX_CORRELATIONS as i64);
        assert!(bytes <= MAX_CORRELATION_BYTES as i64);
        assert_eq!(
            connection
                .query_row("SELECT evictions FROM correlation_state", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
    }
}
