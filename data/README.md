# Embedded IP data

Two DB-IP Lite databases and the IANA RDAP bootstrap registries are embedded
into release binaries. They are separate works from Kunato's source code and
are not covered by the MIT or Apache-2.0 licenses.

## Country database

`dbip-country-lite.mmdb.gz` is the DB-IP IP to Country Lite database for
November 2026 (release `2026-11`). It is embedded into release binaries and
expanded once at startup.

- Source: <https://download.db-ip.com/free/dbip-country-lite-2026-11.mmdb.gz>
- SHA-256: `75fe430010f6d38a8c4331c202bf0df6ce3221a6e6d823b9e5a6d951e4cf9758`
- Format: MaxMind DB 2.0 (MMDB), compressed with gzip
- License: [Creative Commons Attribution 4.0 International](https://creativecommons.org/licenses/by/4.0/)
- Attribution: "IP Geolocation by [DB-IP](https://db-ip.com/)"

## ASN database

`dbip-asn-lite-2026-11.mmdb.gz` is the DB-IP IP to ASN Lite database for
November 2026 (release `2026-11`). The console loads it lazily for source
detail; the WAF request path never reads it. An operator can set
`console.ip_info.asn_database` to a raw or gzip-compressed MMDB to override the
embedded copy for periodic updates.

- Source: <https://download.db-ip.com/free/dbip-asn-lite-2026-11.mmdb.gz>
- SHA-256: `36a8c45136877d8df48ad371de6c9c97c861dedd356277f30de730c16fc0f928`
- Format: MaxMind DB 2.0 (MMDB), compressed with gzip
- Database type: `DBIP-ASN-Lite (compat=GeoLite2-ASN)`
- License: [Creative Commons Attribution 4.0 International](https://creativecommons.org/licenses/by/4.0/)
- Attribution: "IP data by [DB-IP](https://db-ip.com/)"

The ASN record contains the autonomous system number and organization name. It
does not contain a registrant, allocation range, registration date, or abuse
contact; those require RDAP and are not part of this build. The DB-IP Lite
editions are subsets with reduced coverage and accuracy, and the organization
name can lag the current BGP holder.

Do not remove the DB-IP attribution from the monitoring console or the README
files when updating either database.

## RDAP bootstrap

`rdap-ipv4.json` and `rdap-ipv6.json` are snapshots of the IANA RDAP bootstrap
registries. The console uses them to select the authoritative HTTPS registry
for an address when `console.ip_info.rdap.enabled` is set. The files are
embedded in the binary; they are not request data.

- Source IPv4: <https://data.iana.org/rdap/ipv4.json>
- Source IPv6: <https://data.iana.org/rdap/ipv6.json>
- Publication dates: IPv4 `2019-06-07T19:00:02Z`, IPv6 `2024-11-01T22:00:01Z`
- SHA-256 IPv4: `f6ad30d1ebbd16fed6121e1eb54ae7db86edbf5e425345a040aa7893b0447d78`
- SHA-256 IPv6: `3292eb71787b903f7a6798ff31f7f2239fb61ce346be142a3719ffa26deaf080`
- Format: IANA RDAP bootstrap JSON
- Attribution: IANA RDAP bootstrap registry

RDAP responses are fetched on demand from the selected registry and cached in
memory only. The registries' terms and the redaction of registrant fields
apply; Kunato does not redistribute registry records.

## Updating

1. Download the required monthly release from DB-IP.
2. Verify the gzip stream and record its SHA-256.
3. Replace the file and update this file's release, source URL, and checksum.
   Replace the RDAP bootstrap JSON when IANA publishes a newer registry.
4. Rebuild and run the tests. Embedded databases are validated for MaxMind DB
   version, database type, IP version, node count, record size, build time, and
   IPv4/IPv6 sample lookups. Bootstrap files are parsed at console startup;
   their services must use HTTPS.

An external ASN database is loaded when the console starts. Replace the file
and restart `kunato console` to apply the update; there is no in-process file
watcher.
