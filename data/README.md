# Embedded country database

`dbip-country-lite.mmdb.gz` is the DB-IP IP to Country Lite database for
November 2026 (release `2026-11`). It is embedded into release binaries and
expanded once at startup.

- Source: <https://download.db-ip.com/free/dbip-country-lite-2026-11.mmdb.gz>
- SHA-256: `75fe430010f6d38a8c4331c202bf0df6ce3221a6e6d823b9e5a6d951e4cf9758`
- Format: MaxMind DB 2.0 (MMDB), compressed with gzip
- License: [Creative Commons Attribution 4.0 International](https://creativecommons.org/licenses/by/4.0/)
- Attribution: "IP Geolocation by [DB-IP](https://db-ip.com/)"

The database is a separate work from Kunato's source code and is not covered by
the MIT or Apache-2.0 licenses. Do not remove the attribution from the
monitoring console or the README files when updating this file.

## Updating

1. Download the required monthly release from DB-IP.
2. Verify the gzip stream and record its SHA-256.
3. Replace `dbip-country-lite.mmdb.gz` and update this file's release,
   source URL, and checksum.
4. Rebuild and run the tests. The embedded database is validated for MaxMind DB
   version, database type, IP version, node count, record size, build time, and
   IPv4/IPv6 sample lookups.
