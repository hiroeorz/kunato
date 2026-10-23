# Behavioral detection deployment readiness

Complete this assessment before tuning behavioral thresholds or enabling
behavioral BLOCK. It establishes the identity and outcome semantics used by
the detector; it does not measure false positives or authorize deployment.
Copy the tables into deployment notes and fill them with observed evidence.
An unfilled item is pending, not a passing result.

## Deployment inventory

| Item | Required record | Evidence |
| --- | --- | --- |
| Request path | Every CDN, load balancer, Kunato listener, and upstream hop | Pending |
| Public entry points | Whether direct access to Kunato can bypass the proxy | Pending |
| Proxy identity contract | Actual proxy IPs/CIDRs; selected header; overwrite/append behavior | Pending |
| Source grouping | Shared NAT users and `aggregate_ipv6_prefix` (default `/64`) | Pending |
| Connection limits | Per-peer transport budget for the proxy and global connection cap | Pending |
| Exceptions | Exact monitoring/administrative source ranges and reasons | Pending |
| Observation path | How to correlate Kunato decision logs/metrics with upstream access logs | Pending |

For a direct deployment, leave `client_ip` out. For a proxy deployment, use the
[client identity configuration](development.md#client-identity-behind-trusted-proxies)
and list only actual proxies. A proxy must append its observed peer to XFF, or
overwrite the selected single-address header. Forwarded scheme and host are
not trusted by this feature. Confirm that untrusted direct-origin connections
cannot assert an arbitrary client identity.

Keep behavior in LOG while assessing readiness:

```yaml
protection:
  behavior:
    enabled: true
    enumeration: { action: LOG }
    auth: { action: LOG }
    global_auth: { enabled: true }
```

LOG applies only to behavioral actions: existing request/rule rate limits and
bans remain active. `protection.allowlist` exempts a source from those request
protections as well as behavioral observation; an ALLOW rule does not exempt it
from observation. Trusting a proxy is separate from allowlisting its clients.
Do not broadly allowlist clients just to suppress behavioral false positives.

## Authentication endpoint inventory

Record each login, token, session, MFA, and SSO endpoint separately, including
different virtual hosts sharing the same Kunato listener.

| Host / method / path | Success status | Wrong-credential status | Expected intermediate statuses | Observe? / reason |
| --- | --- | --- | --- | --- |
| Pending | Pending | Pending | Pending | Pending |

The current predicate is: the normalized/decoded path matches `auth.paths`
AND the upstream status is 401 or 403. There are no host, method, body,
account, or cookie conditions. Kunato-generated blocks/errors do not count.
`auth.paths` replaces the built-in path list and is shared by the per-source
and global authentication signals; an explicit empty list matches nothing.

| Application behavior | Assessment |
| --- | --- |
| Wrong password returns 401 on a dedicated login path | Supported; include the path |
| Successful login returns 200 or 302 | Does not count as a failure |
| Failed login also returns 200 or 302 | Unsupported; record the coverage gap |
| Normal MFA challenge returns 401 on the same path as invalid credentials | Ambiguous; exclude that path or disable authentication signals pending a separate classifier |
| An unrelated resource returns 403 for insufficient permissions | Keep the resource outside `auth.paths` |
| Hosts/methods on the same path require different interpretation | Unsupported distinction; use separate Kunato configurations or document the gap |

Do not count every 200/302 as a failure to make an unsupported endpoint visible.
If classification is ambiguous, keep enumeration available and disable both
authentication signals (`auth.enabled: false`, `global_auth.enabled: false`),
or configure an explicit list containing only unambiguous paths.

## Acceptance checks

Run checks in a controlled deployment against the actual proxy chain and
application. Repository tests verify the mechanisms; they do not certify a
production proxy or application configuration.

| Check | Required outcome |
| --- | --- |
| Untrusted direct peer sends a forged identity header | Identity stays at the direct peer IP |
| Proxy passes a client-supplied XFF prefix | The nearest untrusted hop wins, not the leftmost supplied IP |
| Two clients use the same trusted proxy/HTTP/2 connection | Their request budgets and behavior flags stay separate, subject to documented NAT/IPv6 grouping |
| A trusted peer omits or corrupts the selected header | 400 before body reads; ALLOW and disabled protection do not bypass it |
| A controlled client reaches a behavior BLOCK threshold | Only its identity is banned; another client through the proxy still works; expiry follows the configured ban duration |
| Genuine authentication failure on an included path | Failure count increases once, with source/global flags at the configured thresholds |
| Success, excluded-path failure, or local Kunato rejection | Authentication failure count does not increase |
| Trust settings are validly reloaded / invalidly reloaded | New policy applies / last known good policy remains |

Record timestamps, transport peer, resolved client IP, request path, upstream
status, relevant `kunato_behavior_*` counter deltas, and the expected result.
Do not retain credentials, cookies, or authentication request bodies as evidence.
Because the exported counters are process-wide, isolate the test traffic or
correlate it with decision/upstream logs rather than attributing all deltas to
one client on a busy instance.

## Exit criteria

- All inventory items have evidence or an explicit, applicable exclusion.
- Client identity cannot be overridden by an untrusted header, and source
  grouping matches the deployment's intended NAT/IPv6 boundaries.
- Each authentication endpoint is supported, excluded, or recorded as a gap;
  normal authentication transitions are not misclassified as credential errors.
- Proxy clients have independent request state, and the transport connection
  budgets can accommodate the proxy's connection model.
- Behavioral enumeration/auth actions remain LOG for the next tuning phase;
  controlled BLOCK checks are reverted after verification.

The outcome is either **Ready for LOG evaluation** or **Needs integration
changes**, with the unresolved items listed. False-positive measurement and
enabling production BLOCK belong to the next rollout phase.
