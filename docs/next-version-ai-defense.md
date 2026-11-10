# Next-version concept: defending home servers against AI-assisted attacks

Date: 2026-11-09

Status: Proposal for the next version. The additions below are design ideas;
experimental items remain evaluation candidates, not release commitments.

## Product direction

Kunato should put the following objective at the center of its design:

> Do not let repeated AI-driven reconnaissance and experimentation create more
> opportunities for intrusion.

Home servers have an advantage: their purposes and administrators are often
limited. A policy such as "anyone can browse, but only specific people can
administer, update, or upload, and only at specific times" can be enforced more
thoroughly than in a general-purpose enterprise WAF. Building on that advantage
would give Kunato a distinctive direction.

Anthropic has reported an attack campaign that used AI for reconnaissance,
vulnerability testing, and credential collection. The behavior defenders should
address is the repeated cycle of interpreting a response and selecting the next
attack. However, an HTTP request alone usually cannot establish whether its
sender is using AI. See
[Anthropic's investigation](https://www.anthropic.com/news/disrupting-AI-espionage).

Kunato already has a foundation in behavioral detection, upload inspection,
response inspection, and daily rule updates. The following proposals build on
that foundation.

## 1. Open administrative functions only when needed

Priority: Highest.

Status: Implemented on `main` as the `admin_access` configuration and the
`kunato admin-access status|open|close` commands. The gate has a configurable
default state (`open` by default, or `close` for fail-closed operation) and
time-limited overrides that can target every function, one client, or one
function; the most recent matching command wins and expires automatically.
Enabling it loads built-in presets for WordPress, Rails, Laravel, generic
`/admin` panels, phpMyAdmin, Adminer, Tomcat/JBoss consoles, Solr, Spring
Actuator, Nextcloud, Ghost, and TYPO3 in addition to owner-defined functions.
Open requests still pass the normal rule and inspection pipeline. See
[Administrative access](development.md#administrative-access).

Keep blog browsing publicly available at all times, while allowing access to
administrative pages, plugin installation, file updates, and similar functions
only when the owner authorizes it.

For example, the owner could use an administrative channel such as SSH to
authorize a particular device to use administrative functions for ten minutes.
Kunato would apply a time-limited open/close override limited to those
functions and that period. The override would expire automatically and return
to the configured default. Kunato would apply the effective state before
forwarding the request to the application; knowing a hidden URL would not be
sufficient.

The value is keeping an administrative entry point unreachable for long periods,
even if an attacker discovers an unknown vulnerability behind it. Requests in the open
state would still undergo normal WAF inspection.

Many home servers have exactly one administrator. That makes this approach a
promising way to combine effective protection with a usable workflow.

## 2. Remember an attacker's trial and error

Status: Implemented on `main` as `protection.behavior.sequence`. Evidence from
upstream outcomes and from the requests Kunato rejects itself (rule blocks,
structural rejections, the administrative gate, and rate-limit bans) is weighted
and decays; the action requires activity in at least two short windows plus two
evidence kinds, so a single burst cannot reach it. A retry of a known target with
a different encoding earns extra weight. See the continuity section in
[behavioral detection](behavioral-detection.md#47-cross-request-continuity).

Extend behavioral detection to recognize an attack's progression across
multiple requests.

For example, a sequence might begin with configuration-file discovery, continue
with differently encoded retries, switch to another attack category, and then
attempt an upload. Even with a low request rate, repeated variations pursuing
the same objective could increase the level of suspicion.

Current behavioral detection primarily observes upstream responses. Requests
that Kunato itself blocks are outside that observation. Adding rule matches,
structural inspection rejections, and variations that suggest evasion attempts
would build directly on the existing mechanism. See the
[current behavioral detection design](behavioral-detection.md#3-requirements).

The implementation would need short and long observation windows, suspicion
that decays over time, and a hard limit on retained state. An IP address alone
must not establish that requests belong to the same person, because legitimate
users may share an address. Start with observation, then restrict enforcement
to specific functions and limited periods to reduce collateral blocking.

## 3. Define a small set of operations the application actually needs

Provide PHP and CMS profiles that let owners declare the functions they use.

Examples include:

- Uploads are accepted only at this URL.
- This API's ID parameter must be an integer.
- This form contains only these fields.
- Upload progress is not used.

Reject inputs outside those declarations before they reach the application.
Even when an AI changes an attack string, the constraint that the application
does not permit an unnecessary operation still applies. This would make
Kunato's existing form limits and PHP settings easier to use for particular
deployment purposes.

Access logs or an OpenAPI description could help generate candidate settings.
However, automatically treating observed traffic as legitimate would allow
attacks to become part of the learned policy. Candidate settings therefore need
review and benign-traffic tests before application. This mechanism cannot
replace authorization decisions inside the application.

## 4. Use decoys to obtain evidence of attack progression

Status: First release implemented; experimental, enabled in starter configurations,
and not yet released. See the
[experimental decoy design](decoy-design.md) for the configuration,
token protocol, routing order, resource bounds, and acceptance tests.

The first release is scoped to fictional credentials for an HTTP API served
entirely by Kunato. Starter configurations select `BLOCK`, which affects only a
qualified credential presentation on that owned API. Arbitrary token
occurrences never trigger a decoy source ban or continuity score. A returned
token links related data, not necessarily the same person, and use outside
Kunato's HTTP request path is not observable.

`allowed_hosts` remains optional. Each site's explicit public origin scopes
the local routes; a configured Host allowlist must also accept that origin.
Existing configurations without `decoys` remain disabled, and an omitted
`on_reuse` action still selects `LOG`.

Respond to suspicious reconnaissance with fake configuration files or
administrative APIs that exist entirely inside Kunato.

The interesting part is observing whether information obtained from a decoy is
used in a subsequent action. For example, a fake configuration file could
contain an invalid token unique to that response. If the token appears in a
later request, it provides evidence that the visitor progressed from retrieving
information to trying to use it. It could also help connect related attempts
when their source IP addresses change.

A more experimental variation would return a simulated success response that
leads to an administrative interface containing only dummy data. The experiment
would measure whether the attacker continues investigating that environment.
This is worth evaluating against agents that interpret responses and choose
their next actions accordingly.

Cloudflare's AI Labyrinth provides a precedent for directing misbehaving
crawlers into generated pages. Its purpose is crawler mitigation; effectiveness
against intrusion attempts would need separate validation. See
[Cloudflare's description](https://blog.cloudflare.com/ai-labyrinth/).

For a home server, the design should impose fixed bounds on page count, response
volume, and processing time. Decoys must not use real credentials or connect to
the real upstream application. Keeping attackers waiting for a long time also
consumes the defender's connection capacity, so such techniques need careful
evaluation.

## 5. Put a static counterpart of the public site in front of the application

Status: A substantial option for suitable workloads.

For a personal blog or portfolio, Kunato could normally serve generated public
pages and allow access to the PHP application only while the owner is editing.

When the administrator writes and publishes an article, the public snapshot
would be updated. Visitor requests would be handled entirely from that
snapshot.

Through this path, even tens of thousands of input variations would never reach
PHP. Reducing the amount of application code executed during public access
reduces opportunities to trigger unknown vulnerabilities.

This is unsuitable for membership functions or dynamic APIs, but it could be
applied only to the static portion of a site. Publication must be explicit and
must exclude authenticated pages and personal information. The proposal would
expand Kunato's responsibilities somewhat, but it could be a useful distinction
for a home-server product.

## 6. Use AI to keep improving the defenses

Use AI in the maintenance workflow to produce candidate defenses from attack
logs and public information.

The workflow would form hypotheses from events with sensitive information
removed, reproduce the suspected attack in an isolated environment, generate
both blocking rules and benign-traffic tests, and distribute changes that pass
validation. This could connect to Kunato's daily updates and existing test
infrastructure.

Preserving legitimate traffic must carry as much weight as stopping attacks.
Attackers can write strings that appear in logs, so those strings must be
treated as data rather than instructions to the AI. The system must also
prevent the AI from freely executing commands or changing configuration.

Keeping this work in the development and update workflow would preserve the
lightweight deployment model. Users' servers would not need an LLM or a required
external AI service.

## 7. Test against real attack agents and use the results as product evidence

Priority: As important as the defensive features.

The existing `agentic` suite uses deterministic scenarios that model progression
from reconnaissance to exploitation. It does not run an actual LLM. See the
[existing lab description](security-lab-testing-model.md#agentic-ttp-chain).

Add an AI agent that observes responses and selects its next attempt. Compare
runs with and without Kunato against isolated targets, using fixed time,
request, and compute budgets.

Evaluate actual evidence of secret retrieval, file modification, or code
execution. An attack agent's claim that it succeeded, or a count of HTTP 403
responses, is insufficient. At the same time, measure the success rate of normal
browsing, login, and upload operations, together with Kunato's resource usage.

Publishing evidence that a particular adaptive attack was prevented under
specified conditions while legitimate operations remained available would make
the product concept credible.

## Further experimental ideas

| Idea | Objective and limits |
| --- | --- |
| Reverse prompt injection against an attack agent | Include fictional diagnostic instructions in a decoy response and measure whether the agent follows that path. Results depend heavily on the model and agent implementation, so treat this as an experimental disruption technique. |
| Computational challenges for suspicious operations | Increase the cost of repeated attempts. Solving a challenge does not prove that a visitor is human, and challenges also burden low-powered devices, so limit both their scope and cost. |

## PHP protection boundaries and temporary closure

The product should make the boundaries of PHP protection explicit. For the
critical PHP vulnerabilities disclosed in October 2026, CISA described WAF
protection as limited and called for updates. Kunato likewise cannot claim to
prevent all memory corruption inside PHP. A mechanism that temporarily closes
specified dangerous functions until an update can be applied has practical
value. See
[CISA's advisory](https://content.govdelivery.com/accounts/USDHSCISA/bulletins/42ff5ac).

## Recommended implementation order

1. Open administrative functions only when needed (implemented as `admin_access`).
2. Detect continuity across an attacker's attempts (implemented as
   `behavior.sequence`).
3. Validate the defenses against real AI agents.

Evaluate decoys in parallel as an experimental feature. Treat static public
snapshots as a further option for blog deployments.

## Proposed product message

> **Protect your home server from AI-powered attacks.**
>
> Detect suspicious reconnaissance, close unnecessary entry points, and update
> your defenses every day.
