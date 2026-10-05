# Security & Responsible Use

Gauntlet is an **offensive security tool**. It generates prompt-injection,
jailbreak, tool-misuse, and data-exfiltration attacks and fires them at
a target LLM application, looking for bypasses. That capability is
dangerous if pointed at a system you don't own or don't have explicit
permission to test.

## Scope restriction, enforced in code

Gauntlet refuses to attack a host unless it is:

- `localhost` / `127.0.0.1` / `::1` / `*.localhost`,
- a Docker Compose service name from this repo's own stack
  (`gullible-llm`, `agent-unprotected`, `agent-protected`, `aegis`,
  `postgres`, `redis`),
- or a private/loopback IP address (RFC 1918, link-local).

Any other host is rejected with a `DisallowedHostError`
(`gauntlet/targets/allowlist.py`) unless you explicitly pass
`--i-own-this-target` on the CLI, or set `i_own_this_target: true` in
your run config. That flag exists for legitimate use against your own
staging/production systems -- using it against a system you do not
own or do not have written authorization to test is a misuse of this
tool, and may be illegal in your jurisdiction (e.g. under
unauthorized-access laws).

## Reporting a vulnerability in Gauntlet itself

If you find a security issue in Gauntlet's own code (not in a target
you tested with it), please open a private security advisory on this
repository rather than a public issue, so any real-world impact can be
assessed before details are public.

## No real secrets, ever

The bundled demo services (`gullible-llm`, the demo agent) are entirely
synthetic: in-memory fake file system, in-memory fake outbox, no real
network calls, no real credentials. The "canary secret" planted in the
demo agent's fake file system (`CANARY-9f8a3b2c`) is a fixture for
testing the harm oracle, not a real credential. Do not reuse it.
