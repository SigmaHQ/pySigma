# Security Policy

## Supported versions

Security fixes go into the latest minor release line of pySigma. Older major versions are not patched.

| Version            | Supported |
| ------------------ | --------- |
| 1.x (latest minor) | ✅        |
| < 1.0              | ❌        |

## Reporting a vulnerability

**Please do not open a public issue, discussion or pull request for a security problem.**

Report it privately through GitHub: **Security → Advisories → "Report a vulnerability"** on this repository (<https://github.com/SigmaHQ/pySigma/security/advisories/new>).
If you cannot use GitHub, contact one of the maintainers listed in `pyproject.toml` privately.

Please include:

- the affected component (rule parser, modifier, processing pipeline, conversion base class, plugin loader, …) and the pySigma version or commit;
- a minimal Sigma rule, pipeline or API call that reproduces the problem, with the observed and expected output;
- the impact you see (see the scope below) and, if you have one, a proposed fix.

## What we treat as a vulnerability

pySigma turns Sigma rules and processing pipelines, which are often third-party or community content, into queries that run in a SIEM. The following are in scope:

- **Query or configuration injection:** rule content (values, field names, titles, metadata) that can change the *structure* of a generated query or of backend output formats (for example extra search commands, or altered saved-search or alert configuration). This covers pySigma itself and the base classes that backends inherit.
- **Code execution or file access:** loading rules, pipelines or plugins that leads to code execution, unsafe deserialisation, path traversal, or writes outside the intended location.
- **Denial of service:** a small crafted rule or pipeline that causes excessive CPU or memory use (for example YAML alias expansion, or pathological regex or wildcard expansion).
- **Plugin supply chain:** flaws in plugin discovery or installation that could install or load unintended code.

**Out of scope (report publicly as bugs):**

- Conversion errors that make a rule match more or fewer events than intended, without attacker-controlled input changing the query structure. These are important, but they are handled as normal issues and pull requests so fixes reach users quickly.
- A systemic and severe detection gap (for example a whole modifier class never matching) may be reported privately; the maintainers decide whether it becomes an advisory.

Report issues in backends or pipelines maintained in separate repositories to that repository. If the root cause is in pySigma, report it here.

## Our process

| Step                                                                        | Target                                           |
| --------------------------------------------------------------------------- | ------------------------------------------------ |
| Acknowledge the report                                                      | within 5 working days                            |
| Initial assessment and severity (CVSS 3.1)                                  | within 14 days                                   |
| Fix developed in the advisory's temporary private fork                      | as soon as practical, normally within 90 days    |
| Coordinated release, then GitHub Security Advisory published (CVE via GitHub) | at the fix release                             |

- We credit reporters in the advisory unless they ask not to be credited.
- When a fix changes the behaviour of dependent SigmaHQ projects (sigma-cli, backends, pipelines), we may coordinate their releases.
- We ask reporters to keep details private until the advisory is published or 90 days have passed, whichever comes first, unless agreed otherwise.
