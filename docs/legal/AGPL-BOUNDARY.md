# Security Phone AGPL process-boundary summary

Status: **Approved**

This file is an engineering summary for counsel and is not legal advice. The legal opinion and privileged analysis remain in counsel's records.

## Boundary

`security-phone-server` is a public AGPL-3.0-only fork of `signalapp/Signal-Server`, pinned initially to upstream commit `ccc22f9ac4799b8e5a89587f8ff4e5266e3682ef`. It runs as a separate process and deployable unit. Its modified Corresponding Source remains available in this public repository.

Proprietary Security 2.0 systems do not import, link, vendor or copy code from this fork. They may communicate with it only over the versioned protocol contracts in `contracts/`:

1. `registration.proto`
2. `identity.proto`
3. `policy.proto`
4. `audit.proto`
5. `abuse.proto`

The fork does not import private SAM OS, STN, HAM or Security Phone Cell packages. The `boundary-check` CI status rejects Java imports, Maven dependencies and protocol imports that cross that rule.

## Operational obligations

- Preserve upstream copyright notices, the AGPL-3.0 license and applicable SPDX identifiers.
- Publish source for every deployed fork modification and identify the exact deployed revision.
- Provide network users a clear route to the running version's Corresponding Source.
- Keep proprietary credentials, policies, models, data and services outside the fork.
- Review every proposed contract change for data minimization, compatibility and tier ownership.
- Do not merge this work order until counsel records approval and the Program Owner confirms the five-contract list.

## Counsel decision

Reviewer: **Counsel (name retained with privileged opinion)**

Decision: **Approved**

Date: **2026-10-17**
