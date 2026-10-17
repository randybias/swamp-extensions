# Promotion criteria: beta to stable

visibility: public
audience: general

Naming answers (naming and visibility convention, questions 1 to 5):

Q1: Public: a policy document in the public monorepo; no package is published.

Q2: General usage: anyone who publishes or consumes versions from this repo.

Q3: Yes. The document name says exactly what it holds. Not a package name.

Q4: Not applicable (public and general).

Q5: Yes. A stranger reads it as the rule for promoting a release, which it is.

Status: to write in full; the criteria below are the contract. RFC 2119 keywords. Not clean-room (written from this repo's README, LOGBOOK and public docs).

## 1. Purpose

A version moves from `beta` to `stable` on the registry only by meeting a written test, applied
from the receipts, so that "stable" means the same thing for every extension in this repo.

## 2. Criteria

A published version is promoted beta -> stable only when all of the following hold:

1. Its receipts section for the exact published content hash shows a `pass` row for every public
   method and workflow: no `untested`, no `inconclusive`.
2. The published bytes equal the live-tested bytes (same content hash).
3. No open Critical or High finding, and no Medium in the security classes.
4. An upgrade row from the previous stable version, where one exists.

## 3. Procedure

Evaluate every published version against the criteria from its LOGBOOK receipts. Promote each
qualifying version with an explicit `--channel stable`, and record it in `release.yaml` with one
record commit per promotion. A version that fails any criterion stays on `beta`, with the failing
criterion named in the LOGBOOK.

## Next version scope: repo-promotions

Docs item plus registry promotions; no new package is published.

- Blocked on the `knot-dns`, `apt-cache` and `kubevirt` versions above being
  published (their earlier merge heads were never live-tested).
- Write this document in full (the criteria in section 2 are the contract).
- Evaluate every published version against it from the receipts, and promote
  the qualifying ones with an explicit `--channel stable`, one record commit
  each.
- Candidates to check first: `k8s-secret`, `kea-dhcp`, `syncthing-peer`,
  `secret-file`, `cherry-servers`. Explicit non-candidates: `azure-vm` and
  `azure-nsg` (never live), `cephadm` (cluster cells), `redfish` (emulator
  only), the `ssh-host` version tested against a container only.
