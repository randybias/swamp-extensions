# Spec: `release.yaml` formatting gate

visibility: public
audience: general

Naming answers (naming and visibility convention, questions 1 to 5):

Q1: Public: repo tooling in the public monorepo; no package is published.

Q2: General usage: anyone who runs this repo's gates or CI.

Q3: Yes. The item name says what it touches (`release.yaml`), what it does (formatting) and where (a gate). Not a package name, so the segment rules do not apply.

Q4: Not applicable (public and general).

Q5: Yes. A stranger reads it as a formatting check on the release file, which it is.

Status: to build. RFC 2119 keywords. Not clean-room (written from this repo's README, LOGBOOK and public docs).

## 1. Purpose

`release.yaml` is edited by lanes and by merge-prep, and a formatting drift there has no owner.
Format it with the house formatter and make gate 1 and CI refuse an unformatted file, so neither
a lane nor a merge-prep can leave it unformatted.

## 2. Behaviour

- Running the house formatter over `release.yaml` is idempotent and changes nothing but
  whitespace and key order within its rules; no stanza, value or comment is lost.
- Gate 1 (`scripts/gates.sh`) fails when `release.yaml` differs from its formatted form, and says
  so in one line with the fix command.
- CI runs the same check on every push and pull request.
- The gates test script carries a planted-failure test: an unformatted copy must fail the gate
  and the formatted copy must pass.

## 3. Deliverables

The formatted `release.yaml`, the gate-1 change, the CI step, the planted-failure test, and a
line in the repo's gate documentation. One commit on a short branch; merge-prep as usual, without
receipts, because nothing is published.

## Next version scope: next

Docs-and-scripts item; no package is published.

- Run the house formatter over `release.yaml`.
- Add the formatting check to gate 1 and to CI, so neither a lane nor a
  merge-prep can leave `release.yaml` unformatted.
- Add a planted-failure test to the gates test script.
- One commit on a short branch; merge-prep as usual, without receipts.
