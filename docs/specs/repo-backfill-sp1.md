# Spec: back-fill of factory events and live matrices for the first run

visibility: public
audience: general

Naming answers (naming and visibility convention, questions 1 to 5):

Q1: Public: LOGBOOK edits in the public monorepo; no package is published.

Q2: General usage: anyone reading an extension's LOGBOOK for its provenance and live results.

Q3: Partly. The item name says what it does (back-fill) but carries a label that only the factory reads; acceptable for a docs-only item that is never a package name.

Q4: Not applicable (public and general).

Q5: Mostly. A stranger reads it as a documentation back-fill, which it is, and guesses nothing wrong beyond not knowing which run.

Status: to build. RFC 2119 keywords. Not clean-room (written from this repo's README, LOGBOOK and public docs).

## 1. Purpose

The first run published its versions before the factory recorded events in a uniform shape and
before the LOGBOOK carried a uniform live matrix. Reconstruct both from what exists (record
commits, lane branches, ledger files, receipt timestamps) so every published version has the same
provenance trail as the versions that follow.

## 2. Behaviour

- Factory events: one record per transition, written to the run's directory in the factory repo
  as `events.jsonl`, and copied into each extension's LOGBOOK under `## Factory events`.
- Live matrix: each extension's live results converted into the seven-column live matrix under
  `## Live test matrix` in its LOGBOOK, redacted (no hostnames, addresses or private names).
- The launchd-agent prior-art retirement is recorded in a LOGBOOK under its directory if one
  exists, else in the run's events only.
- Nothing inside a package changes: LOGBOOK-only commits per extension, no version bump, merged
  in one train.

## 3. Invariants

Redaction is checked by the repo's leak scan before the train merges. Timestamps come from the
sources named above, never estimated; where a transition has no source it is recorded as unknown.

## Next version scope: next

Docs-only item; no package is published.

- For every version published in the first run, back-fill the factory events
  (one record per transition, from the record commits, lane branches, ledger
  files and receipt timestamps) into that run's directory in the factory repo
  as `events.jsonl`, and copy them into each LOGBOOK under
  "## Factory events".
- Convert each extension's live results into the seven-column live matrix
  under "## Live test matrix" in its LOGBOOK, redacted.
- Record the launchd-agent prior-art retirement in a LOGBOOK under its
  directory if one exists, else in the run's events only.
- LOGBOOK-only commits per extension (no version bump: the LOGBOOK is outside
  the package), merged in one train.
