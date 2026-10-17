# 07: RGW users (admin plane) and buckets (S3 plane)

Part of the `@randybias/cephadm` behaviour specification. Read
`00-overview.md` first; its decisions win over this file.

This file specifies six methods:

| Method | Class | Plane |
|---|---|---|
| `cephRgwUserEnsure` | M | admin (secret delivery per D50, see §1.3) |
| `cephRgwBucketInventory` | RO | admin |
| `cephRgwBucketInspect` | RO | S3 |
| `cephRgwBucketEnsure` | M | S3 (also writes and deletes temporary probe objects) |
| `cephRgwBucketPolicyEnsure` | M | S3 |
| `cephRgwBucketVersioningEnsure` | M | S3 |

Every error thrown by these methods starts with `cephadm[<phase>]:` followed by
non-secret `key=value` pairs (overview §4). The phases used here are listed in
§1.10.

---

## 1. Cross-cutting rules for this group

### 1.1 Two access planes

The group uses two planes on purpose. Each method uses exactly the plane
assigned to it above.

**Admin plane** (`cephRgwUserEnsure`, `cephRgwBucketInventory`):

- The method SSHes to an admin host and runs `radosgw-admin` inside
  `cephadm shell`, using the shared cephadm-shell script execution of
  01-transport: a fresh `mktemp -d` directory with mode 0700 (D7), the script
  mounted into the container and run under `set -euo pipefail` and sudo, and
  the directory removed afterwards, best effort, with a warning on failure.
- The cephadm-shell minimum budget of 5 minutes applies to every call (D37).
- An SSH exit of 255, a connection-level failure or a timeout surfaces as a
  typed transport error, even where the method allows non-zero exits (D8).
- `radosgw-admin` is a separate binary, not a `ceph` subcommand. No command
  MAY start with `ceph radosgw-admin` or any other `ceph ` prefix.
  - Why: a doubled prefix can ship unnoticed when tests check only parsed
    output; tests MUST therefore assert the exact command text.
- Both admin-plane methods are in the `ssh-installed` pre-flight check's
  applies-to list (overview §2). The four S3-plane methods are not.

**S3 plane** (`cephRgwBucketInspect`, `cephRgwBucketEnsure`,
`cephRgwBucketPolicyEnsure`, `cephRgwBucketVersioningEnsure`):

- No SSH and no admin keyring. Every signed request is signed with AWS
  Signature Version 4 using the **bucket owner's** S3 key pair: service `s3`,
  region = the `region` argument (the zonegroup api name).
- `x-amz-content-sha256` carries the hex SHA-256 of the request body (the
  empty-body hash for bodiless requests).
- Addressing is path-style: `<origin>/<bucket>[?<subresource>]`.
- Requests go through the injectable HTTP fetch dependency (overview §2), with
  a fresh connection per request and no keep-alive reuse.
- An **unsigned** request carries no `Authorization` header and no SigV4
  `x-amz-*` authentication headers.
- Why the owner's key and not an admin path: no `radosgw-admin` subcommand can
  create a bucket, set its policy or set its versioning (the `bucket`
  subcommands are list, stats, link, unlink, chown, rm, check, rewrite,
  radoslist, reshard and sync). Only the owner can do these through the S3
  API, and the owner's key is also the least-privileged credential that works.

**What each plane cannot see:**

- The S3 plane cannot read a bucket's **placement target**. GetBucketLocation
  returns only the zonegroup.
- Placement is fixed when a bucket is created and cannot change. A bucket
  created without the `<zonegroup>:<placement-id>` LocationConstraint lands on
  the default placement and escapes the pool quota the caller intended.
- `cephRgwBucketEnsure` sends the constraint but cannot verify it. The admin
  plane (`cephRgwBucketInventory`) reports `placementRule`. Comparing the two is
  a **workflow** concern; `cephRgwBucketEnsure` MUST NOT attempt it (D54). A
  pre-existing bucket on the wrong placement therefore passes the S3-plane
  methods, by design.

### 1.2 Secret-redaction contract

This contract applies to every method in this file. It never weakens; where
another rule appears to conflict, this one wins.

**Origin of secrets.**

- RGW credentials are always caller-supplied, from a vault reference at the
  workflow call site. A method MUST NOT generate a credential, and MUST NOT
  leave on a user it created any key the caller did not supply.
  - Why: a generated secret exists only in the cluster and in output nobody is
    allowed to keep, so it can never be recovered.
- `accessKey` and `secretKey` are marked `sensitive` in schema metadata on
  every method that accepts them (D48). This includes `cephRgwUserEnsure` and
  all four S3-plane methods.

**Where a secret MUST NOT appear:**

- a resource record;
- a log line;
- an error message or error detail (including chained causes);
- a test fixture (fixtures use obviously synthetic values);
- any command line, on the control machine, on the admin host or inside the
  container (D50; see §1.3).

**Field names.** Result schemas MUST declare every field they write and MUST
NOT declare a secret, nor any field whose name is `secret_key`, `secret`,
`secretKey` or similar (D49). Records and the method's own log lines MUST NOT
contain the string `secret_key` at all.

**Parsed views.** `radosgw-admin user info` / `user create` output, and the
equivalent Admin Ops responses, contain `keys[].secret_key`. The parsed user
view MUST omit the secret entirely: a key entry is modelled as user and
access key only, so the secret cannot be carried around by accident.

**The redactor.** All raw output that becomes error text or log text MUST pass
through one redactor first. The redactor:

1. replaces the value of every JSON `"secret_key"` or `"secret"` field with
   `<redacted>`, keeping the field name so that the result is still valid
   JSON;
2. replaces the value after `--secret=`, `--secret <v>`, `--secret-key=` and
   `--secret-key <v>`, quoted or bare, keeping the flag (defence in depth: no
   command should carry these, per D50);
3. replaces every literal occurrence of the caller-supplied `secretKey` value
   (and, on the Admin Ops path, the admin secret) with `<redacted>`;
4. leaves the **access key** alone, because it is a public identifier;
5. returns text that contains no secret byte-for-byte unchanged;
6. runs **before** any truncation.
   - Why: truncating first can cut a value in half so that no rule matches the
     surviving piece.

**Transport errors are redacted too.** The SSH layer builds its failure
message from raw stdout and stderr and has no redactor of its own. Every
`radosgw-admin` invocation, and every Admin Ops request, MUST go through a
wrapper that catches the transport error, redacts its message, and rethrows. The
rethrown error keeps the exit code and the command name, and chains the
original as its cause only after the cause's message has also been redacted.

- Why: a mutating call that fails unexpectedly (container crash, OOM) can print
  the JSON that holds the secret, and that path belongs to the transport, so a
  method-level leak review easily misses it.

**S3 plane specifics.**

- The secret is used only to compute signatures.
- Request headers (which carry the signature) are never copied into a record,
  a log line or an error.
- A credential-validation error reports the argument name and the length,
  never the value.

### 1.3 Admin-plane secret delivery (D50)

The admin-plane secret MUST NOT appear on any command line: not in the SSH
argv on the control machine, not in a remote shell command line, not in the
`cephadm shell` argv, and not in the `radosgw-admin` argv inside the container.
It also MUST NOT appear in the text of the generated remote script.

Two paths are allowed. A build implements exactly one of them.

**Path A: `radosgw-admin` reads the secret from a file or stdin.**

- The secret travels from the control machine to the admin host over the SSH
  process's **stdin**, separately from the script text.
- On the admin host it reaches `radosgw-admin` only through stdin or through a
  file with mode 0600 inside the run's mode-0700 temp directory (D7), mounted
  into the container for that call only. The file is removed with the
  directory; a removal failure is a warning that names the directory, never
  the contents.
- Only the secret-bearing operations (user create with a key, key create) use
  this delivery. All other operations are plain `radosgw-admin` calls.
- The exact `radosgw-admin` option or subcommand that consumes the secret from
  the file or stdin is the one confirmed on the twin for the pinned Squid
  release.

**Path B: RGW Admin Ops API over HTTPS.**

- Used only if the pinned `radosgw-admin` cannot read the secret from a file
  or stdin.
- Only the secret-bearing operations go over Admin Ops:
  - create user with the requested key: `PUT /admin/user` with `uid`,
    `display-name`, optional `email`, `access-key`, `secret-key`,
    `key-type=s3`, and `generate-key=false`;
  - add the requested key to an existing user: `PUT /admin/user?key` with
    `uid`, `access-key`, `secret-key`, `key-type=s3`, `generate-key=false`.
- Reads (`user info`) and non-secret modifies (display name, email) stay on
  `radosgw-admin` over SSH. So absence classification is the same on both
  paths, and the method stays an SSH method for the pre-flight check.
- Each request is SigV4-signed (service `s3`) with an admin credential that
  holds the `users=write` capability. That credential is caller-supplied from
  the vault, sensitive, and covered by §1.2 exactly like `secretKey`.
- The endpoint follows the same origin rules as the S3 `endpoint` argument
  (§1.6): https only, origin only.
- The extension MUST NOT put any request URL into a record, log or error,
  because the Admin Ops query carries the secret.
- Each response is classified as answered, refused or unreachable (§1.7). Only
  a 2xx answer counts as success, and every write is confirmed by the
  `radosgw-admin user info` re-read, never by the status code alone.

**Selection rule.**

1. The path is fixed per release by the twin confirmation of D50 for the pinned
   Squid point release. It is not chosen at run time.
2. If Path A works on the pinned release, the build MUST use Path A (it needs
   no extra credential). Otherwise it MUST use Path B.
3. A build MUST NOT probe for a path at run time, MUST NOT fall back from one
   path to the other, and MUST NOT under any circumstances fall back to
   passing the secret as a command-line argument.
4. The README states which path the release uses. The record field
   `secretDelivery` (§2) names it on every run.

### 1.4 Effect, not acceptance

- Every write is followed by a re-read, and the re-read MUST show the
  requested state. A write's status code or exit code is never proof.
- Every claim about access comes from a request that was actually made:
  - "Anonymous refused" means an unsigned request was answered 403.
  - That 403 counts only after a **control** succeeded first: the same request,
    signed by the owner, answered 200.
  - Why: without the control, a refusal could just mean the endpoint is broken.

### 1.5 Validation inside execute

The schema is only the first gate; tests and direct callers can call the
method with raw arguments. Every method MUST re-check every injection-relevant
and credential value when it runs, before any command or request is sent
(compare D20). When validation fails, the method MUST make **zero** transport
calls (no SSH spawn, no fetch) and write no record.

### 1.6 Common S3 arguments (all four S3-plane methods)

| name | type | required | default | constraints | meaning |
|---|---|---|---|---|---|
| `endpoint` | string | yes | – | MUST parse as a URL with scheme `https`. Origin only: path empty or `/`, no query, no fragment, no userinfo. | RGW S3 endpoint. The bucket is appended path-style. |
| `region` | string | yes | – | 1–64 characters of letters, digits, `.`, `_`, `-`; first character a letter or digit | Zonegroup api name. The SigV4 region and the first half of the LocationConstraint. |
| `bucket` | string | yes | – | S3 naming rules (below). Also the URL-path injection boundary. | Bucket name |
| `accessKey` | string | yes | – | **sensitive** (D48). 1–512 characters, each a visible ASCII character (0x21–0x7E): any printable non-space character (D53) | Owner's S3 access key id, from the vault |
| `secretKey` | string | yes | – | **sensitive** (D48). Same grammar as `accessKey` | Owner's S3 secret, from the vault; used only to sign |
| `requestTimeoutMs` | integer | yes | – | 1000–300000 | Timeout per request |

- **Endpoint examples.** Accept `https://203.0.113.10`,
  `https://s3.example.test:8443`, `https://s3.example.test/`. Reject
  `http://s3.example.test`, `https://s3.example.test/prefix`,
  `https://s3.example.test/?x=1`, `https://user:pw@s3.example.test`,
  `not a url`.
- **Bucket name grammar.** 3–63 characters drawn from lowercase letters,
  digits, `.` and `-`. The first and last characters are a letter or digit. No
  `..` anywhere. Not shaped like an IPv4 dotted quad. Accept `a.b-c`,
  `data-01`. Reject `Upper-Case`, `a..b`, `192.0.2.1`, `ab`, `a/b`, `-leading`,
  `trailing-`, `has space`, `q?x`.
- **Credential grammar.** Accept `AKIAEXAMPLE`, `ab+/cd=`. Reject the empty
  string, any value containing a space, tab, newline or other control
  character, and any non-ASCII character.
  - Why: the access key goes into an HTTP header and a signature string, where
    whitespace, control characters and non-ASCII text are either injection
    vectors or signing errors; otherwise the charset stays permissive (D53).
- `requestTimeoutMs` is required because how long a gateway may take is a
  deployment fact that the caller owns.

### 1.7 S3 transport outcome classes

Every request ends in exactly one of three outcomes:

- **answered**: a status, the body, and the `x-amz-version-id` header if
  present.
- **refused**: connection refused (ECONNREFUSED, errno 111, or a connection
  reset before any response). This is the **only** transport failure that
  counts as evidence: nothing is listening at that address.
- **unreachable**: timeout, DNS failure, TLS failure, anything else. This
  proves nothing about the far side. The transport detail is redacted, then
  truncated to a few hundred characters.

Each request has its own abort timeout of `requestTimeoutMs`. Where the only
possible failure is "no answer", the method throws a phase-tagged error saying
the endpoint was not reached; the error claims nothing about the bucket.

**XML.** S3 XML bodies MUST be parsed with a real, pinned XML parser that
handles namespaces (default and prefixed) and entity decoding (D53). Elements
are matched by local name within the S3 2006-03-01 namespace (or no
namespace). An S3 error code is read from `Error` → `Code` only when the body
is an S3 Error document; otherwise the code is empty (HEAD answers have no
body).

### 1.8 Bucket presence classification

All S3-plane methods share one classifier. A signed `HEAD <origin>/<bucket>`
decides the class:

| HEAD answer | Class |
|---|---|
| 200 | **owned** |
| 404 | **absent**. This is the **only** answer that permits a create. |
| 301 or 307 | **wrong-zonegroup**: the bucket lives in another zonegroup |
| 403 | tie-break with a signed ListBuckets (`GET <origin>/`): 200 → **foreign** (exists, belongs to someone else); 403 → **credentials-rejected**, carrying the S3 error code; anything else → **unreadable** |
| any other status, or refused / unreachable | **unreadable** |

How the mutating methods treat each class:

- owned: proceed.
- absent: `cephRgwBucketEnsure` creates; policy and versioning refuse with a
  hint to run `cephRgwBucketEnsure` first. Nothing is created.
- foreign: refuse, stating that nothing was created or changed.
- credentials-rejected: refuse, and point at the vault keys or a missing RGW
  user.
- wrong-zonegroup: refuse.
- unreadable: refuse; never create on a guess.

### 1.9 Public Access Block (PAB)

Facts measured on a Squid 19.2.x RGW, which the methods are built around:

- A bucket **policy alone does not stop object leaks.** An object-owning user
  could PutObjectAcl `public-read`, and an anonymous GET then served the
  object. Only all four PAB flags closed the leak.
- With BlockPublicPolicy on, **every** PutBucketPolicy fails 403, even when the
  owner re-puts an identical document.
- PutObject with an `x-amz-grant-read` AllUsers header is **stored** (200) even
  under BlockPublicAcls. Only IgnorePublicAcls keeps it unreadable.
- After a denied small-body PUT on a reused keep-alive connection, an RGW
  build answered the **next** request with a spurious 405. Fresh connections
  are mandatory (overview §2), and a 405 MUST never be read as a refusal.
- SigV4 PutPublicAccessBlock requires a `Content-MD5` header: base64 of the
  MD5 of the body.

Rules:

- **Reading** (`GET ?publicAccessBlock`):
  - 404 with code `NoSuchPublicAccessBlockConfiguration` → none configured
    (null).
  - 200 → a `PublicAccessBlockConfiguration` document with
    `BlockPublicAcls`, `IgnorePublicAcls`, `BlockPublicPolicy`,
    `RestrictPublicBuckets`. A missing flag element reads as false. Any value
    other than `true` or `false` throws.
  - anything else throws.
- **Full** means all four flags are true. Null is not full.
- **Writing** (`PUT ?publicAccessBlock`, with `Content-MD5`) is always
  verified: write, read back, and require exact equality on all four flags.

### 1.10 Error phases

| Phase | Meaning |
|---|---|
| `validate` | An argument failed validation. Zero transport calls. |
| `public-allow` | Policy document grants public access. Zero transport calls. |
| `read` | A read failed, or presence was unreadable |
| `absent` | Bucket does not exist (policy, versioning) |
| `foreign` | Bucket exists and belongs to another user |
| `credentials` | Gateway rejected the owner's credentials |
| `zonegroup` | Bucket lives in another zonegroup |
| `placement` | CreateBucket answered `InvalidLocationConstraint` |
| `create`, `create-verify` | CreateBucket refused, or bucket not owned afterwards |
| `acl-set`, `acl-verify` | ACL write not accepted, or not private on re-read |
| `pab-set`, `pab-lift`, `pab-restore` | PAB write, lift or restore not accepted, or read-back mismatch |
| `control` | Owner's signed list was not answered 200 |
| `anonymous-allowed`, `anonymous-inconclusive` | Unsigned list served, or neither served nor 403 |
| `object-leak-probe` | The object-leak probe **could not run**; no leak verdict (D51) |
| `object-leak` | The probe **detected** a leak (D51) |
| `object-leak-inconclusive` | The probe ran but its anonymous answers prove nothing |
| `object-leak-cleanup` | Probe objects could not be deleted |
| `self-lockout` | Policy would deny the owner its own policy management |
| `policy-write`, `versioning-write` | Policy or versioning write not accepted |
| `verify` | A write was accepted but the re-read differs from the request |
| `secure-transport-ignored`, `plain-http-inconclusive` | Plain-HTTP probe outcomes |
| `user-create`, `user-modify`, `key-create` | Admin-plane user writes |
| `list`, `stats`, `parse` | Admin-plane inventory reads |

### 1.11 Resource records

- Every method writes exactly one record on success, under a **stable,
  non-timestamped** instance key.
  - Why: a workflow reads the record with `data.latest(model, exactName)` and
    cannot construct a timestamp.
- Freshness is shown by `capturedAt`, an ISO-8601 timestamp from the injectable
  clock.
- Every resource spec has lifetime `infinite` and keeps 10 versions
  (overview §4).
- Every schema is strict and declares every field the method writes (D49).
- A failing method writes **no** record. A success record is never written for
  a bucket that is public, leaking, or has its PAB lifted.

| Method | Resource spec | Instance key |
|---|---|---|
| cephRgwUserEnsure | `cephRgwUserResult` | `rgwUser-<uid>` |
| cephRgwBucketInventory | `cephRgwBucketInventoryResult` | `rgwBucketInventory-<host>`, or `rgwBucketInventory-<host>-<realm>` when a realm is given |
| cephRgwBucketInspect | `cephRgwBucketInspectResult` | `rgwBucketInspect-<region>-<bucket>` |
| cephRgwBucketEnsure | `cephRgwBucketResult` | `rgwBucket-<region>-<bucket>` |
| cephRgwBucketPolicyEnsure | `cephRgwBucketPolicyResult` | `rgwBucketPolicy-<region>-<bucket>` |
| cephRgwBucketVersioningEnsure | `cephRgwBucketVersioningResult` | `rgwBucketVersioning-<region>-<bucket>` |

- S3 keys include the zonegroup because a bucket name is unique per
  zonegroup, not per cluster.
- The inventory key includes the realm because one admin host can read every
  realm; without it, one realm's record would overwrite another's.

### 1.12 Probe objects (D51)

- Probe objects live under the fixed prefix `.cephadm-pab-probe/`. The prefix
  is not configurable.
- Key stem = prefix + epoch milliseconds from the injectable clock. The two
  keys are `<stem>-canned` and `<stem>-grant`, for example
  `.cephadm-pab-probe/1760400000000-canned`.
- The probe body is a short text stating that the object is safe to delete.
- Why: one hidden, dedicated prefix is easy to exclude from listings and easy
  to sweep if a leftover survives.
- "The probe could not run" (`object-leak-probe`) and "a leak was detected"
  (`object-leak`) are distinct error kinds with distinct phases and messages
  (D51).

---

## 2. Method: cephRgwUserEnsure

- **Safety class:** M (idempotent converge). Handles secrets.
- **Purpose:** Ensure that an RGW user exists with the requested display name,
  optional email, and the requested S3 access key, converging rather than
  create-only. An RGW user is a different object from a cephx
  `client.<name>` entity; they live in separate databases, and creating one
  does not create the other.

**Inputs**

| name | type | required | default | constraints | meaning |
|---|---|---|---|---|---|
| `host` | string | yes | – | hostname or IPv4 grammar (01-transport) | Admin host |
| `sshUser`, `port`, `keyPath`, `privateKey`, `strictHostKeyChecking` | shared | `sshUser` yes | overview §3 | overview §3 (`privateKey` sensitive; nullish) | SSH connection |
| `uid` | string | yes | – | Ceph identifier: letters, digits, `.`, `-`, `_`; at most 128 characters; first character a letter or digit. Accept `app-user.01`; reject `a b`, `x;rm`, `-x`, `a'b`. | RGW uid. Shell-injection boundary. |
| `displayName` | string | yes | – | 1–512 characters, free text including spaces; no control characters | Display name |
| `email` | string, nullish | no | not managed | `""`, `null` or omitted all mean **not managed**. Otherwise at most 320 characters, exactly one `@`, a `.` in the domain part, no whitespace. Accept `ops@example.test`; reject `not-an-email`, `a@b`, `a b@example.test`. | Email to converge |
| `accessKey` | string | yes | – | **sensitive** (D48); credential grammar (§1.6, D53) | S3 access key id, from the vault |
| `secretKey` | string | yes | – | **sensitive** (D48); credential grammar (§1.6) | S3 secret, from the vault |

On a Path B build (§1.3) the method also takes the Admin Ops arguments:
`adminOpsEndpoint` (https origin, §1.6 endpoint rules), `adminOpsAccessKey` and
`adminOpsSecretKey` (sensitive, credential grammar), and `requestTimeoutMs`
(1000–300000). The SigV4 region for Admin Ops is the zonegroup api name passed
as `adminOpsRegion` (region grammar, §1.6). On a Path A build these arguments
do not exist.

**Preconditions**

- SSH reach to an admin host with passwordless sudo and cephadm.
- An RGW realm and zone exist.
- Path B only: the Admin Ops endpoint is reachable and the admin credential
  holds `users=write`.

**Behaviour**

1. Re-check `uid`, `displayName`, `email`, `accessKey`, `secretKey` and, on
   Path B, the Admin Ops arguments (§1.5). On failure, throw `validate` with
   zero SSH and zero HTTP calls. Credential errors name the argument and its
   length, never the value.
2. Read: `radosgw-admin user info --uid='<uid>'`, allowing a non-zero exit,
   because absence arrives as a non-zero exit and is an answer. Classify:
   - **present**: exit 0, stdout parses as JSON, and the JSON has a string
     `user_id`.
   - **absent**: non-zero exit, and the combined stdout and stderr carry a
     recognised absence marker:
     - `could not fetch user info:` followed by errno `(2)`; or
     - `could not fetch user info:` followed by `no user info saved` (the
       Squid form: exit 22, no errno, often after a long cephadm banner); or
     - `no such user`, case-insensitive.
   - **unreadable**: everything else, including exit 0 with non-JSON, JSON
     without `user_id`, and the same `could not fetch user info` phrase with
     any **other** errno (13 permission denied, 110 timed out, 5 I/O error, …).
     The detail is redacted (§1.2), then trimmed to the **last** ~2000
     characters.
   - A typed transport error (D8), such as SSH exit 255, is never absent: the
     method throws `read` with the redacted message.
3. Initial state unreadable → throw `read`. Do not create.
4. **Absent** → create the user with `uid`, `displayName`, `email` if managed,
   and the requested key pair, using the build's secret-delivery path (§1.3).
   No other key may be generated. Record change `created user`. Re-read with
   `user info`; if the re-read is not present, or its key list holds any
   access key other than the requested one, throw `verify` with the observed
   state and the redacted detail.
5. **Present** → compare, and collect only the writes that differ, in this
   order:
   - display name differs → `radosgw-admin user modify --uid='<uid>'
     --display-name='<displayName>'`; change `set display-name`.
   - email managed and differs → `radosgw-admin user modify --uid='<uid>'
     --email='<email>'`; change `set email`. An unmanaged email never clears an
     existing one.
   - no key entry has the requested access-key id → add an S3 key with that
     access key and secret, using the build's secret-delivery path (§1.3);
     change `created s3 access key`.
   - If any write was issued, run the writes in order, then re-read:
     - unreadable → throw `verify`;
     - absent → throw `verify`;
     - otherwise display name, email (if managed) and key presence MUST all
       hold, or throw `verify` listing what still differs.
   - If nothing differed, issue **no** write and **no** second read. The first
     read is the evidence.
     - Why: each `cephadm shell` start costs tens of seconds.
6. Log either the list of changes or `already correct`. The log line never
   includes the access key or the secret.
7. Write the record.

All values that reach the remote script are validated and then single-quoted
with POSIX quote escaping (01-transport). Validation and quoting are separate,
complementary layers; neither replaces the other.

**Idempotency**

- A second run against a converged user does exactly one `user info` and no
  writes; `changes` is empty.
- Another access key alongside the requested one is left alone; the method
  only adds the requested key.
- **Blind spot:** the secret is never compared, because comparing it would mean
  handling it. A rotated secret behind an unchanged access-key id therefore
  reads as correct. To rotate, use a new access-key id, which the method
  notices and adds, or rotate out-of-band. There is deliberately no force
  flag.
- Suspension is out of scope.

**Output / record** (`cephRgwUserResult` at `rgwUser-<uid>`)

| field | meaning |
|---|---|
| `method`, `host`, `uid`, `displayName` | as given |
| `email` | `""` when not managed |
| `existedBefore` | boolean |
| `changes` | list of change labels; empty means already correct, not skipped |
| `accessKeyPresent` | the final read shows the requested access-key id |
| `maxBuckets` | from `max_buckets`, or **-1** when not reported. 0 is a real quota (no buckets allowed), so a fake 0 would be misread as policy. |
| `suspended` | true when a non-zero `suspended` is reported |
| `secretDelivery` | `file`, `stdin` or `admin-ops` (§1.3) |
| `capturedAt` | ISO timestamp |

No secret, no secret field name, no access key and no raw JSON.

**Post-verification:** `user info` re-read after any write.

**Failure modes**

- invalid `uid` (or any other argument) → `validate`, zero calls, no record.
- credential with bad length or a forbidden character → `validate`, zero calls,
  value not echoed.
- initial read unreadable or transport error → `read`; no create.
- create, modify or key create fails → `user-create`, `user-modify` or
  `key-create` with a **redacted** message; the secret is never shown.
- re-read after create not present, or extra keys → `verify`.
- re-read after converge unreadable, absent or mismatched → `verify`.
- No retries.

**Security**

- The secret never appears on a command line or in script text (D50, §1.3).
- The script is built only from validated, quoted values.

**Why**

- The absence marker must include the errno, because `radosgw-admin` prefixes
  every `user info` failure with the same phrase; matching the phrase alone
  classifies permission-denied and timeout as absent and creates a user on a
  cluster the method cannot read. A false absent mutates the cluster; a false
  unreadable only fails loudly and can be retried.
- Keep the end of the output in the detail, not the start, because the cephadm
  banner fills the start.
- Workflows cannot omit an argument conditionally, so `""` and `null` mean
  "not managed".

**Test obligations**

- Redactor:
  - [ ] one `secret_key` in JSON → replaced; result still parses; access key
    kept.
  - [ ] three secrets in pretty-printed multi-line JSON → three replacements.
  - [ ] `--secret=` and `--secret-key <v>` forms → value redacted, flag kept.
  - [ ] literal secret value inside free text → redacted.
  - [ ] redaction before truncation: a secret straddling the truncation point
    leaves no fragment.
  - [ ] negative control: text without a secret → byte-identical.
- Classifier:
  - [ ] exit 0 + user JSON → present, with uid, display name and access key,
    and no secret in the parsed view.
  - [ ] exit 2 + errno-2 text → absent.
  - [ ] `No such user` → absent.
  - [ ] exit 22 `no user info saved` after a ~60-line banner → absent.
  - [ ] exit 1 permission denied, exit 5 → unreadable with non-empty detail.
  - [ ] SSH exit 255 → typed transport error, throws `read`, no create (D8).
  - [ ] exit 0 + garbage → unreadable.
  - [ ] unreadable detail is redacted.
  - [ ] same phrase with errno 13, 110 or 5 → unreadable; errno 2 → absent.
  - [ ] errno 13 or 110 after the banner → unreadable, detail contains the
    error tail.
- Method:
  - [ ] absent → exactly 3 operations (info, create, info). The create carries
    uid, display name, email and access key, quoted; the secret is delivered
    by the build's path. Record `existedBefore=false`, `changes` includes
    `created user`.
  - [ ] present and identical → exactly 1 operation; `changes=[]`;
    `existedBefore=true`; `accessKeyPresent=true`.
  - [ ] different display name → exactly one `user modify` with the new name;
    `changes=["set display-name"]`.
  - [ ] a different key exists → one key-create with type s3 and the requested
    access key; `changes=["created s3 access key"]`.
  - [ ] create re-read shows an extra generated key → rejects `verify`.
  - [ ] record and all log lines contain neither the secret nor `secret_key`.
  - [ ] `uid` with shell metacharacters → rejects `validate`, zero calls, zero
    records.
  - [ ] unreadable initial read → rejects after one operation, no create.
  - [ ] read succeeds, then the modify fails with secret-bearing stdout →
    thrown message lacks the secret, **contains** `<redacted>` (positive
    control), names the command or `cephadm shell`; chained cause also
    redacted.
- D48:
  - [ ] `accessKey` and `secretKey` carry `sensitive` metadata (also the Admin
    Ops credentials on a Path B build).
- D49:
  - [ ] the result schema declares every written field and no field whose name
    contains `secret`.
- D50:
  - [ ] across create and key-create runs, no SSH argv element, no remote
    command line, no script text and no `radosgw-admin` argv contains the
    secret or a `--secret` flag.
  - [ ] Path A build: the secret reaches the admin host only via the SSH
    process's stdin; the temp file (if used) is created mode 0600 inside the
    0700 directory and removed.
  - [ ] Path B build: the secret appears only in the signed Admin Ops request;
    no URL appears in records, logs or errors; a failed Admin Ops request
    throws a redacted error; success is confirmed only by the `user info`
    re-read.
  - [ ] `secretDelivery` matches the build's path.
- D53:
  - [ ] access key `ab+/cd=` accepted; with a space, newline or non-ASCII
    character → rejects `validate`, zero calls.
- Schema:
  - [ ] `email` `""` or `null` → not managed; omitted → not managed; a valid
    email kept; `not-an-email` refused.
  - [ ] key is exactly `rgwUser-<uid>` and stable; lifetime and GC as §1.11.
  - [ ] the method exposes a description and an argument schema.

---

## 3. Method: cephRgwBucketInventory

- **Safety class:** RO. Description starts with `READ-ONLY.`
- **Purpose:** List every RGW bucket with owner, object count, logical and
  on-disk size, and placement rule, plus cluster totals. This is the
  before/after evidence for data migrations and the only place placement is
  observed (D54). It does not talk to the S3 endpoint, so it says nothing about
  the gateway's reachability or TLS.

**Inputs**

| name | type | required | default | constraints | meaning |
|---|---|---|---|---|---|
| `host` | string | yes | – | hostname or IPv4 grammar | Admin host |
| SSH connection args | shared | `sshUser` yes | overview §3 | overview §3 | SSH connection |
| `rgwRealm` | string, nullish | no | default realm | `null` and `""` mean omitted. Otherwise the Ceph identifier grammar (§2 `uid`), at most 128 characters, re-checked when the method runs. | RGW realm to read |

There is deliberately no uid filter: `bucket list` documents only `--bucket`,
which turns the listing into an object listing. Callers filter the result.

**Preconditions:** SSH reach to an admin host with passwordless sudo and
cephadm.

**Behaviour**

1. If a realm is given, validate it. Invalid → `validate`, zero commands. The
   realm flag ` --rgw-realm='<realm>'` is appended to **every** command.
2. List buckets, paged until exhausted (D52):
   `radosgw-admin bucket list --format=json --max-entries=<page>[ --marker='<m>'][ --rgw-realm=…]`.
   - `<page>` is a fixed page size of 1000.
   - The first page has no marker. Each next page uses the last name of the
     previous page as the marker.
   - Stop when a page holds fewer than `<page>` entries, or is empty.
   - A page that returns the previous marker again, or no new names, → throw
     `list` (no progress).
   - A name seen twice across pages is counted once.
   - Each page is parsed as an array of strings, or as an array of objects
     each with a string `bucket` field. Non-JSON, a non-array, or an entry of
     neither shape → throw `parse` with a redacted excerpt of the first ~500
     characters. `[]` is a valid empty answer.
   - The marker is a cluster-returned name: it MUST pass the safe-name
     charset (step 3) before it may appear in a command. A last name that
     fails it → throw `list`, naming the problem without echoing the name
     unquoted.
3. Split the names. A cluster-returned name is attacker-influenced data,
   because anyone with a key can create a bucket. A name may be put in a
   command only if it starts with a letter or digit and continues with at most
   254 letters, digits, `.`, `_` or `-`. Accept `data-01`, `a.b_c`; reject
   `x; rm -rf /`, `a'b`, `-x`, a name with a space. Names that fail go into
   `unstattable` and are reported, never silently dropped and never put in a
   command.
4. For each safe name: `radosgw-admin bucket stats --bucket='<name>'
   --format=json[ --rgw-realm=…]`. Parse:
   - non-JSON → throw `stats`.
   - missing string `owner` → throw `stats`.
   - Sum `num_objects`, `size` and `size_actual` across **every** category
     under `usage` (`rgw.main`, `rgw.multimeta`, …).
   - An empty usage object, a missing category, or a non-numeric figure counts
     as 0, never NaN.
   - `placementRule` = `placement_rule`, or `""` when absent. Never a guess.
5. Write the record and log the counts.

**Idempotency:** N/A, read-only. Each run overwrites the same key.

**Output / record** (`cephRgwBucketInventoryResult`)

| field | meaning |
|---|---|
| `method`, `host` | as given |
| `rgwRealm` | `""` for the default realm |
| `bucketCount` | number of buckets stat'd |
| `buckets[]` | each `bucket`, `owner`, `numObjects`, `sizeBytes`, `sizeActualBytes`, `placementRule` |
| `unstattable[]` | non-empty means the inventory is **incomplete** and totals are lower bounds |
| `pagesRead` | number of list pages read |
| `totalObjects`, `totalSizeBytes`, `totalSizeActualBytes` | sums |
| `capturedAt` | ISO timestamp |

**Post-verification:** N/A.

**Failure modes**

- invalid realm → `validate`, zero commands.
- list or stats fails at the transport → `list` / `stats`, redacted.
- parse failure → `parse` / `stats`.
- paging makes no progress → `list`.
- No partial record is written.

**Security:** realm validation; the safe-name charset for every
cluster-returned name, including markers; all values quoted; output redacted
before it reaches an error.

**Why**

- An unparseable answer must never become an empty inventory, or a migration
  gate would pass over buckets it never saw.
- An unpaged list can silently truncate on a large cluster, which is the same
  failure as an empty inventory (D52).
- A new bucket's `usage` is `{}`, and NaN totals compare false against every
  threshold, so missing figures count as zero.
- `size` is the logical figure (what must be moved); `size_actual` is rounded
  up to allocation units (what it will occupy).
- An empty `placementRule` makes any comparison against the requested
  placement fail, which is the right outcome for a property that could not be
  observed.

**Test obligations**

- [ ] commands are exactly `radosgw-admin bucket list --format=json
  --max-entries=1000` and `radosgw-admin bucket stats --bucket='<n>'
  --format=json`; no command starts with `ceph `.
- [ ] two buckets → `bucketCount` 2; totals summed (objects 3+7, sizes
  1000+500, actual 1024+512); empty `unstattable`; key from the host.
- [ ] cluster-returned name containing `; rm -rf /` → in `unstattable`,
  `bucketCount` 1, exactly one list and one stats command, no command contains
  the injected text.
- [ ] empty cluster → one list command, a record of zeros, no error.
- [ ] realm `realm-a` → every command ends with the realm flag; key and
  `rgwRealm` include the realm. Omitted, `null` or `""` → no flag, key and
  `rgwRealm` `""`.
- [ ] realm with shell metacharacters → rejects `validate`, zero commands.
- [ ] D52: 2500 names → three list pages; pages 2 and 3 carry the last name of
  the previous page as `--marker`; `pagesRead` 3; all names stat'd.
- [ ] D52: a page exactly 1000 long followed by an empty page → stops, two
  pages.
- [ ] D52: a page that repeats the previous marker → rejects `list`, no record.
- [ ] D52: an unsafe last name on a full page → rejects `list`; it never
  reaches a command.
- [ ] list parser accepts names, objects with `bucket`, and `[]`; throws on
  non-JSON and on a non-array.
- [ ] stats parser sums all categories; empty usage → zeros; non-numeric → 0;
  missing owner → throws; `placement_rule` read through, otherwise `""`.
- [ ] key stable, per host, realm-suffixed.
- [ ] secret-bearing stats output in a failure → error redacted.

---

## 4. Method: cephRgwBucketInspect

- **Safety class:** RO (sends only HEAD and GET). Description starts with
  `READ-ONLY.`
- **Purpose:** Record what one bucket is, as seen by the supplied credentials.
  Used as evidence for an approval gate before a mutation.

**Inputs:** the common S3 arguments (§1.6) only.

**Preconditions:** none beyond a reachable endpoint.

**Behaviour**

1. Validate all arguments (§1.5). Zero requests on failure.
2. Classify presence (§1.8). **unreadable** → throw `read`; nothing is
   recorded. absent, foreign, credentials-rejected and wrong-zonegroup are
   **recorded, not thrown**.
3. Only when **owned**, read in this order:
   - PAB (`GET ?publicAccessBlock`, §1.9; null when none);
   - ACL (`GET ?acl`, MUST be 200, parsed);
   - policy (`GET ?policy`: 404 with `NoSuchBucketPolicy` = none; 200 = the
     text, which MUST be JSON; anything else throws `read`);
   - versioning (`GET ?versioning`, MUST be 200).
4. ACL parsing MUST find an `AccessControlPolicy` document with `Owner` →
   `ID`. Each `Grant` MUST have a grantee type (`xsi:type`, resolved by
   namespace, not by prefix spelling), a grantee identity (`ID`, `URI` or
   `EmailAddress`, entity-decoded) and a `Permission`. Anything else throws
   `parse`.
   - Why: an unparseable ACL is not a private one.
5. **Private** means exactly one grant: `CanonicalUser` = owner id, permission
   `FULL_CONTROL`.
6. Versioning has **three** states:
   - `Enabled`, `Suspended`, or `never-configured` (no `Status`, or an empty
     `Status`);
   - any other `Status` throws `parse`;
   - a body that is not a `VersioningConfiguration` throws `parse`.
   - Why: never-configured behaves differently from Suspended for conditional
     writes, so two states would lose information.

**Idempotency:** N/A, read-only; same key each run.

**Output / record** (`cephRgwBucketInspectResult`)

| field | meaning |
|---|---|
| `method`, `endpoint` (normalised origin), `region`, `bucket` | as given |
| `presence` | `owned`, `absent`, `foreign`, `credentials-rejected`, `wrong-zonegroup` |
| `ownerId` | `""` unless owned |
| `aclGrants[]` | grantee type, grantee, permission; empty unless owned |
| `aclPrivate` | boolean |
| `hasPolicy` | boolean |
| `policy` | verbatim text, `""` when none |
| `policyCanonical` | canonical JSON string (§6), `""` when none |
| `versioning` | one of the three states, or `""` when not owned |
| `publicAccessBlock` | four booleans, or null |
| `publicAccessBlockFull` | boolean |
| `capturedAt` | ISO timestamp |

**Post-verification:** N/A.

**Failure modes:** validation → `validate`, zero requests; unreadable presence
→ `read`, no record; non-200 or unparseable ACL, policy or versioning → `read`
/ `parse`, no record.

**Security:** never reads or claims anything about a bucket these credentials
cannot use; no request headers in output.

**Test obligations**

- [ ] owned bucket with a policy and Suspended versioning → every request is
  GET or HEAD; presence owned; `aclPrivate` true; `policy` verbatim;
  `policyCanonical` equals the canonical form of the parsed text; versioning
  Suspended.
- [ ] absent → recorded with versioning `""`.
- [ ] foreign → recorded, empty `aclGrants`. Rejected credentials → recorded
  `credentials-rejected`. HEAD 503 → rejects `read`, no record.
- [ ] PAB with BlockPublicPolicy false → flags recorded, full false. No PAB →
  null, full false.
- [ ] D53: ACL with a prefixed namespace (e.g. `s3:Grant`) and an AllUsers URI
  containing an entity → parsed identically to the unprefixed form; the
  AllUsers grant makes `aclPrivate` false.
- [ ] D48: `accessKey` and `secretKey` carry `sensitive` metadata.

---

## 5. Method: cephRgwBucketEnsure

- **Safety class:** M (idempotent converge). Also writes and deletes
  temporary probe objects.
- **Purpose:** Ensure the bucket exists, is owned by these credentials, has a
  private ACL and all four PAB flags, and **prove** that anonymous listing is
  refused and that public object ACLs cannot leak.

**Inputs:** the common S3 arguments (§1.6), plus:

| name | type | required | default | constraints | meaning |
|---|---|---|---|---|---|
| `placementTarget` | string | yes | – | region grammar (§1.6), 1–64 characters | Placement id in the zonegroup. Sent as `<region>:<placementTarget>` on create; cannot change afterwards. |
| `skipObjectLeakProbe` | boolean, nullish | no | run the probe | omitted or `null` → **run** | `true` skips the object-leak probe. Skipping must be asked for, and the record says so. |

**Preconditions:** the owner's RGW user exists (see `cephRgwUserEnsure`).

**Behaviour**

1. Validate everything (§1.5). Zero requests on failure.
2. Classify presence (§1.8). Refuse anything other than owned or absent, with
   the phase of the class (`foreign`, `credentials`, `zonegroup`, `read`), and
   zero writes.
3. **Absent** → CreateBucket: signed `PUT <origin>/<bucket>` with header
   `x-amz-acl: private` and a `CreateBucketConfiguration` body (S3 2006-03-01
   namespace) whose `LocationConstraint` is `<region>:<placementTarget>`.
   - Success: 200, or code `BucketAlreadyOwnedByYou` (covers a race).
   - Code `InvalidLocationConstraint` → throw `placement`: the placement
     target is missing from this zonegroup, or the region is not this
     endpoint's zonegroup.
   - Other answers → throw `create`.
   - Re-classify; anything other than owned → throw `create-verify`.
   - `created` = true only on a 200.
4. Read the ACL. If not private: `PUT ?acl` with `x-amz-acl: private` (MUST be
   200, else `acl-set`), re-read, require private (else `acl-verify`).
5. Read the PAB. If not full: write all four true with `Content-MD5` and
   verify by read-back (§1.9); failure → `pab-set`.
6. **Anonymous-list probe:**
   - Control: signed `GET <origin>/<bucket>?list-type=2&max-keys=0` MUST answer
     200. Otherwise throw `control`; no unsigned request is sent.
   - The same request **unsigned**:
     - 2xx → throw `anonymous-allowed` (the bucket is PUBLIC);
     - 403 → pass;
     - anything else → throw `anonymous-inconclusive`.
7. **Object-leak probe** (unless skipped), with the owner's credentials and
   the keys of §1.12:
   - a. PutObject `<stem>-canned`. Not 200 → throw `object-leak-probe` (the
     probe could not run; nothing stored). Remember `x-amz-version-id` if
     returned.
   - b. PutObjectAcl `<stem>-canned?acl` with `x-amz-acl: public-read`. Its
     status is recorded but not judged.
   - c. Unsigned GET of `<stem>-canned`.
   - d. PutObject `<stem>-grant` with header
     `x-amz-grant-read: uri="http://acs.amazonaws.com/groups/global/AllUsers"`.
     If 2xx, remember it (and its version id) and send an unsigned GET for it;
     otherwise its anonymous status is recorded as 0.
   - e. **Always** delete every stored probe object, by `?versionId=` when one
     was returned, so a versioned bucket keeps no noncurrent version. A delete
     succeeds only on 2xx.
   - Error handling:
     - a step failed after something was stored → rethrow that step's error
       (`object-leak-probe`), adding the keys left behind if cleanup also
       failed;
     - only cleanup failed → throw `object-leak-cleanup`, naming the keys to
       remove by hand.
   - Judge only by the anonymous GETs, never by write statuses:
     - either GET served (2xx) → throw `object-leak`, naming the form: canned
       `public-read` ACL, or the `x-amz-grant-read` header (IgnorePublicAcls
       not holding).
     - canned GET not 403, or grant GET neither 403 nor 0 → throw
       `object-leak-inconclusive`. A 405 is explicitly not a refusal.
8. Write the record.

Placement is not checked here (D54). The record's `placementRequested` states
what was asked for, not what is true.

**Idempotency:** an owned, private, fully blocked bucket gets **no
bucket-level write**. Only the probe objects are written, and they are
deleted.

**Output / record** (`cephRgwBucketResult`)

| field | meaning |
|---|---|
| `method`, `endpoint`, `region`, `bucket` | as given |
| `placementRequested` | `<region>:<placementTarget>`; not proven (D54) |
| `existedBefore`, `created` | booleans |
| `ownerId` | from the final ACL |
| `aclGrantsBefore`, `aclGrantsAfter`, `aclChanged`, `aclPrivate` | ACL evidence |
| `pabBefore` (or null), `pabAfter` (always all four true), `pabChanged` | PAB evidence |
| `objectLeakProbe` | `refused` or `skipped` |
| `objectLeakProbeWriter` | owner id; `""` when skipped |
| `objectLeakProbeKey` | the canned key; `""` when skipped |
| `objectAclStatus`, `anonymousObjectStatus`, `grantHeaderPutStatus`, `grantHeaderAnonymousStatus` | statuses; 0 when skipped |
| `controlStatus` (200), `anonymousStatus` (403) | list probe evidence |
| `capturedAt` | ISO timestamp |

**Post-verification:** presence re-classified after create; ACL re-read; PAB
read back; live anonymous probes.

**Failure modes**

- validation (endpoint, credential, name, id, timeout) → `validate`, zero
  requests.
- foreign, credentials-rejected, wrong-zonegroup, unreadable → that phase, zero
  writes.
- create refused → `create` / `placement`; create-verify → `create-verify`.
- ACL or PAB set/verify fails → `acl-set`, `acl-verify`, `pab-set`.
- control not 200 → `control`.
- anonymous allowed or inconclusive → `anonymous-allowed` /
  `anonymous-inconclusive`.
- probe could not run, leak found, leak inconclusive, cleanup failed →
  `object-leak-probe`, `object-leak`, `object-leak-inconclusive`,
  `object-leak-cleanup` (D51).
- Never a success record on any failure.

**What it cannot see**

- A leak for objects written by a **different** data user. The probe covers
  the owner-written case.
- The actual placement (D54).

**Security:** objects are written only under `.cephadm-pab-probe/`; the
secret signs requests and goes nowhere else.

**Why**

- A policy alone does not stop object leaks, and a PAB flag can be stored
  without being enforced; only live anonymous requests prove the effect.
- Cleanup by version id is needed because deleting the current version of a
  versioned bucket leaves a noncurrent copy behind.

**Test obligations**

- [ ] absent → one CreateBucket with LocationConstraint `<region>:<placement>`,
  `x-amz-acl: private`, signed. Record `created=true`, `existedBefore=false`,
  `aclPrivate=true`, `aclChanged=false`, control 200, anonymous 403,
  `placementRequested`, fixed `capturedAt`. List probes signed then unsigned,
  in that order.
- [ ] owned, private, full PAB → no bucket-level writes, `pabChanged=false`, no
  objects remain, `existedBefore=true`, `created=false`.
- [ ] AllUsers READ grant → one `PUT ?acl` private; `aclChanged=true`; 2 grants
  before, 1 after.
- [ ] foreign → rejects `foreign`, no writes, no record, a signed `GET /` was
  made.
- [ ] rejected key (HEAD 403, ListBuckets 403) → rejects `credentials`, no
  writes.
- [ ] HEAD timeout or HEAD 500 → rejects `read`, no writes.
- [ ] unknown placement → rejects `placement`; no bucket created.
- [ ] anonymous list allowed → rejects `anonymous-allowed`, no record.
- [ ] owner's signed list 500 → rejects `control`; no unsigned list sent.
- [ ] endpoint examples of §1.6 → rejects `validate` with zero calls; a plain
  https origin works.
- [ ] secret containing a newline → rejects `validate`, error lacks the value,
  zero calls.
- [ ] bucket-name examples of §1.6 → refused / accepted as listed.
- [ ] no PAB → becomes all four on; the PUT carries `Content-MD5`;
  `pabBefore=null`; `pabChanged=true`; object statuses 403.
- [ ] PAB write accepted but not stored → rejects `pab-set`, no record.
- [ ] PAB stored but not enforced → rejects `object-leak`; probe objects
  deleted; no record. Control: an enforcing bucket passes with 403.
- [ ] versioned bucket → 2 deletes, each with a `versionId`. Unversioned → no
  `versionId`.
- [ ] D51: every probe PUT path starts with `.cephadm-pab-probe/`; record
  `refused`, writer = owner, key under the prefix.
- [ ] D51: canned PutObject answered 500 → rejects `object-leak-probe`, the
  message says the probe could not run and claims no leak; no delete needed;
  no record. A leak case rejects `object-leak` with a different message.
- [ ] D51: cleanup DELETE refused → rejects `object-leak-cleanup` naming the
  keys.
- [ ] skip `true` → no object requests; record `skipped`, writer `""`. Skip
  omitted or `null` → probe runs.
- [ ] grant-header leak (PAB full but IgnorePublicAcls not enforced) → rejects
  `object-leak` naming `x-amz-grant-read`; objects deleted.
- [ ] fully enforced → canned 403, grant PUT 200, grant GET 403, two deletes.
- [ ] anonymous canned GET 405 → rejects `object-leak-inconclusive`; no record;
  objects deleted.
- [ ] D54: an owned bucket on a different placement → no placement read is
  made; the run succeeds; `placementRequested` is the requested value.
- [ ] each request uses a fresh connection (no keep-alive reuse).
- [ ] across ensure, policy and versioning runs plus a failing run, all
  records, logs and errors (over 1000 characters in total, so the check is not
  vacuous) never contain the secret.

---

## 6. Method: cephRgwBucketPolicyEnsure

- **Safety class:** M (idempotent converge, with rollback).
- **Purpose:** Apply a bucket policy and **prove** what it does: no public
  grant, scoped to this bucket, no owner lockout, anonymous access refused,
  and (when asked) plain HTTP refused.

**Inputs:** the common S3 arguments (§1.6), plus:

| name | type | required | default | constraints | meaning |
|---|---|---|---|---|---|
| `policyDocument` | string | yes | – | at least 2 characters, valid JSON, at most 20480 bytes UTF-8, passes the structural validation below | Policy JSON text, sent verbatim |
| `plainHttpEndpoint` | string, nullish | no | not tested | when given: an `http` origin only (origin rules of §1.6 with scheme `http`) | Requests the TLS-only proof. Omitted → record shows `not-tested`. |

**Structural validation (before any request)**

- The document is a JSON object with a non-empty string `Version` and at least
  one statement. `Statement` may be one object or a list; every entry MUST be
  an object.
- `Effect` MUST be `Allow` or `Deny`.
- An `Allow` MUST NOT (→ `public-allow`):
  - use `NotPrincipal` ("everyone except" counts as public);
  - have a `*` principal in any spelling (`"*"`, `{"AWS":"*"}`, or a list
    containing `*`);
  - have an empty or missing `Principal`;
  - use `NotResource`;
  - omit `Resource`.
- Every `Resource` and `NotResource` entry MUST be `arn:aws:s3:::<bucket>` or
  start with `arn:aws:s3:::<bucket>/` (→ `validate`). For bucket `data-01`,
  accept `arn:aws:s3:::data-01` and `arn:aws:s3:::data-01/*`; reject
  `arn:aws:s3:::data-01x`, `arn:aws:s3:::data-0*`, `*`.
- A `*` principal on a `Deny` is allowed; it is the normal form of a blanket
  refusal.
- `declaresSecureTransport` = some `Deny` has `Condition` → `Bool` →
  `aws:SecureTransport` including `false`.
- Whether the granted actions are the right ones is **not** judged; that is the
  bucket owner's design.

**Canonical form (for comparison)**

- `Statement` is always a list, sorted by each entry's serialised canonical
  form.
- `Action`, `NotAction`, `Resource`, `NotResource` become sorted string lists.
- `Principal` and `NotPrincipal`: `"*"` becomes `{"AWS":["*"]}`; otherwise
  each value becomes a sorted string list. Any other shape throws `validate`.
- `Condition` values become sorted string lists, so `false` and `"false"` are
  equal.
- All object keys are sorted recursively.
- Equal meaning compares equal, so reformatting or reordering is not drift.

**Owner-lockout check**

- The owner id is read from the bucket's ACL, never assumed.
- Only **unconditional** `Deny` statements that apply to the owner count:
  - with `Principal`: it names `*`, the owner id, or
    `arn:aws:iam::<tenant>:user/<uid>`. An owner id of the form `tenant$uid`
    is split at `$`; a plain uid has an empty tenant.
  - with `NotPrincipal`: it does **not** name the owner.
- The statement must also cover the bucket ARN: by a `Resource` glob that
  matches it, or by a `NotResource` that does not.
- For each of `s3:GetBucketPolicy`, `s3:PutBucketPolicy` and
  `s3:DeleteBucketPolicy`: denied if an `Action` glob matches it, or no
  `NotAction` glob matches it. Globs: `*` matches any run, `?` one character,
  case-insensitive.
- A non-empty result → throw `self-lockout` before any write.
  - Why: the owner could never read, fix or remove the policy, not even through
    this method's own re-run or rollback; recovery would need the RGW system
    user.
- Conditional denies are not counted; the probes and the rollback handle them.

**Behaviour**

1. Validate the target, `plainHttpEndpoint` and the document. Zero requests on
   failure.
2. Classify presence (§1.8); refuse anything not owned. Absent → `absent` with
   a hint to run `cephRgwBucketEnsure` first; nothing is created.
3. Read the ACL owner and run the lockout check.
4. Read the current policy (raw text, or none) and canonicalise it.
   `changed` = canonical before ≠ canonical desired.
5. If changed, read the PAB. If BlockPublicPolicy is on, **lift only that
   flag** with a verified write (failure → `pab-lift`).
6. Guarded block:
   - if changed: `PUT ?policy` with content type `application/json` and the
     caller's text verbatim (MUST be 200 or 204, else `policy-write`); re-read;
     the canonical read-back MUST equal desired, else `verify`;
   - then run the anonymous-list probe of §5 step 6 (`control`,
     `anonymous-allowed`, `anonymous-inconclusive`). It runs whether or not
     anything was written.
7. Undo, in reverse order:
   - If the block failed and a policy was written, **roll back**: `DELETE
     ?policy` if there was none before, otherwise PUT the previous raw text
     unchanged. Outcome text: `RESTORED` (with "previous policy was put back"
     when one existed) or `RESTORE FAILED` (the new policy may still be
     applied and may deny its own owner; recover as the RGW system user).
   - Then, if the PAB was lifted, restore the **original** PAB with a verified
     write, on success and failure alike. Failure → outcome text `PUBLIC
     ACCESS BLOCK NOT RESTORED` (BlockPublicPolicy may still be off; fix by
     hand).
   - If the block failed: log a warning and throw the original phase and
     message, followed by the policy and PAB outcome text.
   - If only the PAB restore failed: throw `pab-restore`. No record.
8. Plain-HTTP probe (only when `plainHttpEndpoint` is given): the **same
   signed** list request sent to the http origin.
   - refused → `no-listener` (counts as evidence).
   - unreachable → throw `plain-http-inconclusive`.
   - 2xx → `served`; if `declaresSecureTransport`, throw
     `secure-transport-ignored` (this RGW build ignores the condition, so
     TLS-only is not in effect).
   - 403 → `denied`.
   - other → throw `plain-http-inconclusive`.
   - The policy stays applied when this step throws, since it passed its own
     proof.
9. Write the record.

**Idempotency:** an equivalent stored policy (different formatting or
statement order) → no PutBucketPolicy and **no PAB access at all**;
`changed=false`. The probes still run.

**Output / record** (`cephRgwBucketPolicyResult`)

| field | meaning |
|---|---|
| `method`, `endpoint`, `region`, `bucket` | as given |
| `hadPolicyBefore`, `changed` | booleans |
| `statementCount`, `declaresSecureTransport` | from validation |
| `canonicalPolicy` | desired canonical JSON string |
| `controlStatus`, `anonymousStatus` | list probe evidence |
| `pabLiftedForWrite` | boolean |
| `plainHttp` | `not-tested`, `denied`, `no-listener`, `served` |
| `plainHttpStatus` | 0 unless answered |
| `capturedAt` | ISO timestamp |

**Post-verification:** canonical read-back; live anonymous probe; PAB
read-back after lift and restore; optional plain-HTTP probe.

**Failure modes**

- validation → `validate` / `public-allow`, zero requests.
- absent, foreign, credentials-rejected, wrong-zonegroup, unreadable → that
  phase.
- self-lockout → `self-lockout`, zero writes, policy unchanged.
- write not accepted, or read-back differs → rollback, then throw.
- control or anonymous probe fails → rollback, then throw.
- PAB lift fails → `pab-lift`.
- PAB restore fails → `pab-restore`.
- plain HTTP served with a SecureTransport deny, or inconclusive → throw.

**Security:** a public grant is refused before the network is touched; the
document is sent verbatim and never logged in full alongside credentials.

**Why**

- A policy that parses but denies nothing looks exactly like success from the
  write's status code; only a probe tells them apart.
- A SecureTransport=false deny was measured to be a silent no-op on this RGW
  (RGW may not see TLS when it is terminated in front of it).
- With PAB on, every policy write is refused, which is why the flag is lifted
  and then restored.
- A bucket left with a weakened PAB is worse than a policy that did not land.

**Test obligations**

- [ ] no policy → written; `changed=true`; `hadPolicyBefore=false`;
  `declaresSecureTransport=true`; anonymous 403; plain `denied` with status
  403; the plain probe was signed.
- [ ] equivalent stored policy (statements reversed, pretty-printed) → zero
  writes, `changed=false`, `plainHttp` `not-tested`.
- [ ] read-back mangled (a statement dropped) → rejects `verify`; no record.
- [ ] plain HTTP served plus a TLS deny → rejects `secure-transport-ignored`.
- [ ] plain connection refused → `no-listener`; plain timeout → rejects
  `plain-http-inconclusive`.
- [ ] public Allow → rejects `public-allow` with zero calls.
- [ ] absent bucket → rejects `absent`; no writes; no bucket created.
- [ ] validator: `*` principal on an Allow refused in all three spellings; a
  Deny `*` passes (`statementCount` 2, `declaresSecureTransport` true); Allow
  with `NotPrincipal` refused; a sibling bucket's ARN refused; this bucket's
  ARNs accepted; non-JSON, missing `Version`, empty `Statement` refused.
- [ ] canonical: reordered statements, string vs list, `false` vs `"false"`,
  reordered keys → equal. Dropping one action → not equal.
- [ ] lockout: a two-statement draft (deny the owner everything except five
  data actions; deny everyone else everything) → all three management actions;
  adding those three to the exception list → none; blanket Deny `*` on `s3:*`
  → all three; a conditional TLS deny → none; a Deny with `NotPrincipal`
  sparing the owner → none; a tenant ARN principal with `s3:*Policy` → all
  three for `tenant$uid`, none for another tenant's id.
- [ ] self-locking draft → rejects `self-lockout`, zero writes, policy still
  none. Fixed draft → applied.
- [ ] gateway refuses the owner's list once a policy exists → rejects; message
  contains `RESTORED`; policy back to none via DELETE; no record.
- [ ] previous policy present and only the new one breaks the control →
  rejects with "previous policy was put back"; stored text identical to the
  previous one.
- [ ] rollback DELETE refused → rejects with `RESTORE FAILED`.
- [ ] full PAB on and a new policy → policy lands, PAB back to all on,
  `pabLiftedForWrite=true`, exactly 2 PAB writes. Control: the fake gateway
  refuses a policy PUT while PAB is on.
- [ ] unchanged policy with PAB on → zero writes, no PAB request,
  `pabLiftedForWrite=false`.
- [ ] new policy fails its proof with PAB on → rejects `RESTORED`; policy none;
  PAB restored to all on.
- [ ] PAB restore PUT answers 500 → rejects with `PUBLIC ACCESS BLOCK NOT
  RESTORED`; no record.
- [ ] D48: `accessKey` and `secretKey` carry `sensitive` metadata.

---

## 7. Method: cephRgwBucketVersioningEnsure

- **Safety class:** M (idempotent converge).
- **Purpose:** Converge a bucket's versioning to Enabled or Suspended, and
  report it in three states.

**Inputs:** the common S3 arguments (§1.6), plus:

| name | type | required | default | constraints | meaning |
|---|---|---|---|---|---|
| `desired` | enum | yes | – | `Enabled` or `Suspended` | Target state |

`never-configured` cannot be requested, because S3 has no way back to it. A
bucket that must stay never-configured must never be passed to this method.

**Preconditions:** the bucket exists and is owned (run `cephRgwBucketEnsure`
first).

**Behaviour**

1. Validate (§1.5). Zero requests on failure.
2. Classify presence (§1.8); refuse anything not owned. Absent → `absent` with
   a hint to run `cephRgwBucketEnsure` first.
3. `GET ?versioning` (MUST be 200, else `read`) and parse into the three states
   (§4 step 6).
4. If the state differs: `PUT ?versioning` with a `VersioningConfiguration`
   body whose `Status` is the desired state (MUST be 200, else
   `versioning-write`); re-read and
   require the desired state, else `verify`.
5. `conditionalWritesUnsafe` = final state is Enabled. When true, **log a
   warning**: on this RGW build a versioned bucket ignores `If-None-Match` and
   rejects `If-Match`, so any lock built on a conditional PUT stops excluding
   anything, including the swamp datastore's distributed lock. Such a bucket
   MUST NOT be used as a swamp datastore.
6. Write the record.

**Idempotency:** already in the desired state → zero writes,
`changed=false`.

**Output / record** (`cephRgwBucketVersioningResult`): `method`, `endpoint`,
`region`, `bucket`, `before`, `after` (three states each), `changed`,
`conditionalWritesUnsafe`, `capturedAt`.

**Post-verification:** re-read after the write.

**Failure modes**

- validation → `validate`, zero requests.
- absent, foreign, credentials-rejected, wrong-zonegroup, unreadable → that
  phase.
- write not accepted → `versioning-write`.
- re-read differs (accepted but not applied) → `verify`.
- unparseable versioning document or unknown status → `parse`.

**Security:** as §1.2; no request headers in output.

**Why**

- Measured repeatedly on a Squid 19.2.x RGW: with versioning Enabled, a second
  conditional PUT with `If-None-Match` succeeded and overwrote the object every
  time, while an unversioned bucket returned 412. Enabling versioning for
  backup reasons therefore silently disables the lock while every health check
  stays green.
- The method cannot see noncurrent versions already stored, or lifecycle
  rules. With versioning Enabled, deleted objects linger until a lifecycle
  rule removes them.

**Test obligations**

- [ ] never-configured → Enabled: exactly one versioning PUT with `Status`
  `Enabled`; key `rgwBucketVersioning-<region>-<bucket>`; before
  never-configured; after Enabled; `changed` true.
- [ ] Suspended → Suspended: zero writes, `changed` false.
- [ ] gateway answers the PUT 200 without applying it → rejects `verify`.
- [ ] Enabled → `conditionalWritesUnsafe` true plus a warning line mentioning
  `If-None-Match`. Suspended → false, no warning.
- [ ] parser: a self-closing or empty document → never-configured; Enabled and
  Suspended parse; `Paused` throws; an `Error` document throws; a namespaced
  document with a prefix parses (D53).
- [ ] absent → rejects `absent`, no writes.
- [ ] D48: `accessKey` and `secretKey` carry `sensitive` metadata.

---

## Unresolved

1. **D50 path [twin].** Which path the pinned Squid release supports is still
   to be confirmed. For Path A, no plain `radosgw-admin` user or key option is
   known to read the secret from a file or stdin; a candidate is a
   read-modify-write through `radosgw-admin metadata get` / `metadata put`
   with `-i <file>`. That replaces the whole user metadata object and needs its
   own review if chosen. For Path B, the Admin Ops arguments (`adminOpsEndpoint`,
   `adminOpsRegion`, `adminOpsAccessKey`, `adminOpsSecretKey`,
   `requestTimeoutMs`) are named here provisionally. Admin Ops carries the
   secret in the request query string, which RGW may write to its own logs at
   high debug levels.
2. **User record key scope.** `rgwUser-<uid>` is not scoped to a cluster, so
   one `cephadm` instance serving two clusters with the same uid overwrites the
   record. `rgwUser-<host>-<uid>` would match the inventory key. Decide.
3. **D52 paging shape [twin].** Confirm that `bucket list --max-entries` with
   `--marker` on the pinned release returns plain names and treats the marker
   as exclusive. Confirm too whether a truncation indicator is emitted that
   should be preferred over "short page means done".
4. **Control under RestrictPublicBuckets [twin].** Confirm that with all four
   PAB flags on, the owner's signed list still answers 200. If it does not,
   `cephRgwBucketEnsure` fails `control` on every run.
