# @randybias/artifact-server

Serve a directory of **pinned artifacts over HTTP(S)** from one host, and manage
that directory over SSH.

The model is generic. It holds no host, path or credential in its definition;
every method takes its SSH target and served `root` as arguments, and stored
data is keyed by the canonical target plus root. Consumers fetch bytes by
content hash, so the server is a cache, not a source of trust.

The served tree is the interface: `SHA256SUMS` at the root, immutable blobs
under `sha256/<hash>/<name>`, immutable bundles under `bundles/<tree-hash>/`,
and a control-only `refs/` directory that is never served. A daemon swap that
keeps this layout does not change a single URL.

## Requirements

- A Debian/Ubuntu host with passwordless `sudo` for the login user.
- `nginx` on the target (this model installs it if missing); `flock`, `find`,
  `sha256sum`, `curl` and `openssl` on the target as used.
- The target's SSH host keys, pinned as `ssh-keyscan` lines. Trust-on-first-use
  is not offered: `host_key_policy` is `strict` and `host_keys` is required.
- A private key or password supplied per call from a vault reference. Both are
  marked sensitive and never appear in state, logs or fixtures.

## Methods

| Method           | Kind      | What it does                                                                                                             |
| ---------------- | --------- | ------------------------------------------------------------------------------------------------------------------------ |
| `render_config`  | read-only | Render the nginx site config and persist it. Deterministic.                                                              |
| `install`        | action    | Install nginx, create the layout, write the site, htpasswd and TLS files, prove the config with `nginx -t`, then reload. |
| `upload`         | action    | Push bytes to `sha256/<hash>/<name>` over stdin, refuse a hash mismatch, regenerate `SHA256SUMS`, optionally set a ref.  |
| `fetch`          | action    | Download one https URL on the host, compare the host's SHA-256 to the required pin, and only then move it into place.    |
| `publish_bundle` | action    | Write named files under `bundles/<tree-hash>/`.                                                                          |
| `ref`            | action    | Point a named ref at a blob or bundle.                                                                                   |
| `unref`          | action    | Remove a named ref; a no-op when absent.                                                                                 |
| `list`           | read-only | Read refs, blobs and bundles with sizes and mtimes.                                                                      |
| `verify`         | read-only | Rehash every object and compare against `SHA256SUMS`.                                                                    |
| `get` / `sync`   | read-only | Observe nginx state and the layout summary.                                                                              |
| `plan_prune`     | read-only | List objects no ref or `keep` entry reaches, with a plan hash.                                                           |
| `prune`          | action    | Delete exactly the objects of a plan whose hash is unchanged.                                                            |
| `uninstall`      | action    | Remove the site and reload nginx; optionally remove the root.                                                            |

Read-only methods persist their observation as a resource (`config`, `server`,
`listing`, `verification`, `prune_plan`). Mutating methods that store an object
persist an `artifact` resource.

### Inline upload size

`upload` carries bytes through swamp, which holds the payload in memory before
the method runs. Its cap is therefore **128 MiB** (`max_upload_bytes`, default
64 MiB); a larger value is refused by the schema. Artifacts larger than that
must use the host-side pinned **`fetch`**, which downloads on the target and
never puts the bytes on the control host.

## Safety

Every destructive method enforces its own preconditions in the method, so a
workflow resume with overridden inputs cannot skip a gate:

- The served `root` must have at least two segments and may not be a bare system
  directory. `install` refuses a populated root that holds no regular
  `.layout-version` sentinel, and `uninstall` only removes a root that is a real
  directory holding that sentinel.
- `install` never lets the package default site come up: it blocks service
  starts (`policy-rc.d` and a systemd mask) while the package is installed, and
  only then writes the managed config and the enabled link. After starting or
  reloading it checks with `ss` that nginx added no wildcard listener on a port
  the install did not configure.
- `install` snapshots the site file, the enabled link, the default site, the TLS
  files and the htpasswd before it changes anything. Any failure after the
  snapshots restores all of them, removes a first-install enabled link and a
  root the model created, checks every restore exit code, and re-runs `nginx -t`
  to prove the restored config is clean before reporting.
- The generated config disables autoindex and symlink following and denies
  dotfiles at the root and inside `sha256/` and `bundles/`, so in-flight upload
  temp files are never served.
- Object paths read back from the host must match `sha256/<64-hex>/<name>` or
  `bundles/<64-hex>`; anything else is ignored. `prune` refuses to run when
  `sha256/`, `bundles/` or a hash directory is a symlink, so a planted link
  cannot redirect `rm` outside the root, and it removes a hash directory once
  its last blob is gone.
- `upload` refuses when the computed hash differs from a supplied `sha256`, and
  caps inline content at 128 MiB; larger artifacts use `fetch`.
- `fetch` is idempotent (a present object is not downloaded again), stays on
  `https` across at most five redirects, is size-bounded, and keeps the download
  in a hidden temp file until the host-side hash matches the pin.
- `prune` recomputes the plan and refuses when it differs from `plan_sha256`; a
  change since planning deletes nothing.
- `uninstall` is a clean no-op when the site is absent, removes the site's TLS
  files and htpasswd, restores the default site `install` removed, and never
  removes the nginx package.

`SHA256SUMS` is rebuilt under an exclusive `flock` from the blob paths present
and renamed into place: each line records the content address in the path, not a
re-read of the bytes. `verify` re-hashes every object and reports a mismatch
when the actual hash differs from the path hash or from the recorded value. No
content-derived digest is sent to the host for verification, and no secret is
placed on a command line.

## Layout contract

```
<root>/
  SHA256SUMS            # sha256sum -c format, one "<hex>  <path>" per blob
  .layout-version       # layout version, currently 1
  .lock                 # flock target for SHA256SUMS regeneration
  sha256/<hash>/<name>  # immutable blobs
  bundles/<tree-hash>/  # immutable bundle directories
  refs/<name>           # control-only; denied by the site config
```

The bundle tree hash is the SHA-256 of the bundle's sorted `<sha256>  <name>`
lines, the same rendering used for the top-level index.

## Example

```yaml
# Definitions take no arguments; wire values in per call.
model: artifact-server
```

Calls supply the transport and root, for example an `upload` with a vault
reference for the private key and for the content:

```json
{
  "ssh": {
    "host": "cdn01.example.test",
    "user": "deploy",
    "host_key_policy": "strict",
    "host_keys": ["cdn01.example.test ssh-ed25519 AAAA..."]
  },
  "root": "/srv/artifacts",
  "filename": "release.tar.gz",
  "content": "${{ vault.get('artifacts', 'release-tar-gz') }}",
  "ref": "stable"
}
```

## License

Apache-2.0. See `LICENSE.txt`.
