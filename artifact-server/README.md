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

## Safety

Every destructive method enforces its own preconditions in the method, so a
workflow resume with overridden inputs cannot skip a gate:

- `install` reads the previous site file first; a failed `nginx -t` restores it
  and never reloads. The generated config disables autoindex and symlink
  following and denies dotfiles and `refs/`.
- `upload` refuses when the computed hash differs from a supplied `sha256`.
- `fetch` keeps the download in a hidden temp file until the host-side hash
  matches the pin; a mismatch removes the temp and changes nothing.
- `prune` recomputes the plan and refuses when it differs from `plan_sha256`; a
  change since planning deletes nothing.
- `uninstall` is a clean no-op when the site is absent and never removes the
  nginx package.

`SHA256SUMS` is rebuilt under an exclusive `flock` from the blobs actually
present, written to a same-directory temp file and renamed into place. No
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
