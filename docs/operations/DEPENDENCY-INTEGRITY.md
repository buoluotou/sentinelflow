# Dependency Integrity

What is pinned, what is hashed, what is audited, and what is none of those.
Figures come from the repository and the Docker Hub registry API on 2026-09-11.

## Python dependencies

`backend/requirements/base.lock` and `backend/requirements/dev.lock` pin exact
versions. Both carry the generator command in the header:

```
uv pip compile backend/requirements/base.txt --universal --python-version 3.12 -o backend/requirements/base.lock
uv pip compile backend/requirements/dev.txt  --universal --python-version 3.12 -o backend/requirements/dev.lock
```

`base.lock` pins 29 packages, `dev.lock` pins 48. The Docker build installs
`base.lock`; CI installs `dev.lock` for the test jobs, `base.lock` for migration.

Per-artifact hashes are not verified: neither lock file has a hash column, and
nothing installs with `pip --require-hashes` — not the Dockerfile, not CI. An
install trusts whatever the index serves for a pinned version. The reason is the
`--universal` flag: one lock covers every platform and Python ABI the project
targets, so the Linux image build and a Windows developer machine install from the
same file. Hashes are per wheel, so `--require-hashes` would need one lock per
platform and ABI. The project kept the single lock.

## npm dependencies

`frontend/package-lock.json` is lockfileVersion 3. All 185 `resolved` entries
carry an `integrity` field, all of them `sha512`, and all 185 `resolved` URLs
point at `https://registry.npmjs.org/`. No `.npmrc` is committed. `npm ci` in CI
and in the frontend Dockerfile installs from this lock and verifies those hashes.

## SBOM

Two CycloneDX files are checked into `artifacts/sbom/`. Both were generated on
2026-09-11, and CI does not regenerate them: `.github/workflows/ci.yml` has no SBOM
step.

`python-base.cdx.json` — CycloneDX 1.6, from `cyclonedx-py` 7.3.1: 29 components,
one per line of `base.lock`, each with a name, version and `pkg:pypi/...` purl.
No component carries hashes.

`npm-frontend.cdx.json` — CycloneDX 1.5, from the npm CLI 11.16.0: 158 components
and 159 dependency edges, all 158 carrying a SHA-512 hash and a `pkg:npm/...`
purl. Its 158 distribution references point at `registry.npmmirror.com` while
`package-lock.json` points only at `registry.npmjs.org`, because the SBOM came from
a `node_modules` tree installed through the mirror. Regenerating it after a clean
`npm ci` would align the two.

## CI enforcement

The `security` job in `.github/workflows/ci.yml` runs:

- `pip-audit -r backend/requirements/base.lock --progress-spinner off`, with no
  `|| true`, so any advisory fails the job. `base.lock` is the only lockfile
  audited; `dev.lock` is not covered by CI.
- `npm audit --json` in `frontend`, parsed by an inline script that exits 1 when
  `high > 0` or `critical > 0`. Medium and low counts are printed, not blocking.

Both compare versions against advisory databases and neither verifies a hash.

## Container images

No image reference is digest-pinned. The tags in use, with the digests the registry
served on 2026-09-11 for `linux/amd64`:

| Reference | Used in | Manifest-list digest | `linux/amd64` digest |
|---|---|---|---|
| `postgres:16-alpine` | `docker-compose.yml`, CI service containers | `sha256:cf78e76683b9ca8c5733cbbdce6c9262b45b6767934dd0a95e671f9a0fc20685` | `sha256:075f7ba66bc9b3ce7d6b8b635208ff61cd7cf1a67d71ec530eec5d7ae0cbe571` |
| `python:3.12-slim` | `backend/Dockerfile` | `sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea` | `sha256:2fe5997d249a808b8eeea52c58a1dbffbba28754dc11699ef5c029f2d818ce79` |
| `nginx:1.27-alpine` | `frontend/Dockerfile` | `sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10` | `sha256:62223d644fa234c3a1cc785ee14242ec47a77364226f1c811d2f669f96dc2ac8` |
| `node:22-alpine` | `frontend/Dockerfile` build stage | `sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32` | `sha256:76789712cd1ae89a1225eac9077010d68987a423588042dac30446f502f1858c` |
| `ollama/ollama:0.34.0` | `docker-compose.yml`, optional profile | `sha256:684d8674b4315fa18f4f0e973a118ec2652ed96f67563277839985175858e0ba` | `sha256:aa6f86f01fee264c81f1edd9083ebfb07c8116d95d8bedd1ad470874b66a40b4` |

Tags move: `postgres:16-alpine` was last republished 2026-08-16, `python:3.12-slim`
on 2026-09-02, and `nginx:1.27-alpine` has not moved since 2025-04-16.

Two things were not verified: image signatures and provenance attestations were not
checked, so nothing here says the published images are the ones the upstream projects
built; and the GitHub releases API returned HTTP 403 from this network, so the Ollama
version was confirmed through the registry tag list only.

## Pinning process

The project does not pin digests today. When one is recorded, record the tag, the
manifest-list digest, the platform and the date: a digest without a platform is
ambiguous, and one without a date cannot be reviewed later. Refresh a digest when the
tag it tracks is updated on purpose and the stack re-tested, not on every upstream
republish — leaving it fixed is the point, and moving it deserves the same review.
