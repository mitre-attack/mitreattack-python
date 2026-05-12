# Release Process

Releases of **mitreattack-python** are fully automated. When commits are pushed (or squash-merged) to `main`, [Python Semantic Release (PSR)](https://python-semantic-release.readthedocs.io/) analyzes the commit messages and, if warranted, bumps the version, tags the release, creates a GitHub Release, and publishes the package to PyPI — all within the [CI pipeline](https://github.com/mitre-attack/mitreattack-python/actions).

## How It Works

1. **Commit messages drive versioning.** We follow the [Conventional Commits](https://www.conventionalcommits.org) specification. PSR parses commit messages to determine the appropriate [SemVer](https://semver.org/) bump:

   | Commit prefix | Version bump | Example |
   |---|---|---|
   | `feat:` | Minor (`0.X.0`) | `feat: add analytics to excel output` |
   | `fix:`, `perf:` | Patch (`0.0.X`) | `fix: handle missing data sources` |
   | `BREAKING CHANGE` in footer, or `!` after type | Major (`X.0.0`) | `feat!: drop Python 3.10 support` |
   | `build:`, `chore:`, `ci:`, `docs:`, `style:`, `refactor:`, `test:` | No release | `ci: update uv setup action` |

2. **PRs are squash-merged.** Individual commits within a PR do not need to follow conventional commits — only the PR title matters, as it becomes the squash merge commit message. The [`pr-title.yml`](../.github/workflows/pr-title.yml) workflow validates PR titles on open.

3. **On push to `main`, the CI pipeline** (`.github/workflows/ci.yml`) runs:
   - **commitlint** — validates the squash merge commit message
   - **lint** — ruff check and format verification
   - **test** — pytest with coverage
   - **release** — PSR evaluates commits since the last tag, bumps version, tags, and creates a GitHub Release with build artifacts
   - **publish** — uploads the package to PyPI via trusted publishing (OIDC)

## For Maintainers

### Triggering a Release

No manual steps are needed. Simply merge a PR to `main` with a conventional commit title that includes a release-triggering prefix (`feat:`, `fix:`, or `perf:`). PSR will handle the rest.

### Pre-release Validation (Optional)

If you want to validate locally before merging:

```bash
# Install dependencies (including dev tools)
just install

# Lint and format
just lint

# Run tests with coverage
just test-cov

# Build the package
just build

# (Optional) Validate wheel contents
uv run check-wheel-contents dist/

# (Optional) Dry run semantic release
just release-dry-run
```

### Updating ATT&CK Version Metadata

If releasing for a new ATT&CK version, update `mitreattack-python/release_info.py` after the corresponding STIX releases are published:

- STIX 2.0 hashes come from [mitre/cti](https://github.com/mitre/cti/releases)
- STIX 2.1 hashes come from [mitre-attack/attack-stix-data](https://github.com/mitre-attack/attack-stix-data/releases)

Preview the update first:

```bash
uv run --extra dev python scripts/update_release_info.py 19.1 --dry-run
```

Apply it:

```bash
uv run --extra dev python scripts/update_release_info.py 19.1
```

The updater refreshes:

- `LATEST_VERSION`
- `STIX20["enterprise"]`, `STIX20["mobile"]`, `STIX20["ics"]`
- `STIX21["enterprise"]`, `STIX21["mobile"]`, `STIX21["ics"]`

Then verify:

```bash
uv run --extra dev ruff check scripts/update_release_info.py tests/test_release_info_updater.py mitreattack/release_info.py
```

The GitHub release assets must exist before running the updater, so this step belongs after publishing and tagging [mitre/cti](https://github.com/mitre/cti) and [mitre-attack/attack-stix-data](https://github.com/mitre-attack/attack-stix-data).

## Notes

- All build, release, and publish steps are handled by GitHub Actions — no manual tagging or uploading.
- Version is tracked in `pyproject.toml` (`project.version`) and synced to `docs/conf.py` and `mitreattack/__init__.py` by PSR.
- Documentation builds are managed by [ReadTheDocs](https://app.readthedocs.org/projects/mitreattack-python/), which watches the repository.
