# Release Process

This guide walks maintainers through releasing a new version of **mitreattack-python**.
The process uses [Poetry](https://python-poetry.org/) for dependency management and building,
and [GitHub Actions](https://github.com/mitre-attack/mitreattack-python/actions) for automated linting, testing, and publishing to PyPI.

## 1. Prepare for Release

- Ensure all desired changes are merged into the `main` branch.
- If releasing for a new ATT&CK version, update `LATEST_VERSION` in `mitreattack/release_info.py`.

## 2. Update Version and Metadata

- Run `cz bump --files-only`
  - This will increment the version field in `pyproject.toml` and other places according to semantic versioning rules.
  - It will also update the `CHANGELOG.md` with all commit messages that are compatible with [Conventional Commits](https://www.conventionalcommits.org).
  - NOTE: You should double-check the generated `CHANGELOG.md` file and make sure it looks good.
- Update other metadata as needed in `pyproject.toml` (dependencies, etc.).
  - `poetry update --with dev --with docs`

## 3. Local Validation (Recommended)

Before tagging and pushing, validate the release locally. Following these steps:

```bash
# Pre-requisite: Install Poetry if not already installed
# https://python-poetry.org/docs/#installing-with-the-official-installer
curl -sSL https://install.python-poetry.org | python3 -

# Clean previous builds
rm -rf dist/

# Install dependencies (including dev tools)
poetry install --with=dev

# Lint and format
poetry run ruff check
poetry run ruff format --check

# Build docs
# This is managed directly by the Readthedocs site which is configured to watch our repository, but we should test it locally too
# https://app.readthedocs.org/projects/mitreattack-python/
cd docs/
poetry run python -m sphinx -T -b html -d _build/doctrees -D language=en . _build/html
cd ..

# Run tests
poetry run pytest --cov=mitreattack --cov-report html

# Build the package
poetry build

# (Optional) Validate wheel contents
poetry run check-wheel-contents dist/

# (Optional) Install locally and smoke test
poetry run pip install --find-links=./dist mitreattack-python
poetry run python -c "import mitreattack; print(mitreattack.__version__)"
```

## 4. Commit and Tag the Release

Make sure that after the above local testing you commit all changes!

Perform the following steps to tag the release and push to GitHub:

```bash
# Tag the release
git tag -a "vX.Y.Z" -m "mitreattack-python version X.Y.Z"

# Push the commit and tag
git push
git push --tags
```

## 5. Automated Publishing

Once the tag is pushed to GitHub:

- GitHub Actions will automatically lint, test, build, and publish the package to PyPI using the workflow in `.github/workflows/lint-publish.yml`.

## 6. Verify Release

Check the [GitHub Actions](https://github.com/mitre-attack/mitreattack-python/actions) for a successful workflow run.

Confirm the new version is available on [PyPI](https://pypi.org/project/mitreattack-python/).

## Notes

- All build and publish steps are handled by GitHub Actions once you push the tag.
- Manual local validation is optional but recommended before tagging.
- Readthedocs is used for documentation builds. [Check the status here](https://app.readthedocs.org/projects/mitreattack-python/).
