# Contributors

## Reporting Issues

If you encounter an issue with the `mitreattack-python` library, please let us know by filing a [GitHub issue](https://github.com/mitre-attack/mitreattack-python/issues). When doing so, please make sure you provide the following information:

- Describe (in as much detail as possible) what occurred and what you were expecting to occur. Any information you can provide, such as stack traces or errors, is very helpful.
- Describe the steps necessary to replicate the issue.
- Indicate your OS and Python versions.

## Suggested New Features

If you have an idea for a new feature for `mitreattack-python`, please let us know by filing a [GitHub issue](https://github.com/mitre-attack/mitreattack-python/issues). When doing so, please make sure you provide the following information:

- Explain the functionality you are proposing, and its use case — what would it be useful for or allow you to do?
- List what existing ATT&CK tools or resources map to the proposed functionality.
- If applicable, provide examples of other requests for the proposed functionality.

## Developing

We welcome pull requests! To set up a local development environment:

### Prerequisites

- [Python 3.11+](https://www.python.org/downloads/)
- [uv](https://docs.astral.sh/uv/getting-started/installation/) — fast Python package manager
- [just](https://github.com/casey/just#installation) — command runner (optional, but recommended)

### Setup

```bash
# Clone the repository
git clone https://github.com/mitre-attack/mitreattack-python
cd mitreattack-python

# Install all dependencies (including dev and docs extras)
just install
# or without just:
uv sync --all-extras

# (Optional) Install pre-commit hooks for local linting and commit message validation
just setup-hooks
# or without just:
uv run pre-commit install
uv run pre-commit install --hook-type commit-msg
```

### Common Commands

Run `just` with no arguments to see all available commands. Here are the most common ones:

```bash
just lint          # Run pre-commit hooks (ruff format) on all files
just test          # Run tests
just test-cov      # Run tests with coverage report
just build         # Build the package
```

### Pull Requests

When making a pull request, please make sure to:

- Include a summary of what the changes are intended to do and the testing performed to validate them (ideally in the form of new pytests in the `tests/` collection, though this is not strictly required).
- **Use a [Conventional Commits](https://www.conventionalcommits.org) formatted PR title** (e.g., `feat: add new export format`, `fix: handle missing data sources`). PRs are squash-merged, so the PR title becomes the merge commit message — individual commit messages within the PR do not need to follow any convention.
- All pytest tests in `tests/` must pass, and ruff linting/formatting checks must be clean.
