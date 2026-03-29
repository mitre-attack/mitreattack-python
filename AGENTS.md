# Repository Guidelines

## Project Structure & Module Organization

- Core package code lives in `mitreattack/`.
- Major submodules include `stix20/` (data access), `navlayers/` (Navigator layer helpers/exporters), `diffStix/`, `attackToExcel/`, and `collections/`.
- Tests live in `tests/`, with focused suites like `tests/changelog/` and fixtures in `tests/resources/`.
- User-facing examples are in `examples/`; docs sources are in `docs/`.
- Build and dependency configuration is in `pyproject.toml`, `uv.lock`, and `justfile`.

## Build, Test, and Development Commands

- `just install`: install all dependencies (dev + docs) via `uv sync --all-extras`.
- `just setup-hooks`: install `pre-commit` hooks (including commit message validation).
- `just lint`: run pre-commit hooks across the repo.
- `just test`: run the pytest suite.
- `just test-cov`: run tests with coverage for `mitreattack`.
- `just build`: build distributions with `uv build`.
- Without `just`, run the same tools through `uv run ...`.

## Coding Style & Naming Conventions

- Python 3.11+ is required.
- Use Ruff for formatting and linting (`uv run ruff format`, `uv run ruff check`).
- Ruff line length is 120; docstring style follows NumPy convention.
- Use 4-space indentation, `snake_case` for functions/modules, `PascalCase` for classes, and descriptive test names.

## Testing Guidelines

- Framework: `pytest` (with `pytest-cov` for coverage checks).
- Place tests under `tests/` and name files/functions `test_*.py` / `test_*`.
- Add or update tests for behavior changes, especially around STIX parsing and changelog/diff output paths.
- Run `just test` locally before opening a PR; use `just test-cov` for larger changes.

## Commit & Pull Request Guidelines

- PR titles must follow Conventional Commits (squash merge uses PR title as commit message).
- Release-triggering types: `feat`, `fix`, `perf`; other allowed types include `docs`, `test`, `ci`, `chore`, `refactor`, `style`, `build`, `revert`.
- Keep PRs focused; include a clear summary and validation steps (commands run, tests added/updated).
- Link related issues and include output/examples when behavior or CLI output changes.
