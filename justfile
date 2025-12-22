# Default recipe to list all available commands
default:
    @just --list

# Install development dependencies
install:
    uv sync --all-extras

# Install pre-commit hooks
setup-hooks:
    uv run pre-commit install
    uv run pre-commit install --hook-type commit-msg

# Run pre-commit hooks on all files
lint:
    uv run pre-commit run --all-files

# Run ruff linter
ruff-check:
    uv run ruff check

# Run ruff formatter check
ruff-format-check:
    uv run ruff format --check

# Run ruff formatter (fix)
ruff-format:
    uv run ruff format

# Run tests
test:
    uv run pytest

# Run tests with coverage
test-cov:
    uv run pytest --cov=mitreattack

# Check commit messages in range (default: last commit)
check-commits rev-range="HEAD~1..HEAD":
    uv run cz check --rev-range {{ rev-range }}

# Dry run semantic release (no changes)
release-dry-run:
    uv run semantic-release -v --noop version

# Build the package
build:
    uv build

# Clean build artifacts
clean:
    rm -rf dist/ build/ *.egg-info/
