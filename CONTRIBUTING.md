# Contributing

Thank you for your interest in contributing to cuhepy!

## Getting Started

1. **Fork** the repository on GitHub
2. **Clone** your fork:
   ```bash
   git clone https://github.com/<your-username>/cuhepy.git
   cd cuhepy
   ```
3. **Install** dependencies (requires Python 3.11+):
   ```bash
   uv sync --all-groups
   ```

## Branch Workflow

- **`main`** — stable, release-ready code. All PyPI publishes come from here.
- **`staging`** — integration branch for testing before merging to main.

**To contribute:**

1. Create a feature branch from `main`
2. Open a PR targeting `staging` (or `main` for hotfixes)
3. PRs require passing CI checks and at least 1 approval
4. PRs to `main` are squash-merged to keep a linear history

## Running Tests

```bash
uv run pytest tests/
```

The whole suite runs offline. Tests for the compiled backends skip automatically when the extensions are not built.

## Code Style

This project uses [ruff](https://docs.astral.sh/ruff/) for linting and [mypy](https://mypy-lang.org/) for static type checking:

```bash
uv run ruff check src/cuhepy/
uv run mypy src/cuhepy/
```

Both must pass with no errors before submitting a PR.

## Pull Requests

- Keep changes focused — one concern per PR
- Add or update tests for any changed behaviour
- Do not commit key files, `.so` artifacts, or any credentials
- Update `CHANGELOG.md` under an `[Unreleased]` heading

## Reporting Issues

Open an issue on GitHub with a minimal reproducible example.

## Reporting a weakness

Findings against the schemes are the point of this repository. Open an issue
with a runnable demonstration where you can, and we will add it to `attacks/`
alongside the existing ones.
