# Contributing to subnet-info-cli

Thanks for contributing.

## Development setup

```bash
git clone https://github.com/nithin0x/subnet-info-cli.git
cd subnet-info-cli
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip build
```

Run locally:

```bash
PYTHONPATH=src python -m subnet_info.main
```

## Code guidelines

- Keep changes small and focused.
- Preserve CLI output format unless the change intentionally updates UX.
- Use explicit error handling (avoid broad `except Exception`).
- Add or update type hints for new/changed functions.

## Pull request guidelines

- Create a feature branch from `main`.
- Include a clear title and summary of what changed and why.
- Reference related issue(s), if any.
- Verify the CLI still runs successfully before opening the PR.

## Release guidelines

Versioning is in `pyproject.toml`.

Build:

```bash
python -m build
```

Create GitHub release with assets:

```bash
gh release create vX.Y.Z dist/* -t "vX.Y.Z" -n "Release notes"
```
