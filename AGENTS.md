# pySigma Agent Instructions

These instructions apply to all AI coding agents (Claude Code, GitHub Copilot, Codex, Cursor and
others) working in this repository. `CLAUDE.md` imports this file, so keep this file as the single
source of truth.

## Project Overview

pySigma is a Python library for parsing, validating, converting and matching
[Sigma](https://github.com/SigmaHQ/sigma-specification) rules. It replaces the legacy Sigma
toolchain (sigmac). The core library is vendor-agnostic: backends and processing pipelines for
specific products live in separate projects (`pySigma-backend-*`, `pySigma-pipeline-*`) that are
discovered through the plugin system. Many of these downstream projects depend on pySigma's public
API, so API stability matters.

## Technology Stack

- **Language**: Python 3.11+ (CI tests 3.11–3.14 on Linux, Windows and macOS)
- **Package manager**: Poetry
- **Testing**: pytest, pytest-cov
- **Formatting**: black (line length 100), also run as a pre-commit hook
- **Type checking**: mypy in strict mode for the `sigma` package (see `mypy.ini`)
- **Documentation**: Sphinx (reStructuredText), hosted on ReadTheDocs

## Commands

```bash
poetry install                          # Install dependencies
poetry run pre-commit install           # Install the black pre-commit hook
poetry run pytest -m "not online"       # Run tests without network access
poetry run pytest tests/test_rule.py    # Run one test file
poetry run pytest -k some_test_name     # Run tests matching a pattern
poetry run pytest --cov=sigma           # Run tests with coverage
poetry run black .                      # Format code
poetry run mypy                         # Type-check the sigma package
cd docs && poetry run make html         # Build documentation
```

## Repository Structure

- `sigma/` – library code
  - `rule/` – Sigma rule parsing and representation (`SigmaRule`, detections, log sources)
  - `correlations.py` – correlation rules
  - `filters.py` – Sigma filters (meta filters applied to rules)
  - `collection.py` – `SigmaCollection` for loading sets of rules
  - `conditions.py`, `modifiers.py`, `types.py` – condition parsing, value modifiers, value types
  - `conversion/` – backend base classes (`TextQueryBackend`) and conversion state
  - `processing/` – processing pipelines: `transformations/`, `conditions/`, finalizers,
    postprocessing, field tracking
  - `pipelines/` – pipeline base classes, common pipeline helpers and the `test` pipeline
  - `backends/test/` – test backend used by the test suite (real backends live elsewhere)
  - `validators/` – rule validators; built-in ones are in `validators/core/`
  - `matching/` – matching of Sigma rules and correlations against events
  - `policy/` – Sigma policy profiles and regular expression engine handling
  - `plugins.py` – discovery and installation of backend/pipeline/validator plugins
  - `data/` – MITRE ATT&CK and D3FEND data (downloaded on demand and cached)
  - `exceptions.py` – all pySigma exception classes
- `tests/` – test suite (flat layout, see below), test data in `tests/files/`
- `docs/` – Sphinx documentation (`guides/`, `reference/`)
- `.claude/skills/` – agent skills (e.g. the `release` skill)

## Code Conventions

- Format with black (100 characters). Do not reformat unrelated code.
- `sigma/` is type-checked with `mypy --strict`: annotate all parameters and return values and do
  not add `# type: ignore` without a specific error code and a good reason.
- Add docstrings to public classes, methods and functions.
- Raise exceptions from `sigma/exceptions.py` (subclasses of `SigmaError`); pass a
  `SigmaRuleLocation` as `source=` where one is available so users get useful error messages.
- Use dataclasses for structured data, as the existing code does.
- Follow the existing patterns. Several components are registered by identifier, and these are the
  names used in YAML pipeline definitions and by the CLI:
  - Transformations: `transformations` in `sigma/processing/transformations/__init__.py`
  - Processing conditions: `rule_conditions`, `detection_item_conditions` and
    `field_name_conditions` in `sigma/processing/conditions/__init__.py`
  - Finalizers: `finalizers` in `sigma/processing/finalization.py`
  - Query postprocessing transformations: `query_postprocessing_transformations` in
    `sigma/processing/postprocessing.py`
  - Modifiers: `modifier_mapping` in `sigma/modifiers.py`
  - Validators in `sigma/validators/core/` are discovered automatically: the class name must end
    in `Validator`, and `NameOfCheckValidator` becomes the identifier `name_of_check`.
- Keep the core vendor-agnostic. Product-specific logic belongs in a backend or pipeline project.
- Stay compatible with the Sigma specification.
- Keep backward compatibility of the public API. Breaking changes need a major version bump (see
  `.claude/skills/release/references/version-classification.md`); prefer deprecating over removing.
- This is security-relevant software that processes untrusted input (rules, pipelines, templates).
  Never use `eval`/`exec` or unsafe YAML loading on such input, and keep template rendering
  sandboxed.

## Tests

- Every new feature and every bug fix needs tests. Test both valid input and error cases.
- Test files live directly in `tests/` and are named after the module or feature, e.g.
  `tests/test_processing_transformations.py` for `sigma/processing/transformations/`. Add tests to
  the existing file for the area before creating a new one.
- Tests must be deterministic and independent of each other. Use pytest fixtures for shared setup;
  `tests/conftest.py` mocks the MITRE ATT&CK and D3FEND data.
- Mark tests that need network access with `@pytest.mark.online`.
- Use `tests/files/` for test data files; keep data minimal and prefer inline data where it stays
  readable.
- Do not delete, skip or weaken existing tests to make a change pass.

## Documentation

- User-facing changes need documentation in `docs/` (reStructuredText). Guides are in
  `docs/guides/`, API reference pages in `docs/reference/`, which mostly use Sphinx `autodoc`, so
  docstrings are part of the documentation.
- When adding a public class (e.g. a transformation, condition or validator), add it to the
  matching reference page.
- There is no changelog file; release notes are written on GitHub releases.

## Pull Requests

- Keep changes focused and minimal.
- Include tests and documentation updates as described above.
- Describe breaking changes explicitly.

## Validation Before Finishing

Before completing any task, run these checks and fix any issues they report:

1. `poetry run black .` (CI runs `poetry run black --check .`)
2. `poetry run mypy`
3. `poetry run pytest -m "not online"`

Do not consider a task done until all three pass.
