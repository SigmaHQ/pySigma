# pySigma Copilot Instructions

## Project Overview

pySigma is a Python library for parsing and converting Sigma rules into queries. It replaces the legacy Sigma toolchain (sigmac) with a cleaner design that is fully tested. The project is vendor-agnostic, with backends and processing pipelines separated into dedicated projects.

## Technology Stack

- **Language**: Python 3.9+
- **Package Manager**: Poetry
- **Testing**: pytest with pytest-cov for coverage
- **Linting**: black (line length: 100), pylint
- **Type Checking**: mypy
- **Pre-commit**: Configured with black
- **Documentation**: Sphinx

## Development Workflow

### Setup
```bash
poetry install
poetry run pre-commit install
```

### Testing
```bash
poetry run pytest                    # Run all tests
poetry run pytest --cov=sigma        # Run with coverage report
poetry run pytest -x                 # Stop at first failure
```

### Linting and Formatting
```bash
poetry run black .                   # Format code
poetry run black --check .           # Check formatting
```

### Building
```bash
poetry build
```

## Code Style and Standards

- Follow PEP 8 with black's formatting (100 character line length)
- Use type hints where appropriate
- Write comprehensive tests for new features
- Maintain test coverage
- Update documentation for user-facing changes
- Run pre-commit hooks before committing

## Key Project Structure

- `sigma/` - Main library code
  - `backends/` - Backend implementations
  - `conversion/` - Conversion logic
  - `processing/` - Processing pipelines
  - `pipelines/` - Pipeline implementations
  - `rule/` - Sigma rule parsing and representation
  - `validators/` - Rule validation logic
- `tests/` - Test suite
- `docs/` - Sphinx documentation

## Important Considerations

- This is a security-focused library - code quality and correctness are critical
- Changes should maintain backward compatibility when possible
- All public APIs should be well-documented
- Security implications of changes should be carefully considered
- The project is in release candidate status but is actively used

## Testing Requirements

- Write tests for all new functionality
- Ensure tests are deterministic and don't rely on external resources (mark network tests with `@pytest.mark.online`)
- Follow existing test patterns and structure
- Tests should be clear and maintainable

## Pull Request Guidelines

- Keep changes focused and minimal
- Include tests for new features or bug fixes
- Update documentation if changing user-facing behavior
- Ensure all tests pass locally before submitting
- Run linters and formatters before committing
