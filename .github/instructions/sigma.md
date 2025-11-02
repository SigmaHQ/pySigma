---
applies_to:
  - sigma/
---

# Instructions for sigma/ Directory

This directory contains the core pySigma library code. When making changes here:

## Code Quality

- Maintain consistent code style using black with 100 character line length
- Use type hints for all function parameters and return values
- Add docstrings to all public classes and methods
- Follow existing patterns and conventions in the codebase

## Architecture

- Keep the core library vendor-agnostic
- Backends should be in separate packages, not in core
- Processing pipelines should be modular and composable
- Use exceptions from `sigma/exceptions.py` for error handling

## Testing

- Write comprehensive unit tests for all new functionality
- Place tests in `tests/` directory following the naming convention `test_<module>.py`
- Ensure tests are isolated and don't depend on external resources
- Mock external dependencies when necessary

## Type Safety

- Run mypy to ensure type correctness: `poetry run mypy`
- Fix any type errors before submitting changes
- Use proper type annotations from the `typing` module

## Common Patterns

- Use dataclasses for structured data where appropriate
- Follow the existing pattern for conditions, modifiers, and transformations
- Maintain compatibility with the Sigma rule specification
- Consider performance implications for rule processing operations
