---
applies_to:
  - docs/
---

# Instructions for docs/ Directory

When working with documentation:

## Documentation Framework

- pySigma uses Sphinx for documentation
- Documentation is built and hosted on ReadTheDocs
- Configuration is in `.readthedocs.yaml`

## Building Documentation

```bash
cd docs
poetry run make html
```

## Documentation Standards

- Write clear, concise documentation for end users
- Include code examples where appropriate
- Keep documentation up-to-date with code changes
- Use proper reStructuredText formatting

## What to Document

- All public APIs (classes, functions, methods)
- Usage examples and tutorials
- Architecture and design decisions
- Migration guides for breaking changes

## Documentation Structure

- Keep documentation organized by topic
- Use consistent formatting and style
- Link to related sections where relevant
- Include a table of contents for longer documents

## API Documentation

- Document all parameters and return values
- Include type information
- Provide usage examples
- Note any exceptions that can be raised
- Mention related classes or functions

## Updating Documentation

When making code changes that affect the public API:
1. Update relevant docstrings in the code
2. Update user-facing documentation in `docs/`
3. Add examples if introducing new features
4. Update the changelog if applicable
