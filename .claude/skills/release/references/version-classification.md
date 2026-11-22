# Version Classification Guide

Rules for determining whether a change warrants a patch, minor, or major version bump in pySigma.

## Major (breaking)

A change is **major** if it breaks backward compatibility for users or backend/pipeline developers:

- Removing or renaming a public class, function, method, or attribute
- Changing the signature of a public method in a backward-incompatible way (removing parameters, changing parameter types)
- Changing the default behavior of existing functionality
- Removing or renaming items from public enums
- Changing return types of public methods
- Removing support for a previously supported Sigma rule feature
- Restructuring the package in a way that breaks existing imports

## Minor (new functionality)

A change is **minor** if it adds new, backward-compatible functionality:

- Adding new public classes, methods, functions, or attributes
- Adding new parameters with default values to existing methods
- Adding new enum values
- Adding new modifiers, conditions, or transformations
- Adding new validators
- Supporting new Sigma rule features or fields
- Adding new base class hook methods with default no-op implementations
- Adding new exceptions (that existing code won't raise by default)

## Patch (fixes and improvements)

Everything else is a **patch**:

- Bug fixes
- Performance improvements
- Documentation updates
- Test additions or fixes
- CI/CD changes
- Dependency updates (that don't change the public API)
- Internal refactoring that doesn't affect the public API
- Fixing type hints or type annotations
- Code formatting changes

## Signals in Commit Messages and PR Titles

Look for these keywords (case-insensitive) to help classify:

| Keyword / Pattern | Likely Bump |
|---|---|
| `BREAKING`, `breaking change` | major |
| `remove`, `drop support`, `deprecate and remove` | major |
| `rename` (public API) | major |
| `feat`, `feature`, `add`, `new`, `support` | minor |
| `implement` (new capability) | minor |
| `fix`, `bug`, `patch`, `correct` | patch |
| `docs`, `documentation`, `typo` | patch |
| `refactor`, `cleanup`, `internal` | patch |
| `ci`, `test`, `build`, `deps` | patch |

## Edge Cases

- **Deprecation without removal**: minor (adding a deprecation warning is new behavior, but not breaking)
- **Adding a required parameter to `__init__`**: major (breaks existing instantiation)
- **Adding an optional parameter to `__init__`**: minor
- **Changing error messages**: patch (not part of the API contract)
- **Making a previously private method public**: minor
- **Fixing a bug that some users may depend on**: use judgment — if the buggy behavior was clearly wrong, patch; if it was ambiguous, consider minor
