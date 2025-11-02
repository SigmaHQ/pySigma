---
applies_to:
  - tests/
---

# Instructions for tests/ Directory

When adding or modifying tests:

## Test Structure

- Follow the naming convention: `test_<module_name>.py`
- Test files should mirror the structure of the `sigma/` directory
- Group related tests in classes when it makes sense
- Use descriptive test function names that explain what is being tested

## Test Best Practices

- Each test should test one specific behavior
- Tests should be independent and can run in any order
- Use fixtures from pytest for shared setup
- Mock external dependencies and file system operations
- Mark network-dependent tests with `@pytest.mark.online`

## Running Tests

```bash
poetry run pytest                    # Run all tests
poetry run pytest tests/test_foo.py  # Run specific test file
poetry run pytest -k test_name       # Run tests matching pattern
poetry run pytest -x                 # Stop at first failure
poetry run pytest --cov=sigma        # Run with coverage
```

## Coverage

- Aim for high test coverage of new code
- Run coverage reports to identify untested code paths
- Don't remove or skip existing tests without good reason

## Test Data

- Use `tests/files/` directory for test data files when needed
- Keep test data minimal and focused
- Use inline test data when possible for clarity

## Assertions

- Use clear, specific assertions
- Include helpful error messages in assertions
- Test both positive and negative cases
- Test edge cases and error conditions
