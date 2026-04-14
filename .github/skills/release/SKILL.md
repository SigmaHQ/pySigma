---
name: release
description: "Automate the pySigma release process: analyze changes, determine version bump, update version, tag, push, wait for test PyPI, generate release notes, and create GitHub release. Use when: releasing pySigma, creating a new version, publishing to PyPI, version bump, cut a release."
argument-hint: "Optional: specify patch, minor, or major to skip auto-detection"
---

# pySigma Release

Automates the full release lifecycle for SigmaHQ/pySigma.

## Prerequisites

- `gh` CLI must be installed and authenticated (`gh auth status`)
- Working directory must be the pySigma repository root
- Local `main` branch must be up to date with remote
- No uncommitted changes

## Procedure

Follow these steps **sequentially**. Each step requires user confirmation before proceeding to the next.

### Step 1: Pre-flight Checks

1. Run `git status` to confirm clean working tree and correct branch (`main`).
2. Run `git fetch github` then `git status` to confirm local main is up to date.
3. Run `gh auth status` to confirm GitHub CLI is authenticated.
4. If any check fails, inform the user and stop.

### Step 2: Determine Current Version and Last Release

1. Read the current version from `pyproject.toml` (the `version` field under `[project]`).
2. Use `mcp_github_get_latest_release` (owner: `SigmaHQ`, repo: `pySigma`) to get the latest release tag and its publication date.
3. Store the latest release tag (e.g., `v1.3.0`) and date for later steps.

### Step 3: Analyze Changes Since Last Release

1. Run `git log <last_release_tag>..HEAD --oneline` to get all commits since the last release.
2. Use `mcp_github_search_pull_requests` to find merged PRs since the last release date:
   - query: `merged:>=<YYYY-MM-DD> base:main`
   - owner: `SigmaHQ`, repo: `pySigma`
   - sort: `created`, order: `asc`
   - Paginate if needed to get all results.
3. Classify each change using the [version classification guide](./references/version-classification.md).
4. Determine the highest applicable bump level:
   - Any **major** change → major bump
   - Else any **minor** change → minor bump
   - Else → patch bump

### Step 4: Propose Version Bump

Present to the user:
- **Current version**: (from pyproject.toml)
- **Proposed bump**: patch / minor / major
- **Proposed new version**: X.Y.Z
- **Change summary** organized by category:
  - **Breaking changes** (if any)
  - **New features** (if any)
  - **Bug fixes / improvements**
  - **Other** (documentation, CI, refactoring)

Ask the user to **confirm** the proposed version or **override** with a different bump level. If the user provided a bump level as an argument, use it and ask for confirmation instead.

### Step 5: Bump Version in pyproject.toml

1. Run in terminal: `poetry version <new_version>` (use the exact version number, e.g., `poetry version 1.4.0`).
2. Verify the change: `poetry version -s` should print the new version.
3. Commit the version bump:
   ```
   git add pyproject.toml
   git commit -m "Bump version to <new_version>"
   ```
4. **Ask the user for confirmation** before pushing.
5. Push the commit: `git push github main`.

### Step 6: Create and Push Version Tag

1. Create an annotated tag: `git tag -a v<new_version> -m "Release v<new_version>"`.
2. Push the tag: `git push github v<new_version>`.
3. Inform the user: "Tag `v<new_version>` pushed. This triggers the test PyPI deployment via GitHub Actions."

### Step 7: Wait for Test PyPI Deployment

1. Monitor the workflow run triggered by the tag push:
   ```
   gh run list --workflow=release.yml --limit=1
   ```
2. Check the status of the latest run:
   ```
   gh run watch <run_id>
   ```
   Alternatively, poll with:
   ```
   gh run view <run_id> --json status,conclusion
   ```
3. If the run **fails**, inform the user with the failure details (`gh run view <run_id> --log-failed`) and **stop the release process**. The user must fix the issue before continuing.
4. If the run **succeeds**, inform the user and proceed.

### Step 8: Generate Release Notes

Compose release notes in Markdown with the following structure:

```markdown
## What's Changed

### Breaking Changes
- Description (PR #N)

### New Features
- Description (PR #N)

### Bug Fixes
- Description (PR #N)

### Other Changes
- Description (PR #N)

**Full Changelog**: https://github.com/SigmaHQ/pySigma/compare/<old_tag>...v<new_version>
```

Rules for generating notes:
- Use PR titles and descriptions as the primary source for each entry.
- Link each entry to its PR: `(#N)` where N is the PR number.
- Omit empty sections.
- If a PR addresses a GitHub issue, mention it: `Fixes #N`.
- Keep entries concise — one line per change.

Present the draft to the user and let them **review and amend** the release notes before proceeding.

### Step 9: Create GitHub Release

1. **Ask the user for final confirmation** before creating the release.
2. Create the release:
   ```
   gh release create v<new_version> --title "v<new_version>" --notes "<release_notes>"
   ```
   If notes are long, write them to a temp file and use:
   ```
   gh release create v<new_version> --title "v<new_version>" --notes-file <tempfile>
   ```
3. Inform the user: "GitHub release created. This triggers the production PyPI deployment."
4. Provide the release URL: `https://github.com/SigmaHQ/pySigma/releases/tag/v<new_version>`

### Step 10: Post-Release Verification

1. Check the production PyPI workflow:
   ```
   gh run list --workflow=release.yml --limit=1
   ```
2. Once completed, verify the package is available:
   ```
   pip index versions pySigma
   ```
   Or direct the user to: `https://pypi.org/project/pySigma/<new_version>/`

## Error Recovery

- **Version bump pushed but tag failed**: Create and push the tag manually.
- **Test PyPI failed**: Fix the issue, delete the tag (`git push --delete github v<new_version> && git tag -d v<new_version>`), amend or re-commit, and restart from Step 6.
- **Release creation failed**: Retry `gh release create` or create manually at `https://github.com/SigmaHQ/pySigma/releases/new`.

## Reference

- [Version Classification Guide](./references/version-classification.md) — Rules for determining version bump level.
- [Release workflow](.github/workflows/release.yml) — GitHub Actions workflow that publishes to PyPI.
