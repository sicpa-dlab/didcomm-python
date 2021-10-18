## Release

Assumptions:

*   `main` branch can wait until release PR is merged

The steps:

1.  **release**:
    1.  **review adjust if needed the release version in `main`** to match the changes from the latest release following the [SemVer rules](https://semver.org/#summary).
    2.  [create](https://github.com/sicpa-dlab/didcomm-python/compare/stable...main) a **PR from `main` to `stable`** (you may likely want to name it as `release-<version>`)
    3.  once merged [release pipeline](https://github.com/sicpa-dlab/didcomm-python/actions/workflows/release.yml) will publish the release to [PyPI](https://pypi.org/project/didcomm)
2.  **bump next release version in `main`**
    *   **Note** decision about the next release version should be based on the same [SemVer](https://semver.org/) rules and the expected changes. Usually it would be either a MINOR or MAJOR (if incompatible changes are planned) release.
