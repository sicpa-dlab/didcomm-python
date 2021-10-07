# didcomm-python Testing

## Table of Contents

*   [Development Environment Setup](#development-environment-setup)

*   [Static Testing](#static-testing)

    *   [flake8](#flake8)
    *   [black](#black)

*   [Unit Testing](#unit-testing)

## Development Environment Setup

```bash
pip install -e .[tests]
```

## Static Testing

### flake8

Run [flake8](https://flake8.pycqa.org/en/latest/) as follows:

```bash
$ flake8 .
```

### black

Run [black](https://black.readthedocs.io/en/stable/usage_and_configuration/index.html) for a dry check as follows:

```bash
$ black --check --exclude didcomm/vendor .
```

or to auto-format:

```bash
$ black --exclude didcomm/vendor .
```

## Unit Testing

To run [pytest](https://docs.pytest.org/en/stable/) in your environment:

```bash
pytest
```

To run tests in all supported environments (like CI does) using [tox](https://tox.wiki/en/latest/index.html):

```bash
tox
```
