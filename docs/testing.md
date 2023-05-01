# didcomm-python Testing

## Table of Contents

*   [Development Environment Setup](#development-environment-setup)

*   [Static Testing](#static-testing)

    *   [flake8](#flake8)
    *   [black](#black)

*   [Unit Testing](#unit-testing)

## Development Environment Setup

```bash
poetry install
```

## Static Testing

### flake8

Run [flake8](https://flake8.pycqa.org/en/latest/) as follows:

```bash
$ poetry run flake8 .
```

### black

Run [black](https://black.readthedocs.io/en/stable/usage_and_configuration/index.html) for a dry check as follows:

```bash
$ poetry run black --check .
```

or to auto-format:

```bash
$ poetry run black .
```

## Unit Testing

To run [pytest](https://docs.pytest.org/en/stable/) in your environment:

```bash
poetry run pytest
```