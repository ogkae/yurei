<div align="center">
<!--
<h1 align="center">
$${\color{#9b87f5}y}{\color{#8b7ae5}u}{\color{#7b6dd5}r}{\color{#6b60c5}e}{\color{#5b53b5}i}$$
</h1>
-->
  
# Contributing to Yurei

*Lightweight cryptographic primitives for modern Python applications.*

|[![Version](https://img.shields.io/badge/version-1.4.1-9b87f5?style=for-the-badge&logo=python)](https://github.com/ogkae/yurei) [![Python](https://img.shields.io/badge/python-3.10+-9b87f5?style=for-the-badge&logo=python)](https://www.python.org) [![License](https://img.shields.io/badge/license-MIT-9b87f5?style=for-the-badge)](./LICENSE) [![Stars](https://img.shields.io/github/stars/ogkae/yurei?style=for-the-badge&color=9b87f5)](https://github.com/ogkae/yurei/stargazers) |
|----|

</div>

Thank you for your interest in contributing to Yurei.  
This document outlines the principles, workflow, standards, and expectations for contributions to this repository.

Yurei is a collection of lightweight cryptographic primitives built on Python’s standard library. The project prioritises clarity, correctness, security transparency, and maintainability.

All contributions should align with these principles.

---

## Table of Contents

`01`. [Project Principles](#project-principles)  
`02`. [Contribution Areas](#contribution-areas)  
`03`. [Development Setup](#development-setup)  
`04`. [Coding Standards](#coding-standards)  
`05`. [Security Guidelines](#security-guidelines)  
`06`. [Testing Expectations](#testing-expectations)  
`07`. [Commit and Pull Request Workflow](#commit-and-pull-request-workflow)  
`08`. [Reporting Bugs and Feature Requests](#reporting-bugs-and-feature-requests)  
`09`. [Contribution Checklist](#contribution-checklist)  

---

## Project Principles

Yurei is guided by the following principles:

| Principle                | Description |
|--------------------------|-------------|
| Standard library only    | No external dependencies for core modules |
| Readability              | Code must be clear and maintainable |
| Explicit behaviour       | No hidden behaviour or insecure shortcuts |
| Transparent limitations  | Document limitations, do not obscure them |
| Minimal surface area     | Each feature must have a clear purpose |

Contributions that contradict these principles are unlikely to be accepted.

---

## Contribution Areas

You can contribute in many ways, including but not limited to:

**Code**
- Bug fixes
- New features consistent with design philosophy
- API improvements
- Refactoring for clarity or performance

**Testing**
- Unit and integration tests
- Property-based tests (Hypothesis)
- Validation of edge cases

**Performance**
- Benchmarks
- Profiling and optimisation
- Memory usage improvements

**Documentation**
- API reference entries
- Usage examples
- Security discussions and rationale

**Security**
- Threat modelling and analysis
- Identification and mitigation of weaknesses

---

## Development Setup

To get started with development:

```bash
git clone https://github.com/ogkae/yurei
cd yurei
pip install -e ".[dev]"
````

The development tooling includes:

| Tool   | Purpose              |
| ------ | -------------------- |
| pytest | Test execution       |
| ruff   | Linting              |
| black  | Code formatting      |
| mypy   | Static type checking |

---

## Coding Standards

### Style and Formatting

To maintain consistency:

```bash
black .
ruff check .
mypy yurei/
```

* Follow PEP 8 guidelines.
* Use descriptive and unambiguous names.
* All public functions, classes, and modules must include docstrings.

### Type Hints

* All public interfaces must include type annotations.
* Internal helpers should be typed where appropriate.

Example:

```python
def hash_password(
    password: str,
    iterations: int = 200_000
) -> str:
    """Hash a password using PBKDF2-HMAC-SHA256."""
    ...
```

---

## Security Guidelines

Due to the nature of this project, security considerations are central:

| Expectation                      | Requirement                          |
| -------------------------------- | ------------------------------------ |
| No hidden or insecure defaults   | Required                             |
| Cryptographic design rationale   | Required in PR                       |
| Constant-time comparisons        | Required where applicable            |
| Backward compatibility preserved | Required unless explicitly discussed |

Any change that affects cryptographic behaviour must include a clear security rationale in the pull request description.

---

## Testing Expectations

Before submitting a pull request, the project must be tested thoroughly:

```bash
pytest tests/ -v
ruff check .
black .
mypy yurei/
```

Tests should:

* Be deterministic and reliable
* Cover a variety of correct and incorrect inputs
* Include edge cases and boundary conditions

Recommended test layout:

```
tests/
├── test_auth.py
├── test_cipher.py
├── test_store.py
```

---

## Commit and Pull Request Workflow

### Commit Guidelines

* Use clear, imperative messages:

  * `Add support for refresh tokens`
  * `Fix timing comparison in verify_password`
* Keep each commit focused and minimal.

### Pull Request Guidelines

1. Fork the repository.
2. Create a descriptive branch:

```bash
git checkout -b feature/describe-feature
```

3. Push the branch and open a pull request.
4. Reference any related issues.
5. Provide a clear description of:

   * What the change is
   * Why it was made
   * How it was tested
   * Security implications, if applicable

A Pull Request template may include:

```
## Summary

## Motivation

## Security Considerations

## Test Plan

## Documentation Updates
```

---

## Reporting Bugs and Feature Requests

When reporting a bug, include:

* Python version and environment
* Minimal reproducible example
* Expected and actual behaviour

When proposing a feature, include:

* Use case
* Proposed solution
* Alternatives considered
* Backward compatibility considerations
  
---

## Contribution Checklist

Before submitting, ensure:

* [ ] Code follows style and formatting standards
* [ ] Tests exist and pass
* [ ] Type checks complete
* [ ] Documentation updated
* [ ] Benchmarks included if performance is impacted
* [ ] Security rationale included where applicable

---

### For production environments, consider these audited alternatives:

| <code>Library</code> | <code>Algorithm</code> | <code>Use Case</code> |
|:--------|:----------|:---------|
| [`cryptography`](https://cryptography.io/) | AES-GCM, ChaCha20-Poly1305 | General-purpose encryption |
| [`bcrypt`](https://github.com/pyca/bcrypt/) | bcrypt | Password hashing |
| [`PyNaCl`](https://pynacl.readthedocs.io/) | NaCl/libsodium | High-level cryptography API |
| [`argon2-cffi`](https://github.com/hynek/argon2-cffi) | Argon2 | Modern password hashing |

---

### Contributors

<div align="center">
  
|[![Contributors](https://contrib.rocks/image?repo=ogkae/yurei)](https://github.com/ogkae/yurei/graphs/contributors)|
|-|

<br></br>

[`↑ Back to Top`](#project-principles)

<br></br>

| Licensed under the [`MIT Licence`](./LICENSE)<br></br><a href="https://discord.com/users/1394747147106254949"><img src="https://img.shields.io/badge/Discord-000000?style=for-the-badge&logo=discord"></a><a href="https://github.com/hexa-hosting"><img src="https://img.shields.io/badge/hexaʰ-000000?style=for-the-badge&logo=github"></a><a href="https://bento.me/ogkae"><img src="https://img.shields.io/badge/Bento-000000?style=for-the-badge&logo=bento"></a> |
|:----:|

</div>
<!-- (Also distributed under the [Toaster Licence 2025](./TOASTER-LICENSE))  || 10/10/2025 - 24/12/2025 -->

---

supporting [#good first issue](https://github.com/topics/good-first-issue)
