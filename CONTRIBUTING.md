# Contributing to netcon-sync

Thank you for your interest in contributing to netcon-sync! This document provides guidelines and instructions for contributing.

## Code of Conduct

Please be respectful and constructive in all interactions with other contributors.

## Getting Started

### Development Setup

1. Clone the repository:
```bash
git clone https://github.com/yourusername/netcon-sync.git
cd netcon-sync
```

2. Create a development virtual environment:
```bash
./install_deps.sh
source ~/.venv-netcon-sync/bin/activate
```

3. Make your changes

### Code Style

- Follow PEP 8 style guidelines
- Use meaningful variable and function names
- Add docstrings to functions and modules
- Keep functions focused and testable

### License Header

All Python files must include the GPL-3.0 license header:

```python
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2025 netcon-sync contributors
#
# This file is part of netcon-sync.
# netcon-sync is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

"""Module description."""
```

## Making Changes

### Commits

- Write clear, descriptive commit messages
- Keep commits focused on a single change
- Reference issues where applicable: `Fix #123`

### Testing

Before submitting:
- Test your changes thoroughly
- Test with edge cases
- Test with the actual services (UniFi, pfSense) if possible

### Documentation

- Update README.md if adding new features
- Add docstrings to new functions
- Document any new environment variables

## Pull Request Process

1. Update documentation and code as needed
2. Ensure no credentials or secrets are in the code
3. Create a descriptive pull request title and description
4. Link related issues
5. Be responsive to feedback during review

## Reporting Issues

When reporting issues, include:
- Python version
- Operating system
- What you were trying to do
- Error messages or unexpected behavior
- Steps to reproduce (if applicable)
- Relevant configuration (without credentials)

## Areas for Contribution

- Bug fixes
- Documentation improvements
- Test coverage
- Performance optimizations
- Additional UniFi/pfSense features
- Error handling improvements

## Questions?

Open an issue with the label `question` or `discussion`.

---

Thank you for contributing to netcon-sync!
