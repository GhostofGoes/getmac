## Requirements
- PDM: https://pdm-project.org/en/latest/#installation
- [twine](https://twine.readthedocs.io/) 6.1.0 or newer (for publishing to PyPI)
- Configured `~/.pypirc` file with a token for `getmac` (used by twine)

## Cutting a release
1. Increment version number in `getmac/getmac.py` (in `__version__`)
1. Update the CHANGELOG header for the release (e.g. `## 1.0.0 (TBD)`), replacing `TBD` with the release date in `MM/DD/YYYY` format
1. Run static analysis checks (`pdm run lint`)
1. Ensure CI ([GitHub Actions](https://github.com/GhostofGoes/getmac/actions)) is passing on all checks and on all platforms
1. Ensure a pip install from source works on the main platforms:
```bash
pip install https://github.com/ghostofgoes/getmac/archive/main.tar.gz
```
1. Clean the environment: `bash ./scripts/clean.sh`
1. Build the sdist (`.tar.gz`) and wheel (`.whl`)
```bash
pdm build
```
1. Upload the sdist (`.tar.gz`) and wheel (`.whl`) to PyPI. Use twine, not `pdm publish`: PDM doesn't upload the `License-Expression` metadata, so PyPI would show no license for the release.
```bash
twine upload dist/*
```
1. Build the manpage (writes `manpage/getmac.1`). This needs the `docs` dependency group (`pdm install -d`, Python 3.10+).
```bash
pdm run manpage
```
1. Create a tagged release on GitHub including:
    a) The relevant section of the CHANGELOG in the body
    b) The source and binary wheels
    c) The manpage (`manpage/getmac.1`)
