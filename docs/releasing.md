## Requirements
- Poetry: https://python-poetry.org/docs/#installing-with-the-official-installer
- Configured `~/.pypirc` file with a token for `getmac` (for publishing to PyPI)

## Cutting a release
1. Increment version number in `getmac/getmac.py`
1. Update CHANGELOG header from UNRELEASED to the version and add the date
1. Run static analysis checks (`tox -e check`)
1. Ensure CI ([GitHub Actions](https://github.com/GhostofGoes/getmac/actions)) is passing on all checks and on all platforms
1. Ensure a pip install from source works on the main platforms:
```bash
pip install https://github.com/ghostofgoes/getmac/archive/main.tar.gz
```
1. Clean the environment: `bash ./scripts/clean.sh`
1. Build the sdist (`.tar.gz`) and wheel (`.whl`)
```bash
poetry build
```
1. Upload the sdist (`.tar.gz`) and wheel (`.whl`) to PyPI
```bash
poetry publish
```
1. Create a tagged release on GitHub including:
    a) The relevant section of the CHANGELOG in the body
    b) The source and binary wheels
