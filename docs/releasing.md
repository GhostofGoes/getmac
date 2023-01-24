## Requirements
```bash
python -m pip install -U pip
python -m pip install -U setuptools twine wheel build
```

## Cutting a release
1. Increment version number in `getmac/getmac.py`
2. Update CHANGELOG header from UNRELEASED to the version and add the date
3. Run static analysis checks (`tox -e check`)
4. Ensure CI ([GitHub Actions](https://github.com/GhostofGoes/getmac/actions)) is passing on all checks and on all platforms
5. Ensure a pip install from source works on the main platforms:
```bash
pip install https://github.com/ghostofgoes/getmac/archive/main.tar.gz
```
1. Clean the environment: `bash ./scripts/clean.sh`
2. Build the sdist and wheel (`.whl`)
```bash
python -m build
```
1. Upload the sdist and wheel (`.whl`)
```bash
twine upload dist/*
```
1.  Create a tagged release on GitHub including:
    a) The relevant section of the CHANGELOG in the body
    b) The source and binary wheels
2.   Edit the package name in `pyproject.toml` to `get-mac`, and re-run steps 7 and 8 (build and upload), since people apparently don't check their dependencies and ignore runtime warnings.
3.   Announce the release in the normal places
