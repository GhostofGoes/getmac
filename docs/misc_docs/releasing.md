## One-time setup
CI publishes releases to PyPI with [Trusted Publishing](https://docs.pypi.org/trusted-publishers/), so no PyPI token is stored in GitHub.

## Requirements
- PDM: https://pdm-project.org/en/latest/#installation
- Python 3.12 or newer to build the manpage locally

## Cutting a release
1. Increment version number in `getmac/getmac.py` (in `__version__`)
1. Update the CHANGELOG header for the release (e.g. `## 1.0.0 (TBD)`), replacing `TBD` with the release date in `MM/DD/YYYY` format
1. Run static analysis checks (`pdm run lint`)
1. Ensure CI ([GitHub Actions](https://github.com/GhostofGoes/getmac/actions)) is passing on all checks and on all platforms
1. Ensure a pip install from source works on the main platforms:
```bash
pip install https://github.com/ghostofgoes/getmac/archive/main.tar.gz
```
1. Tag the release commit with the version (no `v` prefix) and push the tag:
```bash
git tag 1.0.0
git push origin 1.0.0
```
1. CI runs the checks, builds the sdist (`.tar.gz`) and wheel (`.whl`), creates build provenance attestations for them, and publishes them to PyPI (the `publish-pypi` job in `ci.yml`). The Docker workflow publishes the container image for the tag at the same time.
1. Approve the deployment for the `pypi` environment in the workflow run.
1. Check the release on PyPI, and verify the attestation of the published files:
```bash
pip download --no-deps getmac==1.0.0 -d dist/
gh attestation verify dist/getmac-1.0.0-py3-none-any.whl --repo GhostofGoes/getmac
```
1. Get the manpage: download the `manpage` artifact from the tag's CI run, or build it (writes `manpage/getmac.1`):
```bash
pdm run manpage
```
1. Create a tagged release on GitHub including:
    a) The relevant section of the CHANGELOG in the body
    b) The source and binary wheels (the `python-package-distributions` artifact of the tag's CI run)
    c) The manpage (`getmac.1`)

## Publishing manually
Only if CI can't publish the release. This needs [twine](https://twine.readthedocs.io/) 6.1.0 or newer, and a `~/.pypirc` file with a PyPI token for `getmac`.
1. Clean the environment: `bash ./scripts/clean.sh`
1. Build the sdist (`.tar.gz`) and wheel (`.whl`)
```bash
pdm build
```
1. Upload the sdist and wheel to PyPI. Use twine, not `pdm publish`: PDM doesn't upload the `License-Expression` metadata, so PyPI would show no license for the release.
```bash
twine upload dist/*
```
