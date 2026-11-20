# Creating Releases

CI publishes releases to PyPI with [Trusted Publishing](https://docs.pypi.org/trusted-publishers/).

Manual publishing is no longer done, all releases should go through GitHub Actions:
- Provenance and trust
- Less potential for token compromise
- Less potential for me to screw something up (good ole' human error)

## Process

1. Increment version number in `getmac/getmac.py` (in `__version__`)
1. Update the CHANGELOG header for the release (e.g. `## 1.0.0 (TBD)`), replacing `TBD` with the release date in `MM/DD/YYYY` format
1. Ensure [CI](https://github.com/GhostofGoes/getmac/actions) is passing on all checks and on all platforms
1. Tag the release commit with the version (no `v` prefix) and push the tag. If it's a pre-release, tag it as such, e.g. `1.0.0a1`, `1.0.0b1`, `1.0.0rc1`.
```bash
git tag 1.0.0
git push origin 1.0.0
```
1. CI runs the checks, builds the sdist (`.tar.gz`) and wheel (`.whl`), creates build provenance attestations for them, and publishes them to PyPI (the `publish-pypi` job in `ci.yml`). The Docker workflow publishes the container image for the tag at the same time.
1. Approve the deployment for the `pypi` environment in the workflow run (`ci.yml`), and for the `ghcr` environment in the Docker workflow run (`docker.yml`). Both workflows first check that the tag is on `main` or a release branch (e.g. `1.0.x`), and stop if it isn't.
1. Check the release on PyPI, and verify the attestation of the published files:
```bash
pip download --no-deps getmac==1.0.0 -d dist/
gh attestation verify dist/getmac-1.0.0-py3-none-any.whl --repo GhostofGoes/getmac
```
1. Check and publish the draft release on GitHub. After publishing to PyPI, CI creates it (the `github-release` job in `ci.yml`) with:
    a) The CHANGELOG section for the version as the notes
    b) The sdist and wheel
    c) The manpage (`getmac.1`)
    d) The signed build provenance (`getmac-1.0.0.intoto.jsonl`)

## Publishing manually

Only for backported releases or the old package name (`get-mac`). This needs [twine](https://twine.readthedocs.io/) 6.1.0 or newer, and a `~/.pypirc` file with a PyPI token for `getmac`.

1. Clean the environment: `bash ./scripts/clean.sh`
1. Build the sdist (`.tar.gz`) and wheel (`.whl`)
```bash
pdm build
```
1. Check the sdist and wheel for problems PyPI would reject, such as a README that doesn't render
```bash
pdm run check_package
```
1. Upload the sdist and wheel to PyPI. Use twine, not `pdm publish`: PDM doesn't upload the `License-Expression` metadata, so PyPI would show no license for the release.
```bash
twine upload dist/*
```

## Repository settings the release process relies on

These are set on GitHub and PyPI, not in the repository, so check them when something about releases changes.

- **Environments** (Settings > Environments): `pypi` and `ghcr` have required reviewers, and are limited to tags (deployment branches and tags: `[0-9]*`). `ghcr-edge` (the `edge` image for `main`) is limited to the `main` branch and has no reviewers.
- **Tag rules** (Settings > Rules > Rulesets): only maintainers can create, move or delete tags matching `[0-9]*`.
- **PyPI Trusted Publisher** for `getmac`: repository `GhostofGoes/getmac`, workflow `ci.yml`, environment `pypi`. With the environment set, a different workflow or job can't publish.
- **No long-lived PyPI token** is needed for 1.0 releases. Delete any that exist once 0.9.x no longer needs one.

