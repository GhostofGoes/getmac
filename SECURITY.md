# Security Policy

## Supported Versions

| Version    | Supported          |
| ---------- | ------------------ |
| 1.0.x      | Yes |
| 0.9.x      | Maintenance mode, security or major bug fixes only |
| 0.8.x      | No longer supported |
| <= 0.7.x   | No longer supported |

## Reporting a Vulnerability or other security issue

If the security issue is a general weakness or poor practice that is *not directly exploitable*, please open a [Issue on GitHub](https://github.com/GhostofGoes/getmac/issues) and add the `security` label.

If the security issue is a vulnerability that can *potentially be exploited or has a exploit developed/proven*, please email ghostofgoes(at)gmail.com.
Please include in the email a description of the vulnerability, any proof of concept code/exploit code, and any other information that you believe may be relevant.
PGP signed message is preferred but not required.

## Verifying releases

Releases are built and published by GitHub Actions, and every published release has a signed [build provenance attestation](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations) that ties it to the commit and workflow run that built it. These can be checked with the [GitHub CLI](https://cli.github.com/).

The sdist and wheel on PyPI (PyPI also stores their attestations, per PEP 740):

```bash
pip download --no-deps getmac==1.0.0 -d dist/
gh attestation verify dist/getmac-1.0.0-py3-none-any.whl --repo GhostofGoes/getmac
```

Docker images on the GitHub Container Registry:

```bash
gh attestation verify oci://ghcr.io/ghostofgoes/getmac:1.0.0 --repo GhostofGoes/getmac
```
