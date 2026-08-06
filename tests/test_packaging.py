"""
Tests for packaging artifacts: sdist and wheel.
This test was mostly generated using AI assistance.
"""

import subprocess
import tarfile
import zipfile
from pathlib import Path


def test_packaging_artifacts(tmp_path: Path) -> None:
    """Build sdist and wheel, then verify their contents."""
    dist_dir = tmp_path / "dist"

    # Build the package
    subprocess.run(
        f"pdm build --dest {dist_dir!s}",
        check=True,
        capture_output=True,
        shell=True,
    )

    # 1. Check sdist
    sdists = list(dist_dir.glob("*.tar.gz"))
    assert len(sdists) == 1, "Expected exactly one sdist (.tar.gz)"

    with tarfile.open(sdists[0], "r:gz") as tar:
        sdist_members = tar.getnames()

    # Normalize paths: remove the top-level directory (e.g. getmac-1.0.0/)
    sdist_files = []
    for m in sdist_members:
        parts = m.split("/", 1)
        if len(parts) > 1:
            sdist_files.append(parts[1])
        else:
            sdist_files.append(m)

    # Forbidden files/directories that should never be in the distribution
    forbidden_starts = [
        ".github",
        ".git",
        ".vscode",
        ".idea",
        "build",
        "dist",
        "venv",
        ".venv",
        ".pdm-python",
        "__pycache__",
    ]

    for f in sdist_files:
        for bad in forbidden_starts:
            assert not f.startswith(bad), f"File '{f}' should not be in sdist"

    # Essential files that MUST be in sdist
    expected_in_sdist = [
        "pyproject.toml",
        "README.md",
        "LICENSE",
        "CHANGELOG.md",
    ]
    for expected in expected_in_sdist:
        assert expected in sdist_files, f"'{expected}' missing from sdist"

    # Ensure source code and tests are present in sdist
    assert any(f.startswith("getmac/") for f in sdist_files), "Source code missing from sdist"
    assert any(f.startswith("tests/") for f in sdist_files), "Tests missing from sdist"

    # 2. Check wheel
    wheels = list(dist_dir.glob("*.whl"))
    assert len(wheels) == 1, "Expected exactly one wheel (.whl)"

    with zipfile.ZipFile(wheels[0], "r") as z:
        wheel_files = z.namelist()

    # Tests should NOT be in wheel (assuming standard practice for this lib)
    for f in wheel_files:
        assert not f.startswith("tests/"), f"File '{f}' (tests) should not be in wheel"
        for bad in forbidden_starts:
            assert not f.startswith(bad), f"File '{f}' should not be in wheel"

    # Ensure package is in wheel
    assert any(f.startswith("getmac/") for f in wheel_files), "Source code missing from wheel"
    assert any(f.endswith(".dist-info/METADATA") for f in wheel_files), (
        "Metadata missing from wheel"
    )
