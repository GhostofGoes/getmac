"""
Tests for packaging artifacts: sdist and wheel.
This test was mostly generated using AI assistance.
"""

import os
import shutil
import subprocess
import tarfile
import zipfile
from pathlib import Path

import pytest


def test_packaging_artifacts(tmp_path: Path) -> None:
    """Build sdist and wheel, then verify their contents."""
    if shutil.which("pdm") is None:
        pytest.skip("pdm CLI not installed")

    dist_dir = tmp_path / "dist"

    # pytest-cov starts coverage in Python subprocesses via COV_CORE_* environment
    # variables. Remove them so the build doesn't record the temporary copy of the
    # source that pdm builds the wheel from, which no longer exists at report time.
    env = {k: v for k, v in os.environ.items() if not k.startswith("COV_CORE_")}

    # Build the package
    subprocess.run(
        f"pdm build --dest {dist_dir!s}",
        check=True,
        capture_output=True,
        shell=True,
        env=env,
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
    assert "getmac/py.typed" in sdist_files, "PEP 561 py.typed marker missing from sdist"

    # Third-party samples are licensed separately and must not be distributed
    for f in sdist_files:
        assert not f.startswith("tests/samples/third_party/"), f"File '{f}' should not be in sdist"
    # ...but the first-party samples the test suite needs must still be there
    assert "tests/samples/ubuntu_18.04/ifconfig.out" in sdist_files, (
        "Test samples missing from sdist"
    )

    # 2. Check wheel
    wheels = list(dist_dir.glob("*.whl"))
    assert len(wheels) == 1, "Expected exactly one wheel (.whl)"

    with zipfile.ZipFile(wheels[0], "r") as z:
        wheel_files = z.namelist()
        metadata_files = [f for f in wheel_files if f.endswith(".dist-info/METADATA")]
        metadata = z.read(metadata_files[0]).decode("utf-8") if metadata_files else ""

    # Tests should NOT be in wheel (assuming standard practice for this lib)
    for f in wheel_files:
        assert not f.startswith("tests/"), f"File '{f}' (tests) should not be in wheel"
        for bad in forbidden_starts:
            assert not f.startswith(bad), f"File '{f}' should not be in wheel"

    # Ensure package is in wheel
    assert any(f.startswith("getmac/") for f in wheel_files), "Source code missing from wheel"
    assert metadata_files, "Metadata missing from wheel"
    assert "getmac/py.typed" in wheel_files, "PEP 561 py.typed marker missing from wheel"

    # Only the package and its .dist-info should be installed (e.g. not a top-level LICENSE)
    for f in wheel_files:
        assert f.startswith(("getmac/", "getmac-")), f"Unexpected top-level file in wheel: '{f}'"
    assert any(f.endswith(".dist-info/licenses/LICENSE") for f in wheel_files), (
        "LICENSE missing from wheel .dist-info"
    )

    # License metadata uses a SPDX expression (PEP 639)
    assert "Metadata-Version: 2.4" in metadata
    assert "License-Expression: MIT" in metadata
    assert "License-File: LICENSE" in metadata
