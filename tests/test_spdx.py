# SPDX-FileCopyrightText: 2017-2026 Christopher Goes
# SPDX-License-Identifier: MIT

"""
Every source file carries a copyright statement and a license identifier, as the
SPDX comments at the top of this file. This is part of the OpenSSF Best Practices
gold criteria (copyright_per_file, license_per_file), and it says who owns the code
and under which terms when a file is copied out of the repository on its own.
"""

import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

# Files that must have the header: by suffix, and by exact name
SUFFIXES = {".py", ".sh", ".yml", ".yaml", ".toml"}
NAMES = {"Dockerfile", "Dockerfile.dockerignore", "Vagrantfile"}

# Captured command output (tests/samples/) isn't source, and some of it is third-party
SKIP_PREFIXES = ("tests/samples/",)

COPYRIGHT = "SPDX-FileCopyrightText:"
LICENSE = "SPDX-License-Identifier: MIT"


def _tracked_source_files() -> list[Path]:
    """The source files in the repository, as git tracks them."""
    git = shutil.which("git")
    assert git is not None
    output = subprocess.check_output([git, "-C", str(REPO_ROOT), "ls-files", "-z"], text=True)
    files = []
    for rel in output.split("\0"):
        if not rel or rel.startswith(SKIP_PREFIXES):
            continue
        path = REPO_ROOT / rel
        if (path.suffix in SUFFIXES or path.name in NAMES) and path.is_file():
            files.append(path)
    return files


def test_spdx_headers():
    """Each source file starts with the SPDX copyright and license comments."""
    if shutil.which("git") is None or not (REPO_ROOT / ".git").exists():
        pytest.skip("not a git checkout")

    files = _tracked_source_files()
    assert files, "no source files found, is this a git checkout?"

    missing = []
    for path in files:
        head = "".join(path.read_text(encoding="utf-8").splitlines(keepends=True)[:5])
        if COPYRIGHT not in head or LICENSE not in head:
            missing.append(str(path.relative_to(REPO_ROOT)))

    assert not missing, "Source files without SPDX headers in their first 5 lines:\n" + "\n".join(
        missing
    )
