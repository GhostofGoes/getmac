from os import path

import pytest

from getmac.variables import settings

settings.DEBUG = 4


@pytest.fixture
def get_sample():
    def _get_sample(sample_path):
        sdir = path.realpath(path.join(path.dirname(__file__), "samples"))
        full_path = path.join(sdir, sample_path)
        # Third-party samples are licensed separately and aren't included in the sdist
        third_party_dir = path.join(sdir, "third_party")
        if sample_path.startswith("third_party/") and not path.isdir(third_party_dir):
            pytest.skip("third-party samples are not included in the sdist")
        with open(full_path, newline="", encoding="utf-8") as f:
            return f.read()

    return _get_sample
