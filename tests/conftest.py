from os import path

import pytest

from getmac.variables import settings

settings.DEBUG = 4


@pytest.fixture
def get_sample():
    def _get_sample(sample_path):
        sdir = path.realpath(path.join(path.dirname(__file__), "samples"))
        with open(path.join(sdir, sample_path), newline="", encoding="utf-8") as f:
            return f.read()

    return _get_sample
