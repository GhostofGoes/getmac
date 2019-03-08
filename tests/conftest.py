# -*- coding: utf-8 -*-
import io
from os import path

import pytest


@pytest.fixture
def get_sample():
    def _get_sample(sample_path):
        sdir = path.realpath(path.join(path.dirname(__file__), 'samples'))
        with io.open(path.join(sdir, sample_path), 'rt',
                     newline='', encoding='utf-8') as f:
            return f.read()
    return _get_sample
