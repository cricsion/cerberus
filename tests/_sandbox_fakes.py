"""Shared fixtures for the sandbox backend suites.

The docker suite fakes the daemon at ``docker_channel.client_for``
(``_docker_fakes.py``); the local suite needs no fake at all. Only the
fixture below is still shared.

Not a test module (leading underscore), so pytest never collects it.
"""
from __future__ import annotations

import pytest


@pytest.fixture
def repo(tmp_path):
    (tmp_path / "app.py").write_text("print('hi')\n")
    return tmp_path
