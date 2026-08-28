"""Upstream conformance kit run against VaultwardenSource."""

from __future__ import annotations

import pytest
from tests.secret_sources.conformance import SecretSourceConformance

from vw_source import VaultwardenSource


class TestVaultwardenConformance(SecretSourceConformance):
    @pytest.fixture
    def source(self):
        return VaultwardenSource()
