# Copyright (c) 2024 Airbyte, Inc., all rights reserved.

"""Shared helpers for `source-gong` unit tests."""

import importlib
import sys
from pathlib import Path
from types import ModuleType

from airbyte_cdk.sources.declarative.yaml_declarative_source import YamlDeclarativeSource
from airbyte_cdk.test.catalog_builder import CatalogBuilder
from airbyte_cdk.test.state_builder import StateBuilder


def _get_manifest_path() -> Path:
    """Resolve the path to the connector's `manifest.yaml`.

    In CI the connector is copied into `/airbyte/integration_code/source_declarative_manifest/`.
    Locally, tests are run from the connector's `unit_tests/` directory, so the manifest lives
    one directory up.
    """
    ci_path = Path("/airbyte/integration_code/source_declarative_manifest")
    if ci_path.exists():
        return ci_path
    return Path(__file__).parent.parent


_MANIFEST_PATH = _get_manifest_path() / "manifest.yaml"

# The manifest references `source_declarative_manifest.components.*`. Outside the connector image
# the CDK falls back to importing `components`, so the directory holding `components.py` must be
# importable.
if str(_get_manifest_path()) not in sys.path:
    sys.path.append(str(_get_manifest_path()))


def load_components() -> ModuleType:
    """Import the connector's `components.py`, the same module instance the manifest resolves to."""
    return importlib.import_module("components")


def get_source(config, state=None) -> YamlDeclarativeSource:
    """Instantiate a `YamlDeclarativeSource` for `source-gong` using its manifest."""
    catalog = CatalogBuilder().build()
    state = state if state is not None else StateBuilder().build()
    return YamlDeclarativeSource(
        path_to_yaml=str(_MANIFEST_PATH),
        catalog=catalog,
        config=config,
        state=state,
    )
