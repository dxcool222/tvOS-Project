"""Relocatable workspace paths for tvOS rootless tooling."""
from __future__ import annotations

import os
from pathlib import Path


def workspace_root() -> Path:
    env = os.environ.get("DT_WORKSPACE_ROOT")
    if env:
        return Path(env).resolve()
    # tools/ is sibling of source/ under workspace root
    return Path(__file__).resolve().parent.parent


def build_root() -> Path:
    env = os.environ.get("DT_BUILD_ROOT")
    if env:
        return Path(env).resolve()
    return workspace_root().parent / "tvOS rootless-build"


def source_root() -> Path:
    return workspace_root() / "source"


def tools_root() -> Path:
    return workspace_root() / "tools"


def bootstrap_root() -> Path:
    return workspace_root() / "bootstrap"


def vendor_root() -> Path:
    return workspace_root() / "vendor"


def work_dir(name: str) -> Path:
    return build_root() / "work" / name


def artifacts_dir() -> Path:
    return build_root() / "artifacts"


def ldid_path() -> Path:
    return source_root() / "Tools" / "ldid"
