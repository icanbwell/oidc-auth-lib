"""The authorization package stays pure: standard library only, no environment access."""

import ast
from pathlib import Path

import oidcauthlib.authorization as authorization_package

PACKAGE_DIR = Path(authorization_package.__file__).parent
FORBIDDEN_ENVIRONMENT_NAMES = {"environ", "getenv"}


def _source_files() -> list[Path]:
    return sorted(PACKAGE_DIR.glob("*.py"))


def test_package_has_source_files() -> None:
    assert _source_files()


def test_authorization_package_imports_nothing_else_from_oidcauthlib() -> None:
    offenders: list[str] = []
    for path in _source_files():
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "oidcauthlib" or (
                        alias.name.startswith("oidcauthlib.") and not alias.name.startswith("oidcauthlib.authorization")
                    ):
                        offenders.append(f"{path.name}: import {alias.name}")
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if node.level > 1:
                    offenders.append(f"{path.name}: relative import above the package")
                elif node.level == 0 and (
                    module == "oidcauthlib"
                    or (module.startswith("oidcauthlib.") and not module.startswith("oidcauthlib.authorization"))
                ):
                    offenders.append(f"{path.name}: from {module} import ...")
    assert offenders == []


def test_authorization_package_never_reads_the_environment() -> None:
    offenders: list[str] = []
    for path in _source_files():
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr in FORBIDDEN_ENVIRONMENT_NAMES:
                offenders.append(f"{path.name}:{node.lineno} .{node.attr}")
            elif isinstance(node, ast.Name) and node.id in FORBIDDEN_ENVIRONMENT_NAMES:
                offenders.append(f"{path.name}:{node.lineno} {node.id}")
            elif isinstance(node, ast.ImportFrom) and node.module == "os":
                for alias in node.names:
                    if alias.name in FORBIDDEN_ENVIRONMENT_NAMES:
                        offenders.append(f"{path.name}:{node.lineno} from os import {alias.name}")
    assert offenders == []


FORBIDDEN_IO_MODULES = {
    "os",
    "io",
    "pathlib",
    "shutil",
    "tempfile",
    "socket",
    "ssl",
    "http",
    "urllib",
    "requests",
    "subprocess",
    "sqlite3",
}


def test_authorization_package_performs_no_io() -> None:
    offenders: list[str] = []
    for path in _source_files():
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                offenders.extend(
                    f"{path.name}:{node.lineno} import {alias.name}"
                    for alias in node.names
                    if alias.name.split(".")[0] in FORBIDDEN_IO_MODULES
                )
            elif (
                isinstance(node, ast.ImportFrom)
                and node.level == 0
                and (node.module or "").split(".")[0] in FORBIDDEN_IO_MODULES
            ):
                offenders.append(f"{path.name}:{node.lineno} from {node.module} import ...")
            elif (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in {"open", "print", "input"}
            ):
                offenders.append(f"{path.name}:{node.lineno} {node.func.id}(...)")
    assert offenders == []
