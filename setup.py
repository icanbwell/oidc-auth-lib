# noinspection Mypy
from typing import Any

from setuptools import setup, find_packages
from os import path, getcwd

# from https://packaging.python.org/tutorials/packaging-projects/

# noinspection SpellCheckingInspection
package_name = "oidcauthlib"

with open("README.md") as fh:
    long_description = fh.read()

try:
    with open(path.join(getcwd(), "VERSION")) as version_file:
        version = version_file.read().strip()
except OSError:
    raise


def fix_setuptools() -> None:
    """Work around bugs in setuptools.

    Some versions of setuptools are broken and raise SandboxViolation for normal
    operations in a virtualenv. We therefore disable the sandbox to avoid these
    issues.
    """
    try:
        from setuptools.sandbox import DirectorySandbox

        # noinspection PyUnusedLocal
        def violation(operation: Any, *args: Any, **_: Any) -> None:
            print("SandboxViolation: {}".format(args))

        DirectorySandbox._violation = violation
    except ImportError:
        pass


# Fix bugs in setuptools.
fix_setuptools()


# classifiers list is here: https://pypi.org/classifiers/

# create the package setup
setup(
    name=package_name,
    version=version,
    author="Imran Qureshi",
    author_email="imran.qureshi@bwell.com",
    description="oidcauthlib",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/icanbwell/oidc-auth-lib",
    packages=find_packages(),
    install_requires=[
        "httpx>=0.27.2",
        "authlib>=1.6.4",
        "joserfc>=1.2.2",
        "pydantic>=2.0,<3.0.0",
        "pymongo[srv]>=4.15.3",
        "fastapi>=0.115.8",
        "starlette>=0.49.1",
    ],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.12",
    dependency_links=[],
    include_package_data=True,
    zip_safe=False,
    package_data={"oidcauthlib": ["py.typed"]},
)
