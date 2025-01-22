import platform

from setuptools import setup

# Custom pre-install checks
if platform.system() != "Windows":
    raise EnvironmentError("This package only supports Windows.")

# Standard setup invocation (most metadata in pyproject.toml)
setup()
