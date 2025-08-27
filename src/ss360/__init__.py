"""SS360 package metadata."""
from importlib.metadata import version, PackageNotFoundError

try:
    __version__ = version("ss360")
except PackageNotFoundError:
    __version__ = "0.0.1"
