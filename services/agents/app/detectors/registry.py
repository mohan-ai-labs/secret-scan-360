import pkgutil, importlib, pathlib
from .base import Detector


def load_detectors():
    detectors = []
    package_path = pathlib.Path(__file__).parent
    pkg_name = __package__  # services.agents.app.detectors
    for m in pkgutil.iter_modules([str(package_path)]):
        if m.name in {"base", "registry", "__init__"}:
            continue
        mod = importlib.import_module(f"{pkg_name}.{m.name}")
        detector_cls = getattr(mod, "DetectorImpl", None)
        if detector_cls and issubclass(detector_cls, Detector):
            detectors.append(detector_cls())
    return detectors
