"""SS360 custom exceptions."""

from __future__ import annotations


class SS360ConfigError(Exception):
    """Raised when configuration is missing or invalid."""
    
    def __init__(self, message: str, config_path: str = None, section: str = None):
        self.config_path = config_path
        self.section = section
        super().__init__(message)
    
    def __str__(self):
        msg = super().__str__()
        if self.config_path:
            msg += f" (config: {self.config_path})"
        if self.section:
            msg += f" (section: {self.section})"
        return msg