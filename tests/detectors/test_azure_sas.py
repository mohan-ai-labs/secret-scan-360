"""Unit test for Azure SAS detector."""

import sys
import os
from pathlib import Path

# Add src to path for imports
test_dir = Path(__file__).parent
project_root = test_dir.parent.parent
sys.path.insert(0, str(project_root / "src"))

from ss360.detectors.azure_storage_sas import scan


def test_azure_sas_detection():
    """Test Azure SAS token detection with expired and future samples."""
    
    # Test with expired SAS token (2023-01-01 is past)
    expired_sas = b"https://myaccount.blob.core.windows.net/container/blob?sv=2022-11-02&se=2023-01-01T00:00:00Z&sr=b&sp=r&sig=EXAMPLE123"
    findings = scan(expired_sas, "test.env")
    
    assert len(findings) == 1, f"Expected 1 finding for expired SAS, got {len(findings)}"
    assert findings[0].rule == "azure_sas"
    
    # Test with future SAS token (2030-01-01 is future) 
    future_sas = b"https://storageacct.blob.core.windows.net/data/file.txt?sv=2022-11-02&se=2030-01-01T00:00:00Z&sr=b&sp=r&sig=FUTURETOKEN456"
    findings = scan(future_sas, "config.env")
    
    assert len(findings) == 1, f"Expected 1 finding for future SAS, got {len(findings)}"
    assert findings[0].rule == "azure_sas"
    
    # Test with non-SAS URL (should not match)
    non_sas = b"https://example.com/not/a/sas/url"
    findings = scan(non_sas, "test.env")
    
    assert len(findings) == 0, f"Expected 0 findings for non-SAS URL, got {len(findings)}"
    
    print("✅ Azure SAS detector working correctly")


if __name__ == "__main__":
    test_azure_sas_detection()