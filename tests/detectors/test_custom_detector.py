import unittest
from detectors.custom_detector import CustomDetector

class TestCustomDetector(unittest.TestCase):
    def setUp(self):
        self.detector = CustomDetector()
    
    def test_detector_initialization(self):
        """Test that the detector initializes with correct properties."""
        self.assertEqual(self.detector.name, "custom_detector")
        self.assertGreater(len(self.detector.patterns), 0)
    
    def test_detect_no_secrets(self):
        """Test that detector returns empty list when no secrets are present."""
        content = "This is a safe file with no secrets"
        findings = self.detector.detect(content, {})
        self.assertEqual(len(findings), 0)
    
    def test_detect_with_secrets(self):
        """Test that detector finds secrets when they are present.
        This is a placeholder that will need to be updated with actual test patterns.
        """
        # This test will need to be updated with actual patterns once implemented
        content = "pattern_here"  # This should match when patterns are implemented
        findings = self.detector.detect(content, {})
        
        # Uncomment when patterns are implemented
        # self.assertGreater(len(findings), 0)
        # self.assertEqual(findings[0]['detector'], 'custom_detector')
        # self.assertEqual(findings[0]['severity'], 'MEDIUM')

if __name__ == '__main__':
    unittest.main()
