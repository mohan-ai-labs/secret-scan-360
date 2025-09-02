import re
from typing import Dict, List, Any

class CustomDetector:
    """
    Detector for identifying potentially sensitive information in code.
    """
    
    def __init__(self):
        self.name = "custom_detector"
        # Patterns to look for in the code
        self.patterns = [
            re.compile(r'pattern_here')
        ]
    
    def detect(self, content: str, metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Scan the content for potential secrets.
        
        Args:
            content: The file content to scan
            metadata: Additional information about the file
            
        Returns:
            A list of findings, each with location and context
        """
        findings = []
        
        for line_num, line in enumerate(content.splitlines(), 1):
            for pattern in self.patterns:
                matches = pattern.finditer(line)
                for match in matches:
                    findings.append({
                        'start_line': line_num,
                        'end_line': line_num,
                        'start_column': match.start() + 1,
                        'end_column': match.end() + 1,
                        'match': match.group(0),
                        'context': line.strip(),
                        'detector': self.name,
                        'severity': 'MEDIUM',
                    })
        
        return findings
