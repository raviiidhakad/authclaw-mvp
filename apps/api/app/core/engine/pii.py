import re
from typing import List, Dict, Any, Tuple
from dataclasses import dataclass

@dataclass
class PIIFinding:
    pii_type: str
    value: str
    start: int
    end: int

class PIIDetector:
    """Regex-based PII detector for MVP."""
    
    # Common regex patterns for PII
    PATTERNS = {
        "EMAIL": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
        "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
        "PHONE": r"\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b",
        "CREDIT_CARD": r"\b(?:\d[ -]*?){13,16}\b",
        "ADDRESS": r"\b\d{1,5}\s+[A-Z][A-Za-z0-9\s\.,#-]*?\s+(?:[Ss]treet|[Ss]t|[Aa]venue|[Aa]ve|[Rr]oad|[Rr]d|[Dd]rive|[Dd]r|[Cc]ourt|[Cc]t|[Bb]oulevard|[Bb]lvd|[Ll]ane|[Ll]n|[Ww]ay|[Pp]arkway|[Pp]kwy)\b",
        "PASSWORD": r"(?i)(?:password\s*(?:is|=|:)?\s*)(\S+)"
    }



    def __init__(self):
        self._compiled_patterns = {
            pii_type: re.compile(pattern) 
            for pii_type, pattern in self.PATTERNS.items()
        }

    def detect(self, text: str, pii_types: List[str] = None) -> List[PIIFinding]:
        findings = []
        types_to_check = pii_types or self.PATTERNS.keys()
        
        for pii_type in types_to_check:
            pii_type = pii_type.upper()
            if pii_type not in self._compiled_patterns:
                continue
                
            pattern = self._compiled_patterns[pii_type]
            for match in pattern.finditer(text):
                findings.append(PIIFinding(
                    pii_type=pii_type,
                    value=match.group(),
                    start=match.start(),
                    end=match.end()
                ))
                
        # Sort findings by start index
        findings.sort(key=lambda x: x.start)
        return findings

class PIIRedactor:
    """Redacts PII findings from text."""
    
    @staticmethod
    def redact(text: str, findings: List[PIIFinding], placeholder_format: str = "[{pii_type}]") -> str:
        """
        Replaces found PII with placeholders.
        Starts from the end to avoid shifting indices.
        """
        result = text
        # Process from back to front to maintain index integrity
        sorted_findings = sorted(findings, key=lambda x: x.start, reverse=True)
        
        for finding in sorted_findings:
            placeholder = placeholder_format.format(pii_type=finding.pii_type)
            result = result[:finding.start] + placeholder + result[finding.end:]
            
        return result
