import re
import logging

logger = logging.getLogger("VersionUtils")

def parse_version(version_str):
    """
    Tries to convert a version string into a tuple of integers for comparison.
    Handles SemVer (1.2.3) and router style (3.0.0.4.388_24768).
    Returns a list of integers.
    """
    if not version_str:
        return []
    
    # Remove common prefixes/suffixes and find all integer segments
    # e.g., "v3.0.0.4.388_24768" -> [3, 0, 0, 4, 388, 24768]
    segments = re.findall(r'\d+', version_str)
    return [int(s) for s in segments]

def compare_versions(v1_str, v2_str):
    """
    Compares two version strings.
    Returns:
        1 if v1 > v2
        -1 if v1 < v2
        0 if v1 == v2
    """
    v1 = parse_version(v1_str)
    v2 = parse_version(v2_str)
    
    # Compare segment by segment
    for i in range(max(len(v1), len(v2))):
        s1 = v1[i] if i < len(v1) else 0
        s2 = v2[i] if i < len(v2) else 0
        
        if s1 > s2:
            return 1
        if s1 < s2:
            return -1
    return 0

def extract_affected_version(cve_description):
    """
    Attempts to extract the 'fixed' or 'earlier than' version from a CVE description.
    This is best-effort and focuses on common NVD patterns.
    """
    if not cve_description:
        return None
    
    # Pattern 1: "earlier than X" or "versions prior to X"
    match = re.search(r'(?:earlier than|prior to|before)\s+([\d._-]+)', cve_description, re.IGNORECASE)
    if match:
        return match.group(1).rstrip('.')
    
    # Pattern 2: "vulnerable in X" (Less reliable for 'higher than' logic)
    # match = re.search(r'vulnerable in ([\d._-]+)', cve_description, re.IGNORECASE)
    
    return None

def is_safe_version(actual_ver, cve_description):
    """
    Determines if the actual version is considered safe based on the CVE description.
    Requirements:
    1. We must be able to extract an 'affected version' limit (v_limit) from the description.
    2. actual_ver must be strictly greater than v_limit.
    """
    v_limit_str = extract_affected_version(cve_description)
    if not v_limit_str:
        return False
    
    # If comparison returns 1, actual_ver is newer than the affected threshold
    return compare_versions(actual_ver, v_limit_str) > 0
