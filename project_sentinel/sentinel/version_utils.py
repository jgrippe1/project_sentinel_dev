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
    
    # Clean description briefly to avoid line breaks interfering with match
    desc = cve_description.replace('\n', ' ').replace('\r', ' ')

    # Pattern 1: Explicit "earlier than", "prior to", "before"
    match = re.search(r'(?:earlier than|prior to|before|below)\s+([\d._-]+)', desc, re.IGNORECASE)
    if match:
        return match.group(1).rstrip('.')
    
    # Pattern 2: "running firmware version X" or "running version X"
    match = re.search(r'(?:running firmware version|running version|vulnerability in version)\s+([\d._-]+)', desc, re.IGNORECASE)
    if match:
        return match.group(1).rstrip('.')
    
    # Pattern 3: "affect devices running version X" or "firmware X"
    match = re.search(r'(?:affect devices running version|with firmware)\s+([\d._-]+)', desc, re.IGNORECASE)
    if match:
        return match.group(1).rstrip('.')

    # Pattern 4: "version X and earlier"
    match = re.search(r'([\d._-]+)\s+and\s+earlier', desc, re.IGNORECASE)
    if match:
        return match.group(1).rstrip('.')

    # Pattern 5: "fixed in X" -> X is the limit (exclusive)
    match = re.search(r'fixed in\s+([\d._-]+)', desc, re.IGNORECASE)
    if match:
        return match.group(1).rstrip('.')

    return None

def is_version_relevant(actual_ver, cve_description, asset_context=None):
    """
    Heuristic to determine if a CVE is even relevant for the asset.
    Attempts to avoid false positives from component mismatches (e.g. InterWorx on Asus).
    """
    if not cve_description:
        return False
    
    desc_l = cve_description.lower()
    
    # 1. Product/Vendor Check
    # If the description mentions a completely different OS/Product than what we are
    if asset_context:
        vendor = (asset_context.get('vendor') or '').lower()
        model = (asset_context.get('model') or '').lower()
        
        # If we know it's an ASUS router, but CVE mentions InterWorx, Plesk, cPanel, etc.
        if vendor == 'asustek computer inc.' or 'asus' in vendor:
            blocked_context = ['interworx', 'plesk', 'cpanel', 'directadmin', 'joomla', 'wordpress']
            if any(ctx in desc_l for ctx in blocked_context):
                return False
                
    # 2. Legacy Heuristic
    # If CVE is extremely old (e.g., 10+ years) and actual_ver looks like a modern semantic/router version
    # Most router CVEs from 2007-2012 are long patched or irrelevant for 2023+ firmware.
    # We still want to be careful, but this can help suppress "junk" findings.
    
    return True

def is_safe_version(actual_ver, cve_description, asset_context=None):
    """
    Determines if the actual version is considered safe based on the CVE description.
    Requirements:
    1. The CVE must be relevant to the asset context.
    2. We must be able to extract an 'affected version' limit (v_limit) from the description.
    3. actual_ver must be strictly greater than v_limit.
    """
    if not is_version_relevant(actual_ver, cve_description, asset_context):
        # If not relevant, we treat it as "safe" (suppressed) because it doesn't apply
        return True

    v_limit_str = extract_affected_version(cve_description)
    if not v_limit_str:
        return False
    
    # If comparison returns 1, actual_ver is newer than the affected threshold
    return compare_versions(actual_ver, v_limit_str) > 0
