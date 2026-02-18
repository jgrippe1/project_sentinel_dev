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
                
    # 2. Legacy & Component Collision Heuristic
    # If the CVE is extremely old (e.g. pre-2015) and we are on a modern firmware (e.g. Asus 380+)
    # we should check for "string collisions" (like 3.0 vs 3.0) and component-level disconnects.
    cve_year = 0
    cve_match = re.search(r'CVE-(\d{4})-', desc_l.upper())
    if cve_match:
        cve_year = int(cve_match.group(1))

    if asset_context:
        vendor = (asset_context.get('vendor') or '').lower()
        if 'asus' in vendor and cve_year > 0 and cve_year < 2015:
            # Modern Asuswrt (380+) is unlikely to be affected by 2011 component CVEs
            # unless the CVE explicitly mentions Asuswrt.
            firmware = asset_context.get('actual_fw_version') or ""
            fw_segments = parse_version(firmware)
            if fw_segments and fw_segments[0] >= 3 or '380' in firmware or '382' in firmware or '384' in firmware or '386' in firmware or '388' in firmware:
                if 'asuswrt' not in desc_l and 'asus' not in desc_l:
                    # If it's a generic component CVE (Mongoose, shttpd, etc.) on modern Asus, mark as low confidence
                    # This lets HybridAnalyzer know it should probably fallback to LLM for a deeper look.
                    return True # Still relevant but potentially a false positive

    return True

def analyze_version_safety(actual_ver, cve_description, asset_context=None):
    """
    Analyzes version safety and returns a structured result with confidence.
    Returns:
        dict: {
            "result": "SAFE" | "VULNERABLE" | "INCONCLUSIVE",
            "confidence": int (0-100),
            "reason": str,
            "method": "regex"
        }
    """
    if not is_version_relevant(actual_ver, cve_description, asset_context):
        return {
            "result": "SAFE",
            "confidence": 90,
            "reason": "Not relevant to asset context (Vendor/Product mismatch)",
            "method": "regex"
        }

    v_limit_str = extract_affected_version(cve_description)
    if not v_limit_str:
        return {
            "result": "INCONCLUSIVE",
            "confidence": 0,
            "reason": "Could not extract affected version from description",
            "method": "regex"
        }
    
    # If comparison returns 1, actual_ver is newer than the affected threshold
    is_newer = compare_versions(actual_ver, v_limit_str) > 0
    
    if is_newer:
        return {
            "result": "SAFE",
            "confidence": 85,
            "reason": f"Version {actual_ver} > {v_limit_str} (Affected Limit)",
            "method": "regex"
        }
    else:
        return {
            "result": "VULNERABLE",
            "confidence": 75,
            "reason": f"Version {actual_ver} <= {v_limit_str} (Affected Limit)",
            "method": "regex"
        }

def is_safe_version(actual_ver, cve_description, asset_context=None):
    """
    Legacy wrapper for analyze_version_safety.
    Returns True if SAFE, False otherwise.
    """
    analysis = analyze_version_safety(actual_ver, cve_description, asset_context)
    return analysis["result"] == "SAFE"
