"""API — Flask REST endpoints for the Sentinel dashboard, analysis, and asset management."""
import logging
import os
import requests
import io
import csv
import json
from flask import Flask, jsonify, send_from_directory, request, Response
from sentinel.datastore import Datastore

# Configure Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("SentinelAPI")

app = Flask(__name__, static_folder='static')
db = Datastore()
from sentinel.cve_analyzer import HybridAnalyzer

# Add-on version — keep in sync with config.yaml on each release
_ADDON_VERSION = "1.0.64"

# Load config similar to core.py
OPTIONS_PATH = "/data/options.json"
config = {"options": {}}
_config_mtime = 0  # Track file modification time for hot-reload

def _reload_config():
    """Reload config from disk if the file has been modified since last load."""
    global config, _config_mtime, analyzer
    try:
        if not os.path.exists(OPTIONS_PATH):
            return
        mtime = os.path.getmtime(OPTIONS_PATH)
        if mtime > _config_mtime:
            _config_mtime = mtime
            with open(OPTIONS_PATH, 'r') as f:
                config["options"] = json.load(f)
            
            verbose = config['options'].get('verbose_logging', False)
            log_level = logging.DEBUG if verbose else logging.INFO
            logging.getLogger().setLevel(log_level)
            logger.info(f"Config reloaded. LLM={config['options'].get('llm_enabled', False)}, LogLevel={'DEBUG' if verbose else 'INFO'}")
            
            # Reinitialize analyzer with new config
            analyzer = HybridAnalyzer(config)
            _init_adguard()
    except Exception as e:
        logger.error(f"Failed to reload config: {e}")

# Initial load
if os.path.exists(OPTIONS_PATH):
    try:
        _config_mtime = os.path.getmtime(OPTIONS_PATH)
        with open(OPTIONS_PATH, 'r') as f:
            config["options"] = json.load(f)
            logger.info(f"Loaded {len(config['options'])} options from {OPTIONS_PATH}")
            if 'llm_enabled' in config['options']:
                logger.info(f"API Config LLM Status: {config['options']['llm_enabled']}")
            
            verbose = config['options'].get('verbose_logging', False)
            log_level = logging.DEBUG if verbose else logging.INFO
            logging.getLogger().setLevel(log_level)
            logger.info(f"Log Level set to: {'DEBUG' if verbose else 'INFO'}")

    except Exception as e:
        logger.error(f"Failed to load options: {e}")

analyzer = HybridAnalyzer(config)

# Optional AdGuard Home integration
adguard_client = None
def _init_adguard():
    """Initialize AdGuard client from config if host is set."""
    global adguard_client
    options = config.get('options', {})
    host = options.get('adguard_host', '')
    if host:
        from sentinel.adguard_client import AdGuardClient
        adguard_client = AdGuardClient(
            host=host,
            username=options.get('adguard_username', ''),
            password=options.get('adguard_password', '')
        )
        logger.info(f"AdGuard integration enabled: {host}")
    else:
        adguard_client = None

_init_adguard()

# ---------- HA Device Registry ----------
import time as _time
_ha_device_cache = {"devices": [], "ts": 0}
_HA_CACHE_TTL = 300  # 5 minutes

def _fetch_ha_device_registry():
    """
    Fetch HA device registry via the /api/template endpoint.
    The device registry is WebSocket-only, but /api/template lets us
    render Jinja2 templates that access device_attr() and related helpers.
    Falls back gracefully when running outside HA or without SUPERVISOR_TOKEN.
    """
    now = _time.time()
    if _ha_device_cache["devices"] and (now - _ha_device_cache["ts"]) < _HA_CACHE_TTL:
        return _ha_device_cache["devices"]

    token = os.getenv("SUPERVISOR_TOKEN")
    if not token:
        return _ha_device_cache["devices"]  # Return stale or empty

    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    # Template that iterates over all devices in the registry and outputs JSON.
    # Uses device_attr() which is available in HA templates.
    tpl = """
{%- set ns = namespace(devs=[]) -%}
{%- for state in states -%}
  {%- set did = device_id(state.entity_id) -%}
  {%- if did and did not in ns.devs | map(attribute='id') | list -%}
    {%- set ns.devs = ns.devs + [{
      'id': did,
      'name': device_attr(did, 'name') or '',
      'name_by_user': device_attr(did, 'name_by_user') or '',
      'manufacturer': device_attr(did, 'manufacturer') or '',
      'model': device_attr(did, 'model') or '',
      'sw_version': device_attr(did, 'sw_version') or '',
      'hw_version': device_attr(did, 'hw_version') or '',
      'area_id': device_attr(did, 'area_id') or '',
      'connections': device_attr(did, 'connections') | list,
      'identifiers': device_attr(did, 'identifiers') | list
    }] -%}
  {%- endif -%}
{%- endfor -%}
{{ ns.devs | to_json }}
""".strip()

    try:
        resp = requests.post(
            "http://supervisor/core/api/template",
            headers=headers,
            json={"template": tpl},
            timeout=30
        )
        resp.raise_for_status()
        devices = json.loads(resp.text)
        _ha_device_cache["devices"] = devices
        _ha_device_cache["ts"] = now
        logger.info(f"Fetched {len(devices)} devices from HA device registry")
        return devices
    except requests.exceptions.ConnectionError:
        logger.debug("HA Supervisor API not reachable (not running in HA?)")
        return _ha_device_cache["devices"]
    except Exception as e:
        logger.warning(f"Failed to fetch HA device registry: {e}")
        return _ha_device_cache["devices"]

def _match_ha_device(mac, ip=None):
    """
    Find an HA device that matches a network asset by MAC or IP.
    Returns the matched device dict or None.
    """
    devices = _fetch_ha_device_registry()
    if not devices:
        return None

    mac_upper = mac.upper() if mac else ''
    mac_clean = mac_upper.replace(':', '').replace('-', '')

    for dev in devices:
        # Check connections (typically [['mac', 'AA:BB:CC:DD:EE:FF']])
        for conn in dev.get('connections', []):
            if len(conn) >= 2:
                conn_type, conn_val = conn[0], str(conn[1]).upper()
                if conn_type == 'mac':
                    conn_clean = conn_val.replace(':', '').replace('-', '')
                    if conn_clean == mac_clean:
                        return dev

        # Check identifiers for IP/MAC patterns
        for ident in dev.get('identifiers', []):
            if isinstance(ident, (list, tuple)) and len(ident) >= 2:
                ident_val = str(ident[1]).upper()
                ident_clean = ident_val.replace(':', '').replace('-', '')
                if ident_clean == mac_clean:
                    return dev
                if ip and str(ident[1]) == ip:
                    return dev

    return None

def _get_integration_from_identifiers(ha_dev):
    """Extract the integration domain from an HA device's identifiers."""
    for ident in ha_dev.get('identifiers', []):
        if isinstance(ident, (list, tuple)) and len(ident) >= 2:
            # Identifiers are typically (domain, unique_id) pairs
            return str(ident[0])
    return ''

@app.route('/')
def index():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/<path:path>')
def static_proxy(path):
    return send_from_directory(app.static_folder, path)

@app.route('/api/assets')
def get_assets():
    try:
        assets = db.get_assets_with_services()
        # Attach cached DNS profiles
        dns_profiles = db.get_all_dns_profiles()
        # Pre-fetch HA device registry (cached, ~5min TTL)
        _fetch_ha_device_registry()
        for a in assets:
            mac = a.get('mac_address')
            ip = a.get('ip_address')
            a['dns_profile'] = dns_profiles.get(mac)

            # If asset has confirmed HA device link, sync from HA registry
            ha_dev_id = a.get('ha_device_id')
            if ha_dev_id:
                ha_dev = next((d for d in _ha_device_cache['devices'] if d.get('id') == ha_dev_id), None)
                if ha_dev:
                    a['ha_device'] = {
                        'id': ha_dev_id,
                        'name': ha_dev.get('name_by_user') or ha_dev.get('name', ''),
                        'manufacturer': ha_dev.get('manufacturer', ''),
                        'model': ha_dev.get('model', ''),
                        'sw_version': ha_dev.get('sw_version', ''),
                        'hw_version': ha_dev.get('hw_version', ''),
                        'area_id': ha_dev.get('area_id', ''),
                        'integration': _get_integration_from_identifiers(ha_dev),
                        'confirmed': True,
                    }
                else:
                    # HA device was removed from registry
                    a['ha_device'] = {'id': ha_dev_id, 'confirmed': True, 'missing': True}
            else:
                # Try auto-matching unconfirmed
                ha_dev = _match_ha_device(mac, ip)
                if ha_dev:
                    a['ha_device'] = {
                        'id': ha_dev.get('id', ''),
                        'name': ha_dev.get('name_by_user') or ha_dev.get('name', ''),
                        'manufacturer': ha_dev.get('manufacturer', ''),
                        'model': ha_dev.get('model', ''),
                        'sw_version': ha_dev.get('sw_version', ''),
                        'hw_version': ha_dev.get('hw_version', ''),
                        'area_id': ha_dev.get('area_id', ''),
                        'integration': _get_integration_from_identifiers(ha_dev),
                        'confirmed': False,
                    }
                else:
                    a['ha_device'] = None
        return jsonify(assets)
    except Exception as e:
        logger.error(f"Error fetching assets: {e}", exc_info=True)
        return jsonify({"error": "An internal error occurred"}), 500

@app.route('/api/vulnerabilities')
def get_vulnerabilities():
    try:
        vulnerabilities = db.get_all_vulnerabilities()
        return jsonify(vulnerabilities)
    except Exception as e:
        logger.error(f"Error fetching vulnerabilities: {e}", exc_info=True)
        return jsonify({"error": "An internal error occurred"}), 500

@app.route('/api/assets/approve', methods=['POST'])
def approve_asset():
    try:
        data = request.json
        if not data:
            return jsonify({"error": "Invalid or missing JSON body"}), 400
        mac = data.get('mac')
        if not mac:
            return jsonify({"error": "MAC address required"}), 400
        db.approve_asset(mac)
        return jsonify({"status": "success"})
    except Exception as e:
        logger.error(f"Error approving asset: {e}", exc_info=True)
        return jsonify({"error": "An internal error occurred"}), 500

@app.route('/api/analyze/metadata', methods=['POST'])
def analyze_metadata():
    try:
        _reload_config()  # Ensure fresh LLM config
        data = request.json
        if not data:
            return jsonify({"error": "Invalid or missing JSON body"}), 400
        name = data.get('name')
        hostname = data.get('hostname')
        mac = data.get('mac')
        
        # Get OUI from asset if possible, or pass none
        asset = db.get_asset(mac)
        oui = asset.get('oui_vendor') if asset else None

        # Include DNS fingerprint data if available
        dns_profile = db.get_dns_profile(mac) if mac else None
        dns_context = None
        if dns_profile:
            dns_context = {
                "top_domains": dns_profile.get("top_domains", [])[:10],
                "platforms": dns_profile.get("platforms", {}),
                "suggested_type": dns_profile.get("suggested_type"),
                "suggested_vendor": dns_profile.get("suggested_vendor"),
            }

        # Include HA device registry data if matched
        ha_dev = _match_ha_device(mac, asset.get('ip_address') if asset else None)
        ha_context = None
        if ha_dev:
            ha_context = {
                "name": ha_dev.get('name_by_user') or ha_dev.get('name', ''),
                "manufacturer": ha_dev.get('manufacturer', ''),
                "model": ha_dev.get('model', ''),
                "sw_version": ha_dev.get('sw_version', ''),
                "integration": _get_integration_from_identifiers(ha_dev),
            }

        result = analyzer.infer_device_metadata(name, hostname, mac, oui,
                                                dns_fingerprint=dns_context,
                                                ha_device=ha_context)
        
        if result:
            return jsonify(result)
        else:
            return jsonify({"error": "LLM returned no data"}), 500
            
    except Exception as e:
        logger.error(f"Error in analyze_metadata: {e}", exc_info=True)
        return jsonify({"error": "An internal error occurred"}), 500

@app.route('/api/analyze/cve', methods=['POST'])
def analyze_cve():
    try:
        _reload_config()  # Ensure fresh LLM config
        data = request.json
        if not data:
            return jsonify({"error": "Invalid or missing JSON body"}), 400
        mac = data.get('mac')
        cve_id = data.get('cve_id')

        if not mac or not cve_id:
            return jsonify({"error": "Missing mac or cve_id"}), 400

        asset = db.get_asset(mac)
        if not asset:
            return jsonify({"error": "Asset not found"}), 404

        # Verify we have enough metadata for a meaningful analysis
        if not asset.get('actual_fw_version'):
            return jsonify({
                "result": "INCONCLUSIVE",
                "reason": "Missing firmware version. Please verify firmware first.",
                "method": "pre-check"
            })

        # Targeted lookup instead of fetching all vulnerabilities
        vuln = db.get_vulnerability(mac, cve_id)
        
        if not vuln:
             return jsonify({"error": "Vulnerability not found on this asset"}), 404

        description = vuln.get('description', '')
        analysis = analyzer.analyze(cve_id, description, asset)
        
        return jsonify(analysis)

    except Exception as e:
        logger.error(f"Error in analyze_cve: {e}", exc_info=True)
        return jsonify({"error": "An internal error occurred"}), 500

@app.route('/api/assets/update', methods=['POST'])
def update_asset():
    try:
        data = request.json
        if not data:
            return jsonify({"error": "Invalid or missing JSON body"}), 400
        mac = data.get('mac')
        if not mac:
            return jsonify({"error": "MAC address required"}), 400
        
        fw_ver = data.get('actual_fw_version')
        db.update_asset_governance(
            mac=mac,
            custom_name=data.get('custom_name'),
            location=data.get('location'),
            device_type=data.get('device_type'),
            tags=data.get('tags'),
            confirmed_integrations=data.get('confirmed_integrations'),
            dismissed_integrations=data.get('dismissed_integrations'),
            actual_fw_version=fw_ver,
            model=data.get('model'),
            os=data.get('os'),
            vendor=data.get('vendor'),
            dismissed_fw_version=data.get('dismissed_fw_version'),
            dismissed_vendor=data.get('dismissed_vendor'),
            manual_parent_mac=data.get('manual_parent_mac'),
            ha_device_id=data.get('ha_device_id')
        )
        
        # Trigger immediate re-assessment if firmware was updated
        if fw_ver:
            try:
                from sentinel.core import reassess_vulnerabilities
                reassess_vulnerabilities(mac)
            except Exception as e:
                logger.error(f"Error during manual re-assessment: {e}")

        return jsonify({"status": "success"})
    except Exception as e:
        logger.error(f"Error updating asset: {e}", exc_info=True)
        return jsonify({"error": "An internal error occurred"}), 500

@app.route('/api/ha/integrations')
def get_ha_integrations():
    """
    Fetches the list of installed integrations from Home Assistant Core.
    Uses the SUPERVISOR_TOKEN provided in the add-on environment.
    """
    token = os.getenv("SUPERVISOR_TOKEN")
    if not token:
        logger.warning("SUPERVISOR_TOKEN not available. Returning empty integration list.")
        return jsonify([])
    
    try:
        url = "http://supervisor/core/api/config"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        config = response.json()
        
        # 'components' contains the list of installed integrations/platforms
        components = config.get("components", [])
        return jsonify(components)
    except Exception as e:
        logger.error(f"Error fetching HA integrations: {e}", exc_info=True)
        return jsonify({"error": "An internal error occurred"}), 500

@app.route('/api/ha/devices')
def get_ha_devices():
    """
    Returns the HA device registry (cached with 5-min TTL).
    Used by the frontend to display device matches and enrichment data.
    """
    try:
        devices = _fetch_ha_device_registry()
        return jsonify({"devices": devices, "ha_available": len(devices) > 0})
    except Exception as e:
        logger.error(f"Error fetching HA devices: {e}", exc_info=True)
        return jsonify({"devices": [], "ha_available": False})

@app.route('/api/ha/confirm', methods=['POST'])
def confirm_ha_device():
    """
    Confirm or unlink an HA device match for a network asset.
    On confirm: auto-fills vendor, model, custom_name, location from HA data
    and stores ha_device_id to keep fields in sync.
    On unlink: clears ha_device_id (fields remain as-is for manual editing).
    """
    try:
        data = request.json
        if not data:
            return jsonify({"error": "Invalid or missing JSON body"}), 400
        mac = data.get('mac')
        action = data.get('action')  # 'confirm' or 'unlink'
        ha_device_id = data.get('ha_device_id')

        if not mac or not action:
            return jsonify({"error": "mac and action required"}), 400

        if action == 'unlink':
            db.update_asset_governance(mac=mac, ha_device_id='')
            return jsonify({"status": "unlinked"})

        if action == 'confirm' and ha_device_id:
            # Find the device in our cache
            devices = _fetch_ha_device_registry()
            ha_dev = next((d for d in devices if d.get('id') == ha_device_id), None)

            if not ha_dev:
                return jsonify({"error": "HA device not found in registry"}), 404

            # Auto-fill fields from HA device data
            ha_name = ha_dev.get('name_by_user') or ha_dev.get('name', '')
            ha_mfr = ha_dev.get('manufacturer', '')
            ha_model = ha_dev.get('model', '')
            ha_area = ha_dev.get('area_id', '')
            ha_integration = _get_integration_from_identifiers(ha_dev)

            # Build update fields — only overwrite if HA has data
            update_kwargs = {'mac': mac, 'ha_device_id': ha_device_id}
            if ha_name:
                update_kwargs['custom_name'] = ha_name
            if ha_mfr:
                update_kwargs['vendor'] = ha_mfr
            if ha_model:
                update_kwargs['model'] = ha_model
            if ha_area:
                update_kwargs['location'] = ha_area
            if ha_integration:
                # Auto-confirm the integration
                asset = db.get_asset(mac)
                confirmed = json.loads(asset.get('confirmed_integrations', '[]')) if asset else []
                if ha_integration not in confirmed:
                    confirmed.append(ha_integration)
                update_kwargs['confirmed_integrations'] = json.dumps(confirmed)

            db.update_asset_governance(**update_kwargs)

            return jsonify({
                "status": "confirmed",
                "applied": {
                    "custom_name": ha_name,
                    "vendor": ha_mfr,
                    "model": ha_model,
                    "location": ha_area,
                    "integration": ha_integration
                }
            })

        return jsonify({"error": "Invalid action"}), 400
    except Exception as e:
        logger.error(f"Error confirming HA device: {e}", exc_info=True)
        return jsonify({"error": "An internal error occurred"}), 500

@app.route('/api/investigate/dns', methods=['POST'])
def investigate_dns():
    """
    Query AdGuard Home DNS logs for an asset's IP to extract a device fingerprint.
    Returns top queried domains, platform indicators, and suggested device type.
    """
    try:
        _reload_config()
        data = request.json
        if not data:
            return jsonify({"error": "Invalid or missing JSON body"}), 400
        mac = data.get('mac')
        if not mac:
            return jsonify({"error": "MAC address required"}), 400

        if not adguard_client:
            return jsonify({"error": "AdGuard Home integration not configured"}), 400

        # Look up the asset's IP address
        asset = db.get_asset(mac)
        if not asset:
            return jsonify({"error": "Asset not found"}), 404

        ip = asset.get('ip_address')
        if not ip:
            return jsonify({"error": "Asset has no IP address"}), 400

        result = adguard_client.get_dns_fingerprint(ip)
        result["ip"] = ip
        result["mac"] = mac

        # Persist the scan results
        if result.get("status") == "ok":
            db.upsert_dns_profile(mac, result)

        return jsonify(result)

    except Exception as e:
        logger.error(f"Error investigating DNS for asset: {e}", exc_info=True)
        return jsonify({"error": "An internal error occurred"}), 500

@app.route('/api/adguard/status')
def adguard_status():
    """Returns AdGuard Home connection health status."""
    if not adguard_client:
        return jsonify({"configured": False, "connected": False})
    result = adguard_client.test_connection()
    result["configured"] = True
    return jsonify(result)

@app.route('/api/config')
def get_config():
    """
    Returns public configuration for the frontend.
    """
    try:
        # Check if LLM is enabled in options
        llm_enabled = config['options'].get('llm_enabled', False)
        router_host = config['options'].get('router_host', '192.168.1.1')
        return jsonify({
            "llm_enabled": llm_enabled,
            "router_host": router_host,
            "version": _ADDON_VERSION,
            "adguard_enabled": adguard_client is not None
        })
    except Exception as e:
        logger.error(f"Error fetching config: {e}", exc_info=True)
        return jsonify({"error": "An internal error occurred"}), 500

@app.route('/api/stats')
def get_stats():
    try:
        assets = db.get_assets()
        vulns = db.get_all_vulnerabilities()
        
        # Risk Distribution
        risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "SECURE": 0}
        asset_risks = {} # mac -> max_score
        
        for v in vulns:
            if v.get('status') == 'suppressed':
                continue
            mac = v['mac_address']
            score = v['cvss_score'] or 0
            if mac not in asset_risks or score > asset_risks[mac]:
                asset_risks[mac] = score
        
        priority_list = []
        categorized_count = 0
        named_count = 0
        integrated_count = 0
        
        for a in assets:
            mac = a['mac_address']
            score = asset_risks.get(mac, 0)
            if score >= 9: risk_counts["CRITICAL"] += 1
            elif score >= 7: risk_counts["HIGH"] += 1
            elif score >= 4: risk_counts["MEDIUM"] += 1
            elif score > 0: risk_counts["LOW"] += 1
            else: risk_counts["SECURE"] += 1
            
            if a.get('device_type') and a['device_type'] != 'Unknown': categorized_count += 1
            if a.get('custom_name'): named_count += 1
            if a.get('confirmed_integrations') and a['confirmed_integrations'] != '[]': integrated_count += 1
            
            if score >= 7:
                priority_list.append({
                    "mac": mac,
                    "name": a.get('custom_name') or a.get('hostname') or a.get('ip_address'),
                    "score": score,
                    "type": a.get('device_type') or 'Unknown'
                })
        
        priority_list.sort(key=lambda x: x['score'], reverse=True)

        # Filter out suppressed for total count
        active_vulns = [v for v in vulns if v.get('status') != 'suppressed']

        return jsonify({
            "total_assets": len(assets),
            "total_vulnerabilities": len(active_vulns),
            "risk_distribution": risk_counts,
            "governance": {
                "categorized": categorized_count,
                "named": named_count,
                "integrated": integrated_count,
                "total": len(assets)
            },
            "priority_queue": priority_list[:5]
        })
    except Exception as e:
        logger.error(f"Error fetching stats: {e}", exc_info=True)
        return jsonify({"error": "An internal error occurred"}), 500

@app.route('/api/vulnerabilities/suppress', methods=['POST'])
def suppress_vulnerability():
    try:
        data = request.json
        if not data:
            return jsonify({"error": "Invalid or missing JSON body"}), 400
        mac = data.get('mac')
        cve_id = data.get('cve_id')
        reason = data.get('reason')
        logic = data.get('logic')
        user_ver = data.get('user_ver')
        
        if not mac or not cve_id:
            return jsonify({"error": "MAC and CVE ID required"}), 400
            
        db.suppress_vulnerability(mac, cve_id, reason, logic, user_ver)
        return jsonify({"status": "success"})
    except Exception as e:
        logger.error(f"Error suppressing vulnerability: {e}", exc_info=True)
        return jsonify({"error": "An internal error occurred"}), 500

@app.route('/api/report/security')
def export_security_report():
    try:
        # Use get_assets() — security report doesn't need service data
        assets = db.get_assets()
        vulns = db.get_all_vulnerabilities()
        
        # Build mapping for easier lookup
        asset_vulns = {}
        for v in vulns:
            mac = v['mac_address']
            if mac not in asset_vulns: asset_vulns[mac] = []
            asset_vulns[mac].append(v)

        output = io.StringIO()
        writer = csv.writer(output)
        
        # Header
        writer.writerow([
            "MAC Address", "IP Address", "Hostname", "Vendor", "Model", "OS", 
            "CVE ID", "CVSS Score", "Severity", "Description"
        ])
        
        for a in assets:
            mac = a['mac_address']
            vlist = asset_vulns.get(mac, [])
            
            if not vlist:
                # Still include asset even if no vulns
                writer.writerow([
                    mac, a.get('ip_address'), a.get('hostname'), a.get('vendor'), 
                    a.get('model'), a.get('os'), "None", "-", "SECURE", "No known vulnerabilities found."
                ])
            else:
                for v in vlist:
                    score = v.get('cvss_score') or 0
                    severity = "LOW"
                    if score >= 9: severity = "CRITICAL"
                    elif score >= 7: severity = "HIGH"
                    elif score >= 4: severity = "MEDIUM"
                    
                    writer.writerow([
                        mac, a.get('ip_address'), a.get('hostname'), a.get('vendor'), 
                        a.get('model'), a.get('os'), v.get('cve_id'), score, severity, v.get('description')
                    ])

        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-disposition": "attachment; filename=sentinel_security_report.csv"}
        )
    except Exception as e:
        logger.error(f"Error generating security report: {e}", exc_info=True)
        return jsonify({"error": "An internal error occurred"}), 500

if __name__ == '__main__':
    # For local debugging only — debug=False to prevent Werkzeug debugger exposure
    app.run(host='0.0.0.0', port=8099, debug=False)
