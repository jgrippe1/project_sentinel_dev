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

# Load config similar to core.py
OPTIONS_PATH = "/data/options.json"
config = {"options": {}}
if os.path.exists(OPTIONS_PATH):
    try:
        with open(OPTIONS_PATH, 'r') as f:
            config["options"] = json.load(f)
            logger.info(f"Loaded {len(config['options'])} options from {OPTIONS_PATH}")
            if 'llm_enabled' in config['options']:
                logger.info(f"API Config LLM Status: {config['options']['llm_enabled']}")
            
            # Set Log Level
            verbose = config['options'].get('verbose_logging', False)
            log_level = logging.DEBUG if verbose else logging.INFO
            logging.getLogger().setLevel(log_level)
            logger.info(f"Log Level set to: {'DEBUG' if verbose else 'INFO'}")

    except Exception as e:
        logger.error(f"Failed to load options: {e}")

analyzer = HybridAnalyzer(config)

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
        return jsonify(assets)
    except Exception as e:
        logger.error(f"Error fetching assets: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/vulnerabilities')
def get_vulnerabilities():
    try:
        vulnerabilities = db.get_all_vulnerabilities()
        return jsonify(vulnerabilities)
    except Exception as e:
        logger.error(f"Error fetching vulnerabilities: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/assets/approve', methods=['POST'])
def approve_asset():
    try:
        data = request.json
        mac = data.get('mac')
        if not mac:
            return jsonify({"error": "MAC address required"}), 400
        db.approve_asset(mac)
        return jsonify({"status": "success"})
    except Exception as e:
        logger.error(f"Error approving asset: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/analyze/metadata', methods=['POST'])
def analyze_metadata():
    try:
        data = request.json
        name = data.get('name')
        hostname = data.get('hostname')
        mac = data.get('mac')
        
        # Get OUI from asset if possible, or pass none
        asset = db.get_asset(mac)
        oui = asset.get('oui_vendor') if asset else None

        result = analyzer.infer_device_metadata(name, hostname, mac, oui)
        
        if result:
            return jsonify(result)
        else:
            return jsonify({"error": "LLM returned no data"}), 500
            
    except Exception as e:
        logger.error(f"Error in analyze_metadata: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/analyze/cve', methods=['POST'])
def analyze_cve():
    try:
        data = request.json
        mac = data.get('mac')
        cve_id = data.get('cve_id')
        force_refresh = data.get('force_refresh', False)

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

        # Fetch vulns to get description
        # Ideally we'd have a get_cve(id) method, but we can search current vulns
        all_vulns = db.get_all_vulnerabilities()
        vuln = next((v for v in all_vulns if v['cve_id'] == cve_id and v['mac_address'] == mac), None)
        
        if not vuln:
             return jsonify({"error": "Vulnerability not found on this asset"}), 404

        description = vuln.get('description', '')

        # If force refresh, we might want to bypass cache in analyzer?
        # For now, analyzer checks cache first. 
        # To strictly force LLM, we'd need to bypass cache check in analyzer or clear cache.
        # Let's assume 'analyze' does what we need, but maybe we add a 'skip_cache' param to it?
        # checking cve_analyzer.py signature: def analyze(self, cve_id, cve_description, asset_context):
        # I'll rely on standard analysis for now. If user wants to force, they might need to clear previous result?
        # Actually, if we are "re-analyzing", it implies we think the previous result (SAFE/VULNERABLE) might be wrong
        # or that metadata changed. If metadata changed, cache key (ver+model) changes, so it won't hit cache.
        
        analysis = analyzer.analyze(cve_id, description, asset)
        
        return jsonify(analysis)

    except Exception as e:
        logger.error(f"Error in analyze_cve: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/assets/update', methods=['POST'])
def update_asset():
    try:
        data = request.json
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
            dismissed_vendor=data.get('dismissed_vendor')
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
        logger.error(f"Error updating asset: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/ha/integrations')
def get_ha_integrations():
    """
    Fetches the list of installed integrations from Home Assistant Core.
    Uses the SUPERVISOR_TOKEN provided in the add-on environment.
    """
    token = os.getenv("SUPERVISOR_TOKEN")
    if not token:
        # Fallback for local testing - return empty or a mock list
        return jsonify(["nginx", "ssh", "esphome", "generic", "adguard"])
    
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
        logger.error(f"Error fetching HA integrations: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/config')
def get_config():
    """
    Returns public configuration for the frontend.
    """
    try:
        # Check if LLM is enabled in options
        llm_enabled = config['options'].get('llm_enabled', False)
        return jsonify({
            "llm_enabled": llm_enabled,
            "version": "1.0.29" 
        })
    except Exception as e:
        logger.error(f"Error fetching config: {e}")
        return jsonify({"error": str(e)}), 500

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
        logger.error(f"Error fetching stats: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/vulnerabilities/suppress', methods=['POST'])
def suppress_vulnerability():
    try:
        data = request.json
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
        logger.error(f"Error suppressing vulnerability: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/report/security')
def export_security_report():
    try:
        assets = db.get_assets_with_services()
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
        logger.error(f"Error generating security report: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    # For local debugging
    app.run(host='0.0.0.0', port=8099, debug=True)
