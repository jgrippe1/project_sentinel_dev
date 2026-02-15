import logging
import os
import requests
from flask import Flask, jsonify, send_from_directory, request
from sentinel.datastore import Datastore

# Configure Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("SentinelAPI")

app = Flask(__name__, static_folder='static')
db = Datastore()

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

@app.route('/api/assets/update', methods=['POST'])
def update_asset():
    try:
        data = request.json
        mac = data.get('mac')
        if not mac:
            return jsonify({"error": "MAC address required"}), 400
        
        db.update_asset_governance(
            mac=mac,
            custom_name=data.get('custom_name'),
            location=data.get('location'),
            device_type=data.get('device_type'),
            tags=data.get('tags'),
            confirmed_integrations=data.get('confirmed_integrations'),
            dismissed_integrations=data.get('dismissed_integrations'),
            model=data.get('model'),
            os=data.get('os'),
            fw_version=data.get('fw_version'),
            hw_version=data.get('hw_version'),
            vendor=data.get('vendor')
        )
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

@app.route('/api/stats')
def get_stats():
    try:
        assets = db.get_assets()
        vulns = db.get_all_vulnerabilities()
        
        # Risk Distribution
        risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "SECURE": 0}
        asset_risks = {} # mac -> max_score
        
        for v in vulns:
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

        return jsonify({
            "total_assets": len(assets),
            "total_vulnerabilities": len(vulns),
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

if __name__ == '__main__':
    # For local debugging
    app.run(host='0.0.0.0', port=8099, debug=True)
