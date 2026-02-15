import logging
import os
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
            owner=data.get('owner'),
            location=data.get('location'),
            device_type=data.get('device_type'),
            tags=data.get('tags')
        )
        return jsonify({"status": "success"})
    except Exception as e:
        logger.error(f"Error updating asset: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/stats')
def get_stats():
    try:
        assets = db.get_assets()
        vulnerabilities = db.get_all_vulnerabilities()
        
        critical_count = sum(1 for v in vulnerabilities if v.get('cvss_score', 0) >= 9.0)
        
        return jsonify({
            "total_assets": len(assets),
            "total_vulnerabilities": len(vulnerabilities),
            "critical_vulnerabilities": critical_count
        })
    except Exception as e:
        logger.error(f"Error fetching stats: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    # For local debugging
    app.run(host='0.0.0.0', port=8099, debug=True)
