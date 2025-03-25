from flask import Flask, request, jsonify
from flask_cors import CORS
import nmap

app = Flask(_name_)
CORS(app)  # Permet les requêtes Cross-Origin

@app.route('/api/scan', methods=['POST'])
def scan():
    try:
        data = request.json  # Récupérer les données envoyées par React
        target_ip = data.get("targetIp")
        mode = data.get("mode", "quick")

        if not target_ip:
            return jsonify({"error": "No target IP provided"}), 400

        scanner = nmap.PortScanner()
        
        if mode == "quick":
            scanner.scan(target_ip, arguments="-T4 -F")  # Scan rapide
        else:
            scanner.scan(target_ip, arguments="-T4 -p 1-65535")  # Scan complet
        
        open_ports = [
            {"port": int(port), "state": scanner[target_ip]["tcp"][int(port)]["state"]}
            for port in scanner[target_ip].all_tcp()
        ]

        return jsonify({"ports": open_ports})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if _name_ == '_main_':
    app.run(host="0.0.0.0", port=5000, debug=True)