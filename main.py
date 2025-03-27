import socket
import json
from flask import Flask, request, jsonify
from flask_cors import CORS
from sentence_transformers import SentenceTransformer
import numpy as np
import faiss

app = Flask(__name__)
CORS(app)  # Permet les requêtes cross-origin depuis le frontend


def scan_ports(target_ip, mode, ports=[21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389]):
    open_ports = []
    closed_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target_ip, port))
        service = get_service_by_port(port)
        port_info = {
            "number": port,
            "service": service if service else "unknown",
            "status": "open" if result == 0 else "closed",
            "riskLevel": determine_risk_level(port, result == 0)
        }
        if result == 0:
            print(f"[+] Port {port} ouvert")
            open_ports.append(port_info)
        else:
            print(f"[-] Port {port} fermé")
            closed_ports.append(port_info)
        sock.close()

    # Ajuster le nombre de ports scannés selon le mode
    if mode == "quick":
        return open_ports[:2] + closed_ports[:2]  # Scan rapide
    elif mode == "medium":
        return open_ports[:5] + closed_ports[:5]  # Scan moyen
    else:  # slow
        return open_ports + closed_ports  # Scan complet


def determine_risk_level(port, is_open):
    # Logique simple pour déterminer le niveau de risque
    high_risk_ports = [21, 22, 23, 3389]  # Ports souvent ciblés
    medium_risk_ports = [80, 443, 3306]
    if is_open:
        if port in high_risk_ports:
            return "HIGH"
        elif port in medium_risk_ports:
            return "MEDIUM"
        else:
            return "LOW"
    return "INFO"


def fetch_cve_for_ports(ports):
    model = SentenceTransformer("all-MiniLM-L6-v2")
    index = load_faiss_index()
    cve_results = {}
    open_port_numbers = [port["number"] for port in ports if port["status"] == "open"]

    for port in open_port_numbers:
        service = get_service_by_port(port)
        if service:
            print(f"Recherche de CVE pour {service}...")
            query_vector = model.encode(service).reshape(1, -1)
            cves = search_cve_with_faiss(index, query_vector)
            # Formater les CVE pour correspondre au format attendu par le frontend
            if cves and cves != ["Index FAISS non disponible"]:
                cve_results[port] = [
                    {
                        "id": cve.get("id", "Unknown") if isinstance(cve, dict) else str(cve),
                        "title": cve.get("title", "No title") if isinstance(cve, dict) else str(cve),
                        "severity": cve.get("severity", "UNKNOWN") if isinstance(cve, dict) else "UNKNOWN",
                        "description": cve.get("description", "No description available") if isinstance(cve,
                                                                                                        dict) else str(
                            cve)
                    } for cve in cves
                ]
            else:
                cve_results[port] = []
        else:
            cve_results[port] = []

    # Ajouter une liste vide pour les ports fermés ou sans service
    for port in ports:
        if port["number"] not in cve_results:
            cve_results[port["number"]] = []

    return cve_results


def get_service_by_port(port):
    services = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
        53: "dns", 80: "http", 110: "pop3", 143: "imap",
        443: "https", 3306: "mysql", 3389: "rdp"
    }
    return services.get(port, None)


def load_faiss_index():
    try:
        index = faiss.read_index("cve_index.faiss")
        with open("cve_data.json", "r") as f:
            cve_data = json.load(f)
        return index, cve_data
    except Exception as e:
        print(f"Erreur lors du chargement de FAISS : {e}")
        return None, None


def search_cve_with_faiss(index_data, query_vector):
    index, cve_data = index_data
    if index is None or cve_data is None:
        return ["Index FAISS non disponible"]
    D, I = index.search(query_vector, 5)
    return [cve_data[i] for i in I[0] if i != -1]


@app.route('/api/scan', methods=['POST'])
def scan():
    data = request.get_json()
    target_ip = data.get('targetIp')
    mode = data.get('mode')

    if not target_ip or not mode:
        return jsonify({"error": "Missing targetIp or mode"}), 400

    # Effectuer le scan des ports
    ports = scan_ports(target_ip, mode)

    # Rechercher les CVE pour les ports ouverts (attendre que cette étape soit terminée)
    cve_results = fetch_cve_for_ports(ports)

    # Préparer la réponse seulement après que tout est terminé
    response = {
        "ports": ports,
        "cveAlerts": cve_results  # Dictionnaire {port: [CVE]}
    }
    print(response)
    return jsonify(response), 200


if __name__ == "__main__":
    app.run(host='127.0.0.1', port=5000, debug=True)
