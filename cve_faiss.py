import requests
from sentence_transformers import SentenceTransformer
import faiss
from faiss import IndexFlatL2  # Explicit import
import json
import numpy as np

# Fonction pour récupérer les CVE depuis CVE Search API
def fetch_cve_data():
    cve_items = []
    url = "https://cve.circl.lu/api/last"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        for item in data:
            if 'containers' in item and 'cna' in item['containers']:
                descriptions = item['containers']['cna'].get('descriptions', [])
                for description in descriptions:
                    if 'value' in description:
                        cve_item = {
                            'cveId': item['cveMetadata']['cveId'],
                            'description': description['value']
                        }
                        cve_items.append(cve_item)
    else:
        print(f"Erreur avec l'API (Code {response.status_code})")
    return cve_items

# Créer un index FAISS à partir des descriptions de CVE
def create_faiss_index(cve_items):
    model = SentenceTransformer('all-MiniLM-L6-v2')
    cve_descriptions = []
    cve_ids = []

    for item in cve_items:
        description = item.get('description', '')
        cve_id = item.get('cveId', '')
        cve_descriptions.append(description)
        cve_ids.append(cve_id)

    vectors = model.encode(cve_descriptions)

    dimension = vectors.shape[1]
    index = IndexFlatL2(dimension)  # Use the explicitly imported class
    index.add(np.array(vectors, dtype=np.float32))

    faiss.write_index(index, "cve_index.faiss")
    with open("cve_data.json", "w") as f:
        json.dump(cve_ids, f)

    print(f"Index FAISS créé et sauvegardé avec {len(cve_ids)} CVE.")

def main():
    cve_items = fetch_cve_data()
    if cve_items:
        print(f"{len(cve_items)} CVE récupérées.")
        create_faiss_index(cve_items)
    else:
        print("Aucune donnée CVE trouvée.")

if __name__ == "__main__":
    main()