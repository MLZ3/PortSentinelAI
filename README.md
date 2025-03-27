### Installation et Exécution du Projet

## ℹ️ Introduction
Ce projet universitaire utilise un modèle de **Retrieval-Augmented Generation (RAG)** basé sur **Sentence Transformers** pour améliorer la récupération d'informations et l'interaction avec les données. Il combine des techniques avancées de traitement du langage naturel et de recherche vectorielle pour offrir des résultats précis et pertinents en allant chercher des CVE pour s'actualiser sur le niveau de criticité des ports ouverts.

## 📁 Pré-requis
Assurez-vous d'avoir installé :
- **Node.js** (avec `npm`)
- **Python 3** et `pip`

## 📦 Installation

1. Rendez-vous dans le répertoire du site :
   ```sh
   cd site
   ```
2. Installez les dépendances Node.js :
   ```sh
   npm install
   ```

## 🖥️ Démarrage du Projet

1. Lancez le serveur de développement :
   ```sh
   npm run dev
   ```
2. Dans une autre console, revenez au répertoire parent et installez les dépendances Python :
   ```sh
   cd ..
   pip install -r requirements.txt
   ```

## 📡 Entraînement du Modèle
L'entraînement du modèle doit être exécuté régulièrement. Ajoutez cette commande dans un **cron job** pour une mise à jour automatique toutes les X minutes :
```sh
python3 cve_faiss.py
```

## 🏗️ Lancement du Backend

Pour démarrer le backend interagissant avec le site :
```sh
python3 main.py
```


## 🔒 Confidentialité et utilisation
Ce projet est destiné à des fins éducatives et "Blue Team" uniquement. L'utilisation de cet outil est strictement encadré et vous ne pouvez pas faire de scans de ports sur n'importe quelle addresse ip légalement. 


## 📝 Licence
Licence Propriétaire - Toute utilisation, modification, distribution, ou reproduction de ce projet sans autorisation explicite écrite du propriétaire est strictement interdite. Ce projet est fourni tel quel, sans garantie d'aucune sorte. L'utilisation non autorisée de ce projet entraînera des poursuites judiciaires. © 2025 Tous Droits Réservés.

## 👥 Contributeurs
Mehdi L - Alexandre Pl - Alexandre Po
