# 🚀 Installation et Exécution du Projet

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
2. Dans une autre console, installez les dépendances Python :
   ```sh
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
python3 main2.py
```

---
🎯 **Conseil** : Pour une exécution fluide, utilisez un gestionnaire de processus comme `pm2` pour Node.js et `supervisor` pour Python.

