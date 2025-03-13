# PortSentinel AI

## Description
PortSentinel AI est un scanner de sécurité réseau intelligent qui identifie les ports ouverts sur un réseau local et utilise une analyse basée sur l'IA pour évaluer les risques de sécurité potentiels. L'outil est conçu pour être utilisé par des débutants en cybersécurité afin d'identifier rapidement les configurations risquées sur leur réseau.

## Caractéristiques principales
- **Scan de ports sécurisé** : Utilise Nmap via Python pour scanner les ports ouverts
- **Vérifications de sécurité** : Empêche les scans accidentels de réseaux externes
- **Évaluation intelligente des risques** : Classifie les risques de sécurité en fonction des ports ouverts
- **Recommandations personnalisées** : Suggère des actions pour remédier aux problèmes détectés
- **Rapports détaillés** : Génère des rapports en formats TXT, JSON et CSV
- **Interface interactive** : Guide l'utilisateur à travers le processus de scan

## Prérequis
- Python 3.6+
- Nmap installé sur votre système
- Modules Python : python-nmap, ipaddress

## Installation

### 1. Installer Nmap
- **Linux** : `sudo apt-get install nmap`
- **macOS** : `brew install nmap`
- **Windows** : Télécharger et installer depuis [nmap.org](https://nmap.org/download.html)

### 2. Installer les dépendances Python
```bash
pip install python-nmap ipaddress
```

### 3. Cloner le dépôt ou télécharger le script
```bash
git clone https://github.com/yourusername/portsentinel-ai.git
cd portsentinel-ai
```
ou simplement télécharger le fichier `portsentinel.py`.

## Utilisation

### Mode interactif
Exécutez le script sans arguments pour lancer le mode interactif :
```bash
python portsentinel.py
```

Le programme vous guidera à travers les étapes suivantes :
1. Vérification de votre adresse IP locale
2. Choix de la cible de scan (localhost, IP spécifique, réseau entier)
3. Sélection de l'intensité du scan
4. Choix des formats de sortie pour les rapports

### Mode ligne de commande
Vous pouvez aussi utiliser des arguments en ligne de commande :
```bash
python portsentinel.py --target 192.168.1.0/24 --intensity 2 --format txt,json
```

### Options principales
- `--target` : Adresse IP, hostname ou plage CIDR à scanner
- `--intensity` : Niveau d'intensité du scan (1=rapide, 2=standard, 3=intensif)
- `--format` : Formats de sortie des rapports (txt, json, csv)
- `--output-dir` : Répertoire pour les rapports (par défaut: "reports")

## Comprendre les résultats

### Niveaux de risque
- **CRITIQUE** : Vulnérabilité grave nécessitant une action immédiate
- **ÉLEVÉ** : Risque significatif nécessitant une attention rapide
- **MOYEN** : Préoccupation de sécurité potentielle à examiner
- **FAIBLE** : Risque minimal mais méritant d'être noté
- **INFO** : Information non considérée comme un risque

### Ports communs et risques associés
- 21 (FTP) : ÉLEVÉ - Protocole de transfert de fichiers non chiffré
- 22 (SSH) : MOYEN - Accès distant sécurisé mais devrait être limité
- 23 (Telnet) : CRITIQUE - Protocole d'accès distant non chiffré
- 80 (HTTP) : MOYEN - Serveur web non chiffré
- 443 (HTTPS) : FAIBLE - Serveur web chiffré (normal)
- 3389 (RDP) : ÉLEVÉ - Protocole de bureau à distance, cible fréquente d'attaques

## ⚠️ Bonnes pratiques de sécurité ⚠️
1. Scanner uniquement les réseaux sur lesquels vous avez l'autorisation
2. Commencer par scanner uniquement votre propre machine (localhost)
3. Éviter de scanner des réseaux d'entreprise sans autorisation
4. Fermer les ports inutilisés identifiés comme risqués

## Dépannage

### Nmap n'est pas détecté
Assurez-vous que Nmap est installé et ajouté à votre PATH système.

### Erreurs de permission
Sur Linux/macOS, vous pourriez avoir besoin d'exécuter avec sudo pour certaines fonctionnalités de scan :
```bash
sudo python portsentinel.py
```

### Scan trop lent
Utilisez l'option d'intensité 1 pour un scan plus rapide ou limitez votre scan à une seule adresse IP.

## Fonctionnalités avancées
- **Base de données de connaissances évolutive** : L'outil mémorise les nouvelles associations port-risque
- **Analyse détaillée des services** : Identifie les versions des services pour une évaluation plus précise
- **Détection de configurations inappropriées** : Signale les combinaisons de ports qui présentent un risque élevé


## 📜 Licence  
Ce projet est privé et **ne peut pas être utilisé, modifié ou distribué sans autorisation**.  
Tous droits réservés © 2025.  

## Avertissement
Cet outil est destiné à des fins éducatives et de sécurité défensive. Utilisez-le uniquement sur des réseaux pour lesquels vous avez l'autorisation explicite de réaliser des tests de sécurité.
