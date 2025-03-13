# PortSentinel AI

## Description

PortSentinel AI est un scanner de ports réseau intelligent conçu pour les débutants et les professionnels de la cybersécurité. Il identifie les ports ouverts sur un réseau et utilise une analyse basée sur l'IA pour évaluer les risques de sécurité potentiels. Cette version fonctionne sans dépendre de Nmap, utilisant des bibliothèques Python pures pour une portabilité et une facilité d'utilisation améliorées.

## Caractéristiques Principales

*   **Scan de Ports Complet:** Identifie les ports TCP ouverts sur un système ou un réseau cible.
*   **Évaluation Intelligente des Risques:** Classe les risques de sécurité en fonction des ports ouverts identifiés et des vulnérabilités connues, en utilisant un moteur de risque inspiré par l'IA.
*   **Intensité de Scan Personnalisable:** Offre des modes de scan "rapide", "standard" et "intensif" pour équilibrer la vitesse et la profondeur de l'analyse.
*   **Contrôles de Sécurité:** Empêche le scan accidentel de réseaux externes grâce à des mécanismes de sécurité intégrés.
*   **Recommandations Claires:** Suggère des actions pour atténuer les problèmes de sécurité identifiés.
*   **Rapports Textuels Détaillés:** Génère des rapports faciles à comprendre au format texte brut.
*   **Interface Utilisateur Graphique (GUI):** Fournit une expérience interactive avec des commandes simples pour la sélection de la cible, l'intensité du scan et l'affichage des résultats.
*   **Scan Multithread:** Utilise le multithreading pour un scan de ports plus rapide et plus efficace.

## Prérequis

*   Python 3.6+
*   Tkinter (généralement inclus avec Python, mais peut nécessiter une installation séparée sur certains systèmes)
*   Aucune dépendance externe n'est requise au-delà des bibliothèques Python standard.

## Installation

1.  Assurez-vous que Python 3.6 ou supérieur est installé.
2.  Téléchargez le fichier `port_sentinel.py`.

    ```bash
    wget https://github.com/yourusername/portsentinel-ai/blob/main/port_sentinel.py # Ou clonez le dépôt si vous préférez
    ```

## Utilisation

### Mode Interface Utilisateur Graphique (GUI)

1.  Exécutez le script :

    ```bash
    python port_sentinel.py
    ```

2.  L'interface graphique de PortSentinel AI apparaîtra.
3.  Entrez l'adresse IP ou la plage réseau cible dans le champ "Target IP/Network".
4.  Choisissez l'intensité du scan dans le menu déroulant "Intensity" (Quick, Standard ou Intensive).
5.  Cochez la case "Scan Common Ports Only" pour ne scanner qu'un ensemble limité de ports courants.
6.  Cliquez sur le bouton "Start Scan".
7.  Les résultats du scan et l'évaluation des risques seront affichés dans la zone de texte.

### Génération de Rapports

*   Les résultats du scan, y compris une évaluation des risques et des recommandations, sont affichés directement dans l'interface graphique.
*   Pour enregistrer le rapport, copiez le contenu de la zone de texte des résultats dans un fichier texte.

### Comprendre les Résultats

#### Niveaux de Risque

*   **CRITICAL:** Vulnérabilité grave nécessitant une action immédiate.
*   **HIGH:** Risque significatif nécessitant une attention rapide.
*   **MEDIUM:** Préoccupation de sécurité potentielle à examiner.
*   **LOW:** Risque minimal, mais à noter.
*   **INFO:** Information qui n'est pas considérée comme un risque.

#### Ports Courants et Risques Associés

*   21 (FTP) : HIGH - Protocole de transfert de fichiers non chiffré.
*   22 (SSH) : MEDIUM - Accès distant sécurisé, mais doit être limité.
*   23 (Telnet) : CRITICAL - Protocole d'accès distant non chiffré.
*   80 (HTTP) : MEDIUM - Serveur web non chiffré.
*   443 (HTTPS) : LOW - Serveur web chiffré (normal).
*   3389 (RDP) : HIGH - Protocole de bureau à distance, une cible fréquente pour les attaques.

⚠️ **Meilleures Pratiques de Sécurité** ⚠️

*   Ne scannez que les réseaux pour lesquels vous avez l'autorisation de scanner.
*   Commencez par scanner uniquement votre propre machine (localhost).
*   Évitez de scanner les réseaux d'entreprise sans autorisation.
*   Fermez les ports inutilisés identifiés comme risqués.

### Dépannage

#### GUI ne s'affiche pas correctement

*   Assurez-vous que Tkinter est installé correctement. Sur certains systèmes, vous devrez peut-être l'installer séparément :

    ```bash
    sudo apt-get install python3-tk  # Debian/Ubuntu
    ```

#### Scan Trop Lent

*   Utilisez l'option d'intensité "Quick" pour un scan plus rapide.
*   Limitez votre scan à une seule adresse IP.

### Fonctionnalités Avancées

*   Base de Connaissances Évolutive : l'outil mémorise les nouvelles associations port-risque.
*   Analyse Détaillée des Services : identifie les versions de service pour une évaluation plus précise.
*   Détection des Configurations Incorrectes : signale les combinaisons de ports qui présentent un risque élevé.

## Licence

Ce projet est privé et ne peut être utilisé, modifié ou distribué sans autorisation.
Tous droits réservés © 2025.

### Clause de Non-Responsabilité

Cet outil est destiné à des fins éducatives et de sécurité défensive. Utilisez-le uniquement sur les réseaux pour lesquels vous avez une autorisation explicite d'effectuer des tests de sécurité.
