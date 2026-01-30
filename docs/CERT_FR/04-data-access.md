# 4. Accès aux données (Flux RSS)

## 4.1 Vue d'ensemble
L'accès aux publications du CERT-FR se fait exclusivement via des flux de syndication **RSS (format XML)**.
Ces flux sont publics, ne nécessitent pas de clé d'API et contiennent les dernières publications de l'ANSSI.

## 4.2 Les 3 Flux Officiels (Endpoints)
Voici les URLs à configurer dans vos outils de collecte (Ingestion / ETL) :

| Type de Flux | URL (Endpoint) | Description et Usage |
| :--- | :--- | :--- |
| **Flux Global** | `https://www.cert.ssi.gouv.fr/feed/` | **Contenu :** Regroupe TOUT (Alertes, Avis, Bulletins et Actualités).<br>**Usage :** Recommandé pour l'archivage complet ou si vous ne souhaitez surveiller qu'une seule URL. |
| **Flux Alertes** | `https://www.cert.ssi.gouv.fr/alerte/feed/` | **Contenu :** Uniquement les **Alertes** (Menaces critiques nécessitant une action immédiate).<br>**Usage :** À surveiller à haute fréquence (ex: toutes les 15 min) pour le déclenchement d'astreintes. |
| **Flux Avis** | `https://www.cert.ssi.gouv.fr/avis/feed/` | **Contenu :** Uniquement les **Avis** (Mises à jour de sécurité régulières).<br>**Usage :** À surveiller quotidiennement pour alimenter le processus de gestion des vulnérabilités standard. |

## 4.3 Note technique
Une simple requête `HTTP GET` sur ces liens renvoie un fichier XML structuré contenant les derniers items publiés. Il n'y a pas de pagination : le flux contient généralement les 20 à 50 derniers éléments.