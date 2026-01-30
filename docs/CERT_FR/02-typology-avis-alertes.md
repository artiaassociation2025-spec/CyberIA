# 2. Présentation générale — CERT-FR / ANSSI / Avis & Alertes

## 2.1 ANSSI
L'**ANSSI (Agence nationale de la sécurité des systèmes d'information)** est l'autorité nationale française en matière de cyberdéfense et de sécurité numérique.

Dans ce contexte, le **CERT-FR** (Centre gouvernemental de veille, d'alerte et de réponse aux attaques informatiques) est le bras opérationnel de l'ANSSI chargé de la veille et de la réaction aux incidents.

## 2.2 Identifiants CERT-FR
Contrairement à une CVE qui identifie une faille unique, un **Avis** ou une **Alerte** CERT-FR est un document composite qui peut regrouper plusieurs vulnérabilités. Il possède son propre identifiant unique.

Exemple : `CERTFR-2024-ALE-012` ou `CERTFR-2024-AVI-345`

Le document fournit principalement :
- une analyse du risque (critique/élevé)
- **les identifiants CVE associés** (intégrés dans la description)
- une liste de produits concernés
- une solution ou contournement (workaround)

## 2.3 Rôle du CERT-FR
Le **CERT-FR** ne cherche pas l'exhaustivité (rôle de la NVD), mais la **qualification** et la **contextualisation** de la menace pour les entités françaises (administrations, OIV, entreprises).

### Mission principale
- Filtrer le bruit (ne publier que sur les vulnérabilités pertinentes/impactantes)
- Contextualiser la menace (exploitation active, impact métier)
- Fournir des recommandations validées par l'autorité nationale

### Données qualifiées disponibles
- **Distinction Avis / Alerte** : Niveau d'urgence opérationnelle
- **Mapping CVE** : Lien vers les identifiants internationaux
- **Systèmes affectés** : Liste explicite des versions touchées
- **Recommandations** : Instructions de patch ou mesures conservatoires en français

> Phrase de synthèse : **NVD = Base exhaustive (Dictionnaire) ; CERT-FR = Intelligence qualifiée (Conseiller/Alerte).**

## 2.4 Cas d’usage
- Veille opérationnelle quotidienne (Avis) et gestion de crise (Alertes)
- Priorisation "Fast-track" des correctifs (si Alerte ANSSI → Patch immédiat)
- Enrichissement des tickets d'incidents avec contexte francophone
- Conformité réglementaire (LPM, NIS 2) : suivi des recommandations étatiques
- Communication interne/COMEX (vulgarisation du risque via les résumés ANSSI)