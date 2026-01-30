# 3. Structure des données — Format XML (CERT-FR)

## 3.1 Objectif de cette section
Cette section décrit la structure des données du CERT-FR au format **XML (RSS 2.0)**, afin de permettre :
- l'ingestion des flux (Polling RSS),
- le parsing des balises standards et du contenu encapsulé (CDATA),
- l'extraction des identifiants et des liens de remédiation.

L’objectif est de comprendre **où se trouve chaque information** dans l'arborescence XML : ID de l'alerte, solution, dates, description technique et CVE associées.

---

## 3.2 Format général des données
Les données sont exposées via un flux RSS 2.0 standard.
Chaque publication (Alerte ou Avis) est représentée par une balise `<item>`.

### Balises globales clés (dans `<item>`)
Une entrée CERT-FR est structurée autour des balises XML suivantes :

- `<title>`
- `<link>`
- `<description>` (Contient du HTML/CDATA)
- `<pubDate>`
- `<guid>`

---

## 3.3 Détail balise par balise (modèle de données)

### 3.3.1 `<title>` — Identifiant et Résumé
- **Type** : string
- **Exemple** : `Multiples vulnérabilités dans les produits Mitel (24 juillet 2025)`
- **Usage** :
  - Identification rapide du sujet (Produit concerné).
  - *Note :* Sur les flux récents, l'ID peut ne pas être présent dans le titre.

⚠️ **Point de vigilance :**
Ne pas utiliser le titre comme clé primaire unique, car il peut changer lors d'une mise à jour (ajout de `[MaJ]`).

---

### 3.3.2 `<link>` — La Solution (Champ Critique)
- **Type** : URL
- **Exemple** : `https://www.cert.ssi.gouv.fr/avis/CERTFR-2025-AVI-0618/`
- **Usage** :
  - **Extraction de l'ID unique** : C'est la méthode la plus fiable (Regex sur l'URL).
  - **Accès à la remédiation** : C'est le lien à fournir aux équipes techniques pour appliquer les correctifs.

✅ Bonnes pratiques :
- Extraire l'ID depuis ce champ (ex: `CERTFR-2025-AVI-0618`).
- Stocker cette URL comme `solution_url`.

---

### 3.3.3 `<pubDate>` — Date de publication
- **Type** : string (Format RFC 822)
- **Exemple** : `Thu, 24 Jul 2025 00:00:00 +0000`
- **Usage** :
  - Ingestion incrémentale (ne traiter que ce qui est nouveau).
  - Détection des mises à jour.

✅ Usage opérationnel :
Convertir systématiquement en format **ISO-8601** (`YYYY-MM-DD`) pour uniformisation avec la NVD.

---

### 3.3.4 `<guid>` — Identifiant technique RSS
- **Type** : string (URL avec paramètres)
- **Exemple** : `https://www.cert.ssi.gouv.fr/avis/CERTFR-2025-AVI-0618/`
- **Attribut** : `isPermaLink="true"`
- **Usage** :
  - Dédoublonnage technique par le lecteur RSS.

---

## 3.4 Balise `<description>` — Le contenu riche (HTML)

### 3.4.1 Objectif de la balise
Contrairement à la NVD qui sépare les scores et les configurations, le CERT-FR encapsule tout le détail technique dans cette balise, sous format **HTML encapsulé dans une section CDATA**.

### 3.4.2 Structure interne (CDATA)
- **Type** : HTML String
- **Exemple de contenu brut** :
```xml
<description>
    <![CDATA[
    De multiples vulnérabilités ont été découvertes dans les produits Mitel.
    Elles permettent à un attaquant de provoquer une injection SQL (SQLi)...
    ]]>
</description>