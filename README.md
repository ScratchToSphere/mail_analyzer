# PhishAnalyze - SOC Email Threat Intelligence Tool

![Version](https://img.shields.io/badge/version-3.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-green.svg)
![License](https://img.shields.io/badge/license-MIT-orange.svg)

**Outil d'analyse forensique avancée d'emails pour les équipes SOC (Blue Team)**

Analysez les emails suspects (.eml) avec des fonctionnalités de détection de phishing, spoofing, et threat intelligence.

---

## 🚀 Fonctionnalités v3.0 (Enterprise)

### 🏭 Industrialisation
- **Mode Batch** : Analyse automatique d'un dossier complet de fichiers .eml
- **Barre de progression** : Suivi visuel de l'avancement
- **Tableau récapitulatif** : Vue d'ensemble des menaces détectées dans le lot

### 🦠 Threat Intelligence
- **Intégration VirusTotal** : Vérification automatique des hashs de fichiers
- **Score de détection** : Affichage du ratio de détection (ex: `35/60`)
- **Gestion des Quotas** : Respect des limites API (4 req/min)

### 📤 Interopérabilité
- **Export JSON** : Sauvegarde des résultats structurés pour intégration SIEM/SOAR

---

## 🛡️ Fonctionnalités de Sécurité (Core)

### 📩 Section 1: ENVELOPPE
- **Méta-données complètes** : From, Reply-To, Return-Path, Subject, Date, Message-ID, X-Originating-IP
- **Authentification Email** :
  - ✅ Vérification **SPF** (Sender Policy Framework)
  - ✅ Vérification **DKIM** (DomainKeys Identified Mail)
  - 🔴 **Alertes CRITIQUES** si SPF/DKIM échouent
- **Route Tracking** : Extraction de toutes les IPs des headers `Received`

### ⚠️ Section 2: ALERTES DE SÉCURITÉ
- **Détection de Spoofing** : Compare `From` vs `Reply-To` (🟡 alerte JAUNE si différent)
- **Échecs d'authentification** : SPF/DKIM fail (🔴 alerte ROUGE)
- **Liens trompeurs** : Détection de liens HTML où le texte visible diffère de la destination réelle
- **Pièces jointes dangereuses** : Doubles extensions suspectes (.pdf.exe, .doc.scr, etc.)

### 🔗 Section 3: ANALYSE DES URLs
- **Parsing HTML avancé** avec BeautifulSoup4
- Extraction des liens `<a href="...">` avec détection d'homograph attacks
- **Defanging automatique** : `http` → `hxxp`, `.` → `[.]` (sécurité)

### 📎 Section 4: PIÈCES JOINTES
- Nom du fichier et détection de doubles extensions
- **Taille en Ko**
- **Hash SHA256**
- **Score VirusTotal** (si activé)

---

## 📦 Installation

### Prérequis
- Python 3.8+
- pip

### Dépendances
```bash
pip install rich beautifulsoup4 requests
```

---

## 🎯 Utilisation

### Mode Fichier Unique
```bash
python phish_analyze.py suspicious_email.eml
```

### Mode Batch (Dossier)
Analyse tous les fichiers `.eml` d'un répertoire :
```bash
python phish_analyze.py ./dossier_emails
```

### Options Avancées

#### Activer VirusTotal
Nécessite une clé API définie dans la variable d'environnement `VT_API_KEY`.
```bash
set VT_API_KEY=votre_cle_api_virustotal
python phish_analyze.py email.eml --vt
```

#### Export JSON
Pour intégration avec d'autres outils :
```bash
python phish_analyze.py email.eml --json resultat.json
```

---

## 📊 Exemples de Sortie

### Dashboard Console (Single Mode)
```
┌──────────────────────────────────────────────────────────┐
│ 🔍 PhishAnalyze v3.0 - SOC Email Threat Intelligence    │
└──────────────────────────────────────────────────────────┘

╔═══════════════════════════════════════════════════════════╗
║                  📎 PIÈCES JOINTES                        ║
╠═══════════════════════════════════════════════════════════╣
║ Nom         │ Extension(s)  │ VT Score    │ SHA256       ║
║ malware.exe │ .exe ⚠️       │ 🔴 45/60    │ a3b2c1d...   ║
╚═══════════════════════════════════════════════════════════╝
```

### Tableau Récapitulatif (Batch Mode)
```
          📊 RÉCAPITULATIF BATCH          
┌────────────┬──────────────┬────────────┬──────────────┐
│ Fichier    │ Sévérité     │ Alertes    │ VT Détections│
├────────────┼──────────────┼────────────┼──────────────┤
│ email1.eml │ 🟡 WARNING   │ 1          │ 0            │
│ email2.eml │ 🔴 CRITICAL  │ 3          │ 🔴 28        │
└────────────┴──────────────┴────────────┴──────────────┘
```

---

## 🔍 Détails Techniques

### API VirusTotal & Quotas
L'outil respecte automatiquement les quotas de l'API gratuite VT (4 requêtes/minute) en ajoutant une pause de 15s entre chaque requête si nécessaire.

### Structure JSON
```json
{
  "tool": "PhishAnalyze",
  "version": "3.0",
  "results": [
    {
      "file": "email.eml",
      "severity": "CRITICAL",
      "alerts": [
        { "level": "CRITICAL", "type": "SPF Failure", "message": "..." }
      ],
      "attachments": [
        {
          "filename": "malware.exe",
          "sha256": "...",
          "vt_results": { "malicious": 45, "total": 60 }
        }
      ]
    }
  ]
}
```

---

## 🤝 Contribution

1. Fork le projet
2. Créez une branche (`git checkout -b feature/nouvelle-detection`)
3. Committez vos changements (`git commit -m 'Ajout détection XYZ'`)
4. Push (`git push origin feature/nouvelle-detection`)
5. Ouvrez une Pull Request

---

## 📄 Licence

MIT License - Libre d'utilisation pour les équipes Blue Team et SOC.
Developed by Senior Security Engineer.
