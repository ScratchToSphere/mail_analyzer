# PhishAnalyze - SOC Email Threat Intelligence Tool

![Version](https://img.shields.io/badge/version-2.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-green.svg)
![License](https://img.shields.io/badge/license-MIT-orange.svg)

**Outil d'analyse forensique avancée d'emails pour les équipes SOC (Blue Team)**

Analysez les emails suspects (.eml) avec des fonctionnalités de détection de phishing, spoofing, et threat intelligence.

---

## 🚀 Fonctionnalités SOC

### 📩 Section 1: ENVELOPPE
- **Méta-données complètes** : From, Reply-To, Return-Path, Subject, Date, Message-ID, X-Originating-IP
- **Authentification Email** :
  - ✅ Vérification **SPF** (Sender Policy Framework)
  - ✅ Vérification **DKIM** (DomainKeys Identified Mail)
  - ✅ Analyse **Authentication-Results**
  - 🔴 **Alertes CRITIQUES** si SPF/DKIM échouent
- **Route Tracking** : Extraction de toutes les IPs des headers `Received` avec identification de la source probable

### ⚠️ Section 2: ALERTES DE SÉCURITÉ
- **Détection de Spoofing** : Compare `From` vs `Reply-To` (🟡 alerte JAUNE si différent)
- **Échecs d'authentification** : SPF/DKIM fail (🔴 alerte ROUGE)
- **Liens trompeurs** : Détection de liens HTML où le texte visible diffère de la destination réelle
- **Pièces jointes dangereuses** : Doubles extensions suspectes (.pdf.exe, .doc.scr, etc.)

### 🔗 Section 3: ANALYSE DES URLs
- **Parsing HTML avancé** avec BeautifulSoup4
- Extraction des liens `<a href="...">` avec :
  - Texte visible (anchor text)
  - URL de destination réelle
  - **Détection d'homograph attacks** (texte montre google.com mais pointe vers evil.com)
- **Defanging automatique** : `http` → `hxxp`, `.` → `[.]` (sécurité)

### 📎 Section 4: PIÈCES JOINTES
- Nom du fichier
- **Détection de doubles extensions** (.pdf.exe → 🔴 ALERTE)
- **Taille en Ko**
- **Hash SHA256** (pour IOC / Threat Intelligence)

---

## 📦 Installation

### Prérequis
- Python 3.8+
- pip

### Dépendances
```bash
pip install rich beautifulsoup4
```

---

## 🎯 Utilisation

### Syntaxe de base
```bash
python phish_analyze.py <fichier.eml>
```

### Exemples
```bash
# Analyse simple
python phish_analyze.py suspicious_email.eml

# Avec chemin complet (Windows)
python phish_analyze.py "C:\Emails\phishing_attempt.eml"

# Avec chemin contenant des espaces
python phish_analyze.py "Sono arrivati i parcheggi Parclick.eml"

# Afficher l'aide
python phish_analyze.py --help
```

---

## 📊 Exemple de Sortie (Dashboard)

```
┌──────────────────────────────────────────────────────────┐
│ 🔍 PhishAnalyze - SOC Email Threat Intelligence Tool    │
│ Advanced Forensic Analysis for Blue Team Operations     │
└──────────────────────────────────────────────────────────┘

✅ Email parsé avec succès

╔═══════════════════════════════════════════════════════════╗
║         📩 ENVELOPPE - Méta-données Email                ║
╠═══════════════════════════════════════════════════════════╣
║ From          │ suspicious@example.com                    ║
║ Reply-To      │ attacker@evil.com                         ║
║ Subject       │ Urgent: Verify Your Account              ║
╚═══════════════════════════════════════════════════════════╝

╔═══════════════════════════════════════════════════════════╗
║                  🔐 AUTHENTIFICATION                      ║
╠═══════════════════════════════════════════════════════════╣
║ SPF Status    │ FAIL                                      ║
║ DKIM Status   │ FAIL                                      ║
╚═══════════════════════════════════════════════════════════╝

╔═══════════════════════════════════════════════════════════╗
║              ⚠️ ALERTES DE SÉCURITÉ                       ║
╠═══════════════════════════════════════════════════════════╣
║ 🔴 CRITICAL   │ SPF Failure    │ Email may be spoofed    ║
║ 🟡 WARNING    │ Spoofing       │ From ≠ Reply-To         ║
╚═══════════════════════════════════════════════════════════╝
```

---

## 🛡️ Cas d'Usage SOC

### 1. Investigation de Phishing
```bash
# Analyser un email suspect signalé par un utilisateur
python phish_analyze.py reported_phishing.eml
```
**Résultat** : Détection automatique de SPF fail, liens trompeurs, et pièces jointes suspectes.

### 2. Threat Intelligence
```bash
# Extraire les IOCs (hash SHA256, IPs, domaines)
python phish_analyze.py malware_campaign.eml
```
**Résultat** : Hash SHA256 des pièces jointes pour recherche VirusTotal, IPs pour blocage firewall.

### 3. Formation Blue Team
```bash
# Démonstration des techniques de phishing
python phish_analyze.py training_sample.eml
```
**Résultat** : Visualisation claire des indicateurs de compromission.

---

## 🔍 Détails Techniques

### Architecture
- **Orienté Objet** : Classe `EmailAnalyzer` avec méthodes modulaires
- **Gestion d'erreurs** : Try/except sur parsing, encodages, extraction
- **Encodage robuste** : Support UTF-8 pour Windows (emojis, caractères spéciaux)

### Librairies Utilisées
| Librairie | Usage |
|-----------|-------|
| `email` (stdlib) | Parsing .eml (MIME, headers, multipart) |
| `rich` | Interface terminal (tableaux, panels, couleurs) |
| `beautifulsoup4` | Parsing HTML (extraction liens, détection spoofing) |
| `hashlib` (stdlib) | Calcul SHA256 des pièces jointes |
| `re` (stdlib) | Regex (extraction IPs, URLs, emails) |

### Détection de Menaces

#### 1. Spoofing Detection
```python
# Compare From vs Reply-To
if from_email != reply_to_email:
    🟡 WARNING: Potential Spoofing
```

#### 2. Authentication Failure
```python
# Analyse SPF/DKIM
if 'fail' in spf_result.lower():
    🔴 CRITICAL: SPF check FAILED
```

#### 3. Deceptive Links
```python
# BeautifulSoup parsing
<a href="http://evil.com">http://google.com</a>
    ↓
🟡 WARNING: Link text shows "google.com" but points to "evil.com"
```

#### 4. Dangerous Attachments
```python
# Détection doubles extensions
filename = "invoice.pdf.exe"
    ↓
🔴 CRITICAL: Double extension detected (possible malware)
```

---

## 📝 Format .eml

Le script accepte uniquement les fichiers `.eml` (RFC 822 email format).

### Comment obtenir un .eml ?
- **Outlook** : Fichier → Enregistrer sous → Format .eml
- **Gmail** : Télécharger le message → "Afficher l'original" → Enregistrer
- **Thunderbird** : Clic droit → Enregistrer comme → .eml

---

## 🎨 Personnalisation

### Modifier les alertes
Éditez la classe `EmailAnalyzer` pour ajouter vos propres règles :

```python
# Exemple: Ajouter une alerte pour domaine suspect
if 'suspicious-domain.com' in from_addr:
    self.security_alerts.append({
        'level': 'CRITICAL',
        'type': 'Blacklisted Domain',
        'message': 'Email from known malicious domain'
    })
```

### Exporter les résultats
Ajoutez une méthode pour exporter en JSON :

```python
def export_json(self, output_file):
    import json
    data = {
        'headers': self.extract_envelope_headers(),
        'alerts': self.security_alerts,
        'attachments': self.extract_attachments()
    }
    with open(output_file, 'w') as f:
        json.dump(data, f, indent=2)
```

---

## 🐛 Dépannage

### Erreur: `ModuleNotFoundError: No module named 'rich'`
```bash
pip install rich
```

### Erreur: `ModuleNotFoundError: No module named 'bs4'`
```bash
pip install beautifulsoup4
```

### Problème d'encodage (Windows)
Le script configure automatiquement UTF-8 pour Windows. Si vous rencontrez des problèmes :
```bash
# Forcer UTF-8 dans le terminal
chcp 65001
python phish_analyze.py email.eml
```

---

## 🤝 Contribution

Les contributions sont les bienvenues ! Pour ajouter des fonctionnalités :

1. Fork le projet
2. Créez une branche (`git checkout -b feature/nouvelle-detection`)
3. Committez vos changements (`git commit -m 'Ajout détection XYZ'`)
4. Push (`git push origin feature/nouvelle-detection`)
5. Ouvrez une Pull Request

---

## 📄 Licence

MIT License - Libre d'utilisation pour les équipes Blue Team et SOC.

---

## 🔗 Ressources

- [RFC 5322 - Internet Message Format](https://tools.ietf.org/html/rfc5322)
- [SPF (RFC 7208)](https://tools.ietf.org/html/rfc7208)
- [DKIM (RFC 6376)](https://tools.ietf.org/html/rfc6376)
- [DMARC (RFC 7489)](https://tools.ietf.org/html/rfc7489)
- [MITRE ATT&CK - Phishing](https://attack.mitre.org/techniques/T1566/)

---

## 👨‍💻 Auteur

**Senior Security Engineer** - Développé pour les équipes Blue Team

**Version**: 2.0 (SOC Edition)  
**Date**: 2026-02-06

---

## 🎯 Roadmap

- [ ] Export JSON/CSV des résultats
- [ ] Intégration VirusTotal API (hash lookup)
- [ ] Détection de typosquatting (domaines similaires)
- [ ] Analyse DMARC avancée
- [ ] Support .msg (Outlook)
- [ ] Mode batch (analyser plusieurs .eml)
- [ ] Génération de rapports PDF

---

**⚠️ Disclaimer** : Cet outil est destiné à l'analyse forensique d'emails suspects dans un cadre légal (SOC, Blue Team). Ne l'utilisez pas pour des activités illégales.
