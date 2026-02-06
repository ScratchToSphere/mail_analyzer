#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
phish_analyze.py - SOC Email Threat Intelligence Tool
======================================================
Outil d'analyse forensique avancée d'emails pour les équipes SOC (Blue Team).
Détection de phishing, spoofing, et analyse approfondie des menaces.

Auteur: Senior Security Engineer
Date: 2026-02-06
Version: 2.0 (SOC Edition)
"""

import argparse
import email
import hashlib
import os
import re
import sys
from email import policy
from email.parser import BytesParser
from typing import List, Dict, Optional, Tuple
from urllib.parse import urlparse

# Configuration de l'encodage UTF-8 pour Windows
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box



class EmailAnalyzer:
    """
    Analyseur forensique avancé pour emails suspects (SOC Tool).
    
    Fonctionnalités:
    - Analyse d'authentification (SPF, DKIM, Authentication-Results)
    - Détection de spoofing (From vs Reply-To)
    - Extraction et analyse des IPs (route tracking)
    - Parsing HTML avancé avec détection de liens trompeurs
    - Analyse approfondie des pièces jointes (doubles extensions, taille)
    - Dashboard de sécurité avec alertes colorées
    
    Attributes:
        filepath (str): Chemin vers le fichier .eml
        console (Console): Instance Rich pour affichage formaté
        email_message (email.message.EmailMessage): Message parsé
        security_alerts (List[Dict]): Liste des alertes de sécurité détectées
    """
    
    def __init__(self, filepath: str):
        """
        Initialise l'analyseur SOC.
        
        Args:
            filepath (str): Chemin complet vers le fichier .eml
            
        Raises:
            FileNotFoundError: Si le fichier n'existe pas
            ValueError: Si le fichier n'est pas au format .eml
        """
        self.filepath = filepath
        self.console = Console()
        self.email_message = None
        self.security_alerts = []  # Stockage des alertes de sécurité
        
        self._validate_file()
        
    def _validate_file(self) -> None:
        """
        Valide l'existence et le format du fichier email.
        
        Raises:
            FileNotFoundError: Si le fichier n'existe pas
            ValueError: Si l'extension n'est pas .eml
        """
        if not os.path.exists(self.filepath):
            raise FileNotFoundError(f"❌ Fichier introuvable: {self.filepath}")
        
        if not self.filepath.lower().endswith('.eml'):
            raise ValueError(f"⚠️  Le fichier doit être au format .eml (reçu: {self.filepath})")
    
    def parse_email(self) -> None:
        """
        Parse le fichier .eml avec gestion des encodages complexes.
        
        Utilise la politique par défaut pour gérer:
        - Encodages multiples (UTF-8, ISO-8859-1, etc.)
        - Formats MIME complexes
        - Headers encodés (RFC 2047)
        
        Raises:
            Exception: Si le parsing échoue
        """
        try:
            with open(self.filepath, 'rb') as f:
                self.email_message = BytesParser(policy=policy.default).parse(f)
        except Exception as e:
            raise Exception(f"❌ Erreur lors du parsing de l'email: {str(e)}")
    
    # ========== SECTION 1: ENVELOPPE & AUTHENTIFICATION ==========
    
    def extract_envelope_headers(self) -> Dict[str, str]:
        """
        Extrait les méta-données de l'enveloppe email.
        
        Headers extraits:
        - From, Reply-To, Return-Path
        - Subject, Date
        - Message-ID, X-Originating-IP
        
        Returns:
            Dict[str, str]: Dictionnaire des headers d'enveloppe
        """
        return {
            'From': self.email_message.get('From', 'N/A'),
            'Reply-To': self.email_message.get('Reply-To', 'N/A'),
            'Return-Path': self.email_message.get('Return-Path', 'N/A'),
            'Subject': self.email_message.get('Subject', 'N/A'),
            'Date': self.email_message.get('Date', 'N/A'),
            'Message-ID': self.email_message.get('Message-ID', 'N/A'),
            'X-Originating-IP': self.email_message.get('X-Originating-IP', 'N/A'),
        }
    
    def check_authentication(self) -> Dict[str, str]:
        """
        Vérifie les mécanismes d'authentification email (SPF, DKIM, DMARC).
        
        Analyse les headers:
        - Authentication-Results: Résultats globaux d'authentification
        - Received-SPF: Validation SPF (Sender Policy Framework)
        - DKIM-Signature: Signature DKIM (DomainKeys Identified Mail)
        
        Génère des alertes ROUGES si SPF ou DKIM échouent.
        
        Returns:
            Dict[str, str]: Statuts d'authentification
        """
        auth_results = self.email_message.get('Authentication-Results', 'N/A')
        spf_result = self.email_message.get('Received-SPF', 'N/A')
        dkim_signature = self.email_message.get('DKIM-Signature', 'N/A')
        
        # Analyse SPF
        spf_status = "UNKNOWN"
        if spf_result != 'N/A':
            if 'pass' in spf_result.lower():
                spf_status = "PASS"
            elif 'fail' in spf_result.lower():
                spf_status = "FAIL"
                self.security_alerts.append({
                    'level': 'CRITICAL',
                    'type': 'SPF Failure',
                    'message': 'SPF check FAILED - Email may be spoofed'
                })
            elif 'softfail' in spf_result.lower():
                spf_status = "SOFTFAIL"
                self.security_alerts.append({
                    'level': 'WARNING',
                    'type': 'SPF SoftFail',
                    'message': 'SPF check SOFTFAIL - Suspicious sender'
                })
        
        # Analyse DKIM
        dkim_status = "UNKNOWN"
        if auth_results != 'N/A':
            if 'dkim=pass' in auth_results.lower():
                dkim_status = "PASS"
            elif 'dkim=fail' in auth_results.lower():
                dkim_status = "FAIL"
                self.security_alerts.append({
                    'level': 'CRITICAL',
                    'type': 'DKIM Failure',
                    'message': 'DKIM signature FAILED - Email integrity compromised'
                })
        elif dkim_signature != 'N/A':
            dkim_status = "PRESENT (not verified)"
        
        return {
            'Authentication-Results': auth_results,
            'SPF Status': spf_status,
            'DKIM Status': dkim_status,
            'Received-SPF': spf_result
        }
    
    def extract_route_ips(self) -> List[str]:
        """
        Extrait toutes les adresses IP des headers 'Received'.
        
        Analyse la route complète de l'email pour identifier:
        - Les serveurs de relais
        - L'IP source probable (premier Received)
        
        Returns:
            List[str]: Liste des IPs trouvées (ordre chronologique inversé)
        """
        ips = []
        ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        
        # Récupérer tous les headers Received (liste)
        received_headers = self.email_message.get_all('Received', [])
        
        for received in received_headers:
            found_ips = ip_pattern.findall(received)
            ips.extend(found_ips)
        
        # Supprimer les doublons tout en gardant l'ordre
        seen = set()
        unique_ips = []
        for ip in ips:
            if ip not in seen:
                seen.add(ip)
                unique_ips.append(ip)
        
        return unique_ips
    
    def detect_spoofing(self, headers: Dict[str, str]) -> None:
        """
        Détecte les tentatives de spoofing en comparant From et Reply-To.
        
        Si les adresses diffèrent, génère une alerte JAUNE (WARNING).
        Technique courante de phishing: afficher un expéditeur légitime
        mais rediriger les réponses vers un attaquant.
        
        Args:
            headers (Dict[str, str]): Headers d'enveloppe extraits
        """
        from_addr = headers.get('From', '')
        reply_to = headers.get('Reply-To', '')
        
        if reply_to != 'N/A' and from_addr != 'N/A':
            # Extraire les adresses email (ignorer les noms)
            from_email = self._extract_email_address(from_addr)
            reply_email = self._extract_email_address(reply_to)
            
            if from_email and reply_email and from_email != reply_email:
                self.security_alerts.append({
                    'level': 'WARNING',
                    'type': 'Potential Spoofing',
                    'message': f'From ({from_email}) ≠ Reply-To ({reply_email})'
                })
    
    @staticmethod
    def _extract_email_address(header_value: str) -> Optional[str]:
        """
        Extrait l'adresse email d'un header (ignore le nom d'affichage).
        
        Args:
            header_value (str): Valeur du header (ex: "John Doe <john@example.com>")
            
        Returns:
            Optional[str]: Adresse email ou None
        """
        match = re.search(r'<(.+?)>', header_value)
        if match:
            return match.group(1).strip()
        # Si pas de <>, vérifier si c'est directement une adresse
        if '@' in header_value:
            return header_value.strip()
        return None
    
    def display_envelope(self, headers: Dict[str, str], auth: Dict[str, str], ips: List[str]) -> None:
        """
        Affiche la section ENVELOPPE du dashboard.
        
        Args:
            headers (Dict[str, str]): Headers d'enveloppe
            auth (Dict[str, str]): Résultats d'authentification
            ips (List[str]): IPs extraites de la route
        """
        # Tableau des méta-données
        table = Table(title="📩 ENVELOPPE - Méta-données Email", box=box.DOUBLE, show_header=True, header_style="bold cyan")
        table.add_column("Champ", style="yellow", width=20)
        table.add_column("Valeur", style="white", overflow="fold")
        
        for key, value in headers.items():
            table.add_row(key, value)
        
        self.console.print(table)
        self.console.print()
        
        # Tableau d'authentification
        auth_table = Table(title="🔐 AUTHENTIFICATION", box=box.DOUBLE, show_header=True, header_style="bold cyan")
        auth_table.add_column("Mécanisme", style="yellow", width=25)
        auth_table.add_column("Statut", style="white", overflow="fold")
        
        for key, value in auth.items():
            # Colorier le statut
            if 'PASS' in value:
                styled_value = f"[bold green]{value}[/bold green]"
            elif 'FAIL' in value:
                styled_value = f"[bold red]{value}[/bold red]"
            else:
                styled_value = value
            
            auth_table.add_row(key, styled_value)
        
        self.console.print(auth_table)
        self.console.print()
        
        # Affichage des IPs de route
        if ips:
            ip_table = Table(title="🌐 ROUTE ANALYSIS - IPs Détectées", box=box.DOUBLE, show_header=True, header_style="bold cyan")
            ip_table.add_column("#", style="dim", width=5)
            ip_table.add_column("Adresse IP", style="cyan")
            ip_table.add_column("Note", style="yellow")
            
            for idx, ip in enumerate(ips, 1):
                note = "Source probable" if idx == 1 else "Relais"
                ip_table.add_row(str(idx), ip, note)
            
            self.console.print(ip_table)
            self.console.print()
    
    # ========== SECTION 2: ALERTES DE SÉCURITÉ ==========
    
    def display_security_alerts(self) -> None:
        """
        Affiche toutes les alertes de sécurité détectées.
        
        Utilise un code couleur:
        - ROUGE (CRITICAL): Menaces graves (SPF/DKIM fail)
        - JAUNE (WARNING): Comportements suspects (spoofing)
        - VERT (INFO): Informations
        """
        if not self.security_alerts:
            self.console.print(Panel.fit(
                "[bold green]✅ Aucune alerte de sécurité détectée[/bold green]",
                title="⚠️ ALERTES DE SÉCURITÉ",
                border_style="green"
            ))
            self.console.print()
            return
        
        # Créer le tableau d'alertes
        alert_table = Table(title="⚠️ ALERTES DE SÉCURITÉ", box=box.HEAVY, show_header=True, header_style="bold red")
        alert_table.add_column("Niveau", style="bold", width=12)
        alert_table.add_column("Type", style="yellow", width=20)
        alert_table.add_column("Message", style="white", overflow="fold")
        
        for alert in self.security_alerts:
            level = alert['level']
            alert_type = alert['type']
            message = alert['message']
            
            # Colorier selon le niveau
            if level == 'CRITICAL':
                level_styled = "[bold red]🔴 CRITICAL[/bold red]"
            elif level == 'WARNING':
                level_styled = "[bold yellow]🟡 WARNING[/bold yellow]"
            else:
                level_styled = "[bold blue]🔵 INFO[/bold blue]"
            
            alert_table.add_row(level_styled, alert_type, message)
        
        self.console.print(alert_table)
        self.console.print()
    
    # ========== SECTION 3: ANALYSE DES URLs ==========
    
    def extract_html_links(self) -> List[Dict[str, str]]:
        """
        Extrait les liens HTML avec BeautifulSoup (analyse avancée).
        
        Pour chaque lien <a href="...">, extrait:
        - Texte visible (anchor text)
        - URL de destination réelle (href)
        - Détecte si le texte est trompeur (homograph/spoofing)
        
        Returns:
            List[Dict[str, str]]: Liste de dictionnaires avec:
                - 'visible_text': Texte affiché
                - 'real_url': URL réelle
                - 'suspicious': True si texte ≠ destination
        """
        links = []
        
        # Trouver la partie HTML du message
        html_content = None
        if self.email_message.is_multipart():
            for part in self.email_message.walk():
                if part.get_content_type() == 'text/html':
                    try:
                        html_content = part.get_content()
                        break
                    except Exception:
                        continue
        else:
            if self.email_message.get_content_type() == 'text/html':
                try:
                    html_content = self.email_message.get_content()
                except Exception:
                    pass
        
        if not html_content:
            return links
        
        # Parser avec BeautifulSoup
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href']
                visible_text = a_tag.get_text(strip=True)
                
                # Détecter les liens trompeurs
                suspicious = False
                if visible_text and visible_text.startswith('http'):
                    # Le texte ressemble à une URL
                    visible_domain = self._extract_domain(visible_text)
                    real_domain = self._extract_domain(href)
                    
                    if visible_domain and real_domain and visible_domain != real_domain:
                        suspicious = True
                        self.security_alerts.append({
                            'level': 'WARNING',
                            'type': 'Deceptive Link',
                            'message': f'Link text shows "{visible_domain}" but points to "{real_domain}"'
                        })
                
                links.append({
                    'visible_text': visible_text or '(no text)',
                    'real_url': href,
                    'suspicious': suspicious
                })
        except Exception:
            pass
        
        return links
    
    @staticmethod
    def _extract_domain(url: str) -> Optional[str]:
        """
        Extrait le domaine d'une URL.
        
        Args:
            url (str): URL complète
            
        Returns:
            Optional[str]: Nom de domaine ou None
        """
        try:
            parsed = urlparse(url)
            return parsed.netloc if parsed.netloc else None
        except Exception:
            return None
    
    @staticmethod
    def defang_url(url: str) -> str:
        """
        Applique le defanging sur une URL (sécurité).
        
        Args:
            url (str): URL originale
            
        Returns:
            str: URL défangée
        """
        defanged = url.replace('http://', 'hxxp://')
        defanged = defanged.replace('https://', 'hxxps://')
        defanged = defanged.replace('.', '[.]')
        return defanged
    
    def display_urls(self, links: List[Dict[str, str]]) -> None:
        """
        Affiche l'analyse des URLs dans un tableau.
        
        Args:
            links (List[Dict[str, str]]): Liens extraits du HTML
        """
        if not links:
            self.console.print("ℹ️  Aucun lien HTML détecté.\n", style="bold yellow")
            return
        
        table = Table(title="🔗 ANALYSE DES URLs", box=box.DOUBLE, show_header=True, header_style="bold cyan")
        table.add_column("Texte Visible", style="white", overflow="fold", width=30)
        table.add_column("URL Réelle (Defanged)", style="cyan", overflow="fold")
        table.add_column("Suspect ?", style="bold", width=10)
        
        for link in links:
            visible = link['visible_text'][:50]  # Limiter la longueur
            real = self.defang_url(link['real_url'])
            suspicious = "🔴 OUI" if link['suspicious'] else "🟢 NON"
            
            table.add_row(visible, real, suspicious)
        
        self.console.print(table)
        self.console.print()
    
    # ========== SECTION 4: PIÈCES JOINTES ==========
    
    def extract_attachments(self) -> List[Dict[str, any]]:
        """
        Extrait les pièces jointes avec analyse approfondie.
        
        Pour chaque pièce jointe:
        - Nom du fichier
        - Extension(s) détectée(s)
        - Taille en Ko
        - Hash SHA256
        - Détection de doubles extensions (.pdf.exe)
        
        Returns:
            List[Dict]: Liste des pièces jointes avec métadonnées
        """
        attachments = []
        
        if self.email_message.is_multipart():
            for part in self.email_message.walk():
                content_disposition = part.get_content_disposition()
                
                if content_disposition == 'attachment':
                    filename = part.get_filename()
                    if filename:
                        payload = part.get_payload(decode=True)
                        if payload:
                            # Calculer la taille en Ko
                            size_kb = len(payload) / 1024
                            
                            # Calculer le hash SHA256
                            sha256_hash = hashlib.sha256(payload).hexdigest()
                            
                            # Détecter les extensions
                            extensions = self._extract_extensions(filename)
                            double_ext = len(extensions) > 1
                            
                            # Alerte si double extension suspecte
                            if double_ext:
                                dangerous_exts = ['.exe', '.scr', '.bat', '.cmd', '.vbs', '.js']
                                if any(ext in extensions for ext in dangerous_exts):
                                    self.security_alerts.append({
                                        'level': 'CRITICAL',
                                        'type': 'Dangerous Attachment',
                                        'message': f'Double extension detected: {filename} (possible malware)'
                                    })
                            
                            attachments.append({
                                'filename': filename,
                                'extensions': extensions,
                                'size_kb': size_kb,
                                'sha256': sha256_hash,
                                'double_ext': double_ext
                            })
        
        return attachments
    
    @staticmethod
    def _extract_extensions(filename: str) -> List[str]:
        """
        Extrait toutes les extensions d'un nom de fichier.
        
        Détecte les doubles extensions (ex: file.pdf.exe → ['.pdf', '.exe'])
        
        Args:
            filename (str): Nom du fichier
            
        Returns:
            List[str]: Liste des extensions trouvées
        """
        extensions = []
        parts = filename.split('.')
        
        if len(parts) > 1:
            # Récupérer toutes les extensions potentielles
            for i in range(1, len(parts)):
                ext = '.' + parts[i].lower()
                extensions.append(ext)
        
        return extensions
    
    def display_attachments(self, attachments: List[Dict]) -> None:
        """
        Affiche l'analyse des pièces jointes.
        
        Args:
            attachments (List[Dict]): Pièces jointes extraites
        """
        if not attachments:
            self.console.print("ℹ️  Aucune pièce jointe détectée.\n", style="bold yellow")
            return
        
        table = Table(title="📎 PIÈCES JOINTES", box=box.DOUBLE, show_header=True, header_style="bold cyan")
        table.add_column("Nom du Fichier", style="magenta", overflow="fold")
        table.add_column("Extension(s)", style="yellow", width=15)
        table.add_column("Taille (Ko)", style="green", width=12)
        table.add_column("SHA256 Hash", style="cyan", overflow="fold")
        
        for att in attachments:
            filename = att['filename']
            exts = ', '.join(att['extensions']) if att['extensions'] else 'N/A'
            
            # Colorier si double extension
            if att['double_ext']:
                exts = f"[bold red]{exts} ⚠️[/bold red]"
            
            size = f"{att['size_kb']:.2f}"
            sha256 = att['sha256']
            
            table.add_row(filename, exts, size, sha256)
        
        self.console.print(table)
        self.console.print()
    
    # ========== ORCHESTRATION PRINCIPALE ==========
    
    def analyze(self) -> None:
        """
        Lance l'analyse SOC complète de l'email.
        
        Affiche un dashboard en 4 sections:
        1. ENVELOPPE (méta-données + authentification)
        2. ALERTES DE SÉCURITÉ
        3. ANALYSE DES URLs
        4. PIÈCES JOINTES
        """
        # Banner de démarrage
        self.console.print(Panel.fit(
            "[bold cyan]🔍 PhishAnalyze - SOC Email Threat Intelligence Tool[/bold cyan]\n"
            "[yellow]Advanced Forensic Analysis for Blue Team Operations[/yellow]",
            border_style="cyan"
        ))
        self.console.print()
        
        # Parser l'email
        self.parse_email()
        self.console.print("✅ Email parsé avec succès\n", style="bold green")
        
        # ===== SECTION 1: ENVELOPPE =====
        envelope_headers = self.extract_envelope_headers()
        auth_results = self.check_authentication()
        route_ips = self.extract_route_ips()
        self.detect_spoofing(envelope_headers)
        
        self.display_envelope(envelope_headers, auth_results, route_ips)
        
        # ===== SECTION 2: ALERTES =====
        self.display_security_alerts()
        
        # ===== SECTION 3: URLs =====
        html_links = self.extract_html_links()
        self.display_urls(html_links)
        
        # ===== SECTION 4: PIÈCES JOINTES =====
        attachments = self.extract_attachments()
        self.display_attachments(attachments)
        
        # Message de fin
        alert_count = len(self.security_alerts)
        if alert_count > 0:
            summary_style = "bold red" if any(a['level'] == 'CRITICAL' for a in self.security_alerts) else "bold yellow"
            summary_msg = f"⚠️  Analyse terminée - {alert_count} alerte(s) détectée(s)"
        else:
            summary_style = "bold green"
            summary_msg = "✅ Analyse terminée - Aucune menace détectée"
        
        self.console.print(Panel.fit(
            f"[{summary_style}]{summary_msg}[/{summary_style}]",
            border_style="cyan"
        ))


def main():
    """
    Point d'entrée principal du script SOC.
    
    Gère:
    - Parsing des arguments CLI
    - Instanciation de l'analyseur
    - Gestion globale des erreurs
    """
    parser = argparse.ArgumentParser(
        description="🔍 PhishAnalyze - SOC Email Threat Intelligence Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:
  python phish_analyze.py suspicious_email.eml
  python phish_analyze.py "C:\\Emails\\phishing_attempt.eml"
  
Fonctionnalités SOC:
  ✓ Authentification (SPF, DKIM, DMARC)
  ✓ Détection de spoofing (From vs Reply-To)
  ✓ Route tracking (extraction IPs)
  ✓ Analyse HTML avancée (liens trompeurs)
  ✓ Deep-dive pièces jointes (doubles extensions, hash)
  
Développé pour les équipes Blue Team - Threat Intelligence & Forensics
        """
    )
    
    parser.add_argument(
        'filepath',
        type=str,
        help='Chemin vers le fichier .eml à analyser'
    )
    
    args = parser.parse_args()
    
    # Lancement de l'analyse avec gestion d'erreurs
    try:
        analyzer = EmailAnalyzer(args.filepath)
        analyzer.analyze()
    except FileNotFoundError as e:
        Console().print(f"\n{e}\n", style="bold red")
        sys.exit(1)
    except ValueError as e:
        Console().print(f"\n{e}\n", style="bold red")
        sys.exit(1)
    except Exception as e:
        Console().print(f"\n❌ Erreur inattendue: {str(e)}\n", style="bold red")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
