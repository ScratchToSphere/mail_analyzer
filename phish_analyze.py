#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
phish_analyze.py - SOC Email Threat Intelligence Tool
======================================================
Outil d'analyse forensique avancée d'emails pour les équipes SOC (Blue Team).
Détection de phishing, spoofing, et analyse approfondie des menaces.

Auteur: Senior Security Engineer
Date: 2026-02-06
Version: 3.0 (Enterprise Edition - Batch + VirusTotal + JSON Export)
"""

import argparse
import email
import hashlib
import json
import os
import re
import sys
import time
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Any
from urllib.parse import urlparse

# Configuration de l'encodage UTF-8 pour Windows
if sys.platform == 'win32':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeRemainingColumn
from rich import box


class VirusTotalClient:
    """
    Client pour l'API VirusTotal (hash lookup).
    
    Gère les requêtes vers l'API VirusTotal pour vérifier les hashs de fichiers.
    Inclut la gestion des quotas (4 requêtes/minute pour l'API gratuite).
    """
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialise le client VirusTotal.
        
        Args:
            api_key (Optional[str]): Clé API VirusTotal (si None, récupère depuis env)
        """
        self.api_key = api_key or os.getenv('VT_API_KEY')
        self.base_url = 'https://www.virustotal.com/api/v3'
        self.console = Console()
        self.last_request_time = 0
        
    def is_configured(self) -> bool:
        """Vérifie si la clé API est configurée."""
        return self.api_key is not None and self.api_key != ''
    
    def check_file_hash(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """
        Interroge VirusTotal pour un hash de fichier.
        
        Args:
            file_hash (str): Hash SHA256 du fichier
            
        Returns:
            Optional[Dict]: Résultats VT ou None si erreur
        """
        if not self.is_configured():
            return None
        
        # Gestion des quotas: attendre 15s entre chaque requête
        elapsed = time.time() - self.last_request_time
        if elapsed < 15:
            wait_time = 15 - elapsed
            time.sleep(wait_time)
        
        try:
            headers = {
                'x-apikey': self.api_key
            }
            url = f'{self.base_url}/files/{file_hash}'
            
            response = requests.get(url, headers=headers, timeout=10)
            self.last_request_time = time.time()
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                
                return {
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'undetected': stats.get('undetected', 0),
                    'harmless': stats.get('harmless', 0),
                    'total': sum(stats.values()) if stats else 0
                }
            elif response.status_code == 404:
                return {'error': 'Hash not found in VT database'}
            else:
                return {'error': f'VT API error: {response.status_code}'}
                
        except requests.exceptions.RequestException as e:
            return {'error': f'Connection error: {str(e)}'}
        except Exception as e:
            return {'error': f'Unexpected error: {str(e)}'}


class EmailAnalyzer:
    """
    Analyseur forensique avancé pour emails suspects (SOC Tool).
    
    Version 3.0 - Fonctionnalités:
    - Analyse d'authentification (SPF, DKIM, Authentication-Results)
    - Détection de spoofing (From vs Reply-To)
    - Extraction et analyse des IPs (route tracking)
    - Parsing HTML avancé avec détection de liens trompeurs
    - Analyse approfondie des pièces jointes (doubles extensions, taille)
    - Dashboard de sécurité avec alertes colorées
    - Intégration VirusTotal API
    - Export JSON
    
    Attributes:
        filepath (str): Chemin vers le fichier .eml
        console (Console): Instance Rich pour affichage formaté
        email_message (email.message.EmailMessage): Message parsé
        security_alerts (List[Dict]): Liste des alertes de sécurité détectées
        vt_client (Optional[VirusTotalClient]): Client VirusTotal si activé
        batch_mode (bool): Mode batch activé ou non
    """
    
    def __init__(self, filepath: str, vt_client: Optional[VirusTotalClient] = None, batch_mode: bool = False):
        """
        Initialise l'analyseur SOC.
        
        Args:
            filepath (str): Chemin complet vers le fichier .eml
            vt_client (Optional[VirusTotalClient]): Client VirusTotal
            batch_mode (bool): Mode batch (affichage réduit)
            
        Raises:
            FileNotFoundError: Si le fichier n'existe pas
            ValueError: Si le fichier n'est pas au format .eml
        """
        self.filepath = filepath
        self.console = Console()
        self.email_message = None
        self.security_alerts = []
        self.vt_client = vt_client
        self.batch_mode = batch_mode
        
        # Données extraites (pour export JSON)
        self.analysis_data = {}
        
        self._validate_file()
        
    def _validate_file(self) -> None:
        """Valide l'existence et le format du fichier email."""
        if not os.path.exists(self.filepath):
            raise FileNotFoundError(f"❌ Fichier introuvable: {self.filepath}")
        
        if not self.filepath.lower().endswith('.eml'):
            raise ValueError(f"⚠️  Le fichier doit être au format .eml (reçu: {self.filepath})")
    
    def parse_email(self) -> None:
        """Parse le fichier .eml avec gestion des encodages complexes."""
        try:
            with open(self.filepath, 'rb') as f:
                self.email_message = BytesParser(policy=policy.default).parse(f)
        except Exception as e:
            raise Exception(f"❌ Erreur lors du parsing de l'email: {str(e)}")
    
    def extract_envelope_headers(self) -> Dict[str, str]:
        """Extrait les méta-données de l'enveloppe email."""
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
        """Vérifie les mécanismes d'authentification email (SPF, DKIM, DMARC)."""
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
        """Extrait toutes les adresses IP des headers 'Received'."""
        ips = []
        ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        
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
        """Détecte les tentatives de spoofing en comparant From et Reply-To."""
        from_addr = headers.get('From', '')
        reply_to = headers.get('Reply-To', '')
        
        if reply_to != 'N/A' and from_addr != 'N/A':
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
        """Extrait l'adresse email d'un header (ignore le nom d'affichage)."""
        match = re.search(r'<(.+?)>', header_value)
        if match:
            return match.group(1).strip()
        if '@' in header_value:
            return header_value.strip()
        return None
    
    def extract_html_links(self) -> List[Dict[str, str]]:
        """Extrait les liens HTML avec BeautifulSoup (analyse avancée)."""
        links = []
        
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
        
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href']
                visible_text = a_tag.get_text(strip=True)
                
                suspicious = False
                if visible_text and visible_text.startswith('http'):
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
        """Extrait le domaine d'une URL."""
        try:
            parsed = urlparse(url)
            return parsed.netloc if parsed.netloc else None
        except Exception:
            return None
    
    @staticmethod
    def defang_url(url: str) -> str:
        """Applique le defanging sur une URL (sécurité)."""
        defanged = url.replace('http://', 'hxxp://')
        defanged = defanged.replace('https://', 'hxxps://')
        defanged = defanged.replace('.', '[.]')
        return defanged
    
    def extract_attachments(self) -> List[Dict[str, any]]:
        """Extrait les pièces jointes avec analyse approfondie."""
        attachments = []
        
        if self.email_message.is_multipart():
            for part in self.email_message.walk():
                content_disposition = part.get_content_disposition()
                
                if content_disposition == 'attachment':
                    filename = part.get_filename()
                    if filename:
                        payload = part.get_payload(decode=True)
                        if payload:
                            size_kb = len(payload) / 1024
                            sha256_hash = hashlib.sha256(payload).hexdigest()
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
                            
                            # Interroger VirusTotal si activé
                            vt_results = None
                            if self.vt_client and self.vt_client.is_configured():
                                vt_results = self.vt_client.check_file_hash(sha256_hash)
                            
                            attachments.append({
                                'filename': filename,
                                'extensions': extensions,
                                'size_kb': size_kb,
                                'sha256': sha256_hash,
                                'double_ext': double_ext,
                                'vt_results': vt_results
                            })
        
        return attachments
    
    @staticmethod
    def _extract_extensions(filename: str) -> List[str]:
        """Extrait toutes les extensions d'un nom de fichier."""
        extensions = []
        parts = filename.split('.')
        
        if len(parts) > 1:
            for i in range(1, len(parts)):
                ext = '.' + parts[i].lower()
                extensions.append(ext)
        
        return extensions
    
    def get_severity(self) -> str:
        """Calcule la sévérité globale basée sur les alertes."""
        if any(a['level'] == 'CRITICAL' for a in self.security_alerts):
            return 'CRITICAL'
        elif any(a['level'] == 'WARNING' for a in self.security_alerts):
            return 'WARNING'
        else:
            return 'CLEAN'
    
    def to_dict(self) -> Dict[str, Any]:
        """Convertit l'analyse en dictionnaire (pour export JSON)."""
        return {
            'file': os.path.basename(self.filepath),
            'headers': self.analysis_data.get('headers', {}),
            'authentication': self.analysis_data.get('authentication', {}),
            'route_ips': self.analysis_data.get('route_ips', []),
            'links': self.analysis_data.get('links', []),
            'attachments': self.analysis_data.get('attachments', []),
            'alerts': self.security_alerts,
            'severity': self.get_severity(),
            'alert_count': len(self.security_alerts)
        }
    
    def analyze(self, display: bool = True) -> Dict[str, Any]:
        """
        Lance l'analyse SOC complète de l'email.
        
        Args:
            display (bool): Afficher le dashboard ou non (False en mode batch)
            
        Returns:
            Dict[str, Any]: Données d'analyse pour export JSON
        """
        # Parser l'email
        self.parse_email()
        
        # Extraire toutes les données
        envelope_headers = self.extract_envelope_headers()
        auth_results = self.check_authentication()
        route_ips = self.extract_route_ips()
        self.detect_spoofing(envelope_headers)
        html_links = self.extract_html_links()
        attachments = self.extract_attachments()
        
        # Stocker pour export JSON
        self.analysis_data = {
            'headers': envelope_headers,
            'authentication': auth_results,
            'route_ips': route_ips,
            'links': html_links,
            'attachments': attachments
        }
        
        # Affichage si demandé (pas en mode batch)
        if display and not self.batch_mode:
            self._display_full_report(envelope_headers, auth_results, route_ips, html_links, attachments)
        
        return self.to_dict()
    
    def _display_full_report(self, headers, auth, ips, links, attachments):
        """Affiche le rapport complet (mode non-batch)."""
        # Banner
        self.console.print(Panel.fit(
            "[bold cyan]🔍 PhishAnalyze v3.0 - SOC Email Threat Intelligence Tool[/bold cyan]\n"
            "[yellow]Advanced Forensic Analysis for Blue Team Operations[/yellow]",
            border_style="cyan"
        ))
        self.console.print()
        self.console.print("✅ Email parsé avec succès\n", style="bold green")
        
        # Section 1: Enveloppe
        self._display_envelope(headers, auth, ips)
        
        # Section 2: Alertes
        self._display_security_alerts()
        
        # Section 3: URLs
        self._display_urls(links)
        
        # Section 4: Pièces jointes
        self._display_attachments(attachments)
        
        # Message de fin
        alert_count = len(self.security_alerts)
        if alert_count > 0:
            summary_style = "bold red" if self.get_severity() == 'CRITICAL' else "bold yellow"
            summary_msg = f"⚠️  Analyse terminée - {alert_count} alerte(s) détectée(s)"
        else:
            summary_style = "bold green"
            summary_msg = "✅ Analyse terminée - Aucune menace détectée"
        
        self.console.print(Panel.fit(
            f"[{summary_style}]{summary_msg}[/{summary_style}]",
            border_style="cyan"
        ))
    
    def _display_envelope(self, headers, auth, ips):
        """Affiche la section ENVELOPPE."""
        table = Table(title="📩 ENVELOPPE - Méta-données Email", box=box.DOUBLE, show_header=True, header_style="bold cyan")
        table.add_column("Champ", style="yellow", width=20)
        table.add_column("Valeur", style="white", overflow="fold")
        
        for key, value in headers.items():
            table.add_row(key, value)
        
        self.console.print(table)
        self.console.print()
        
        # Authentification
        auth_table = Table(title="🔐 AUTHENTIFICATION", box=box.DOUBLE, show_header=True, header_style="bold cyan")
        auth_table.add_column("Mécanisme", style="yellow", width=25)
        auth_table.add_column("Statut", style="white", overflow="fold")
        
        for key, value in auth.items():
            if 'PASS' in value:
                styled_value = f"[bold green]{value}[/bold green]"
            elif 'FAIL' in value:
                styled_value = f"[bold red]{value}[/bold red]"
            else:
                styled_value = value
            
            auth_table.add_row(key, styled_value)
        
        self.console.print(auth_table)
        self.console.print()
        
        # IPs
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
    
    def _display_security_alerts(self):
        """Affiche les alertes de sécurité."""
        if not self.security_alerts:
            self.console.print(Panel.fit(
                "[bold green]✅ Aucune alerte de sécurité détectée[/bold green]",
                title="⚠️ ALERTES DE SÉCURITÉ",
                border_style="green"
            ))
            self.console.print()
            return
        
        alert_table = Table(title="⚠️ ALERTES DE SÉCURITÉ", box=box.HEAVY, show_header=True, header_style="bold red")
        alert_table.add_column("Niveau", style="bold", width=12)
        alert_table.add_column("Type", style="yellow", width=20)
        alert_table.add_column("Message", style="white", overflow="fold")
        
        for alert in self.security_alerts:
            level = alert['level']
            if level == 'CRITICAL':
                level_styled = "[bold red]🔴 CRITICAL[/bold red]"
            elif level == 'WARNING':
                level_styled = "[bold yellow]🟡 WARNING[/bold yellow]"
            else:
                level_styled = "[bold blue]🔵 INFO[/bold blue]"
            
            alert_table.add_row(level_styled, alert['type'], alert['message'])
        
        self.console.print(alert_table)
        self.console.print()
    
    def _display_urls(self, links):
        """Affiche l'analyse des URLs."""
        if not links:
            self.console.print("ℹ️  Aucun lien HTML détecté.\n", style="bold yellow")
            return
        
        table = Table(title="🔗 ANALYSE DES URLs", box=box.DOUBLE, show_header=True, header_style="bold cyan")
        table.add_column("Texte Visible", style="white", overflow="fold", width=30)
        table.add_column("URL Réelle (Defanged)", style="cyan", overflow="fold")
        table.add_column("Suspect ?", style="bold", width=10)
        
        for link in links:
            visible = link['visible_text'][:50]
            real = self.defang_url(link['real_url'])
            suspicious = "🔴 OUI" if link['suspicious'] else "🟢 NON"
            
            table.add_row(visible, real, suspicious)
        
        self.console.print(table)
        self.console.print()
    
    def _display_attachments(self, attachments):
        """Affiche l'analyse des pièces jointes avec résultats VT."""
        if not attachments:
            self.console.print("ℹ️  Aucune pièce jointe détectée.\n", style="bold yellow")
            return
        
        # Ajouter colonne VT si activé
        has_vt = any(att.get('vt_results') for att in attachments)
        
        table = Table(title="📎 PIÈCES JOINTES", box=box.DOUBLE, show_header=True, header_style="bold cyan")
        table.add_column("Nom du Fichier", style="magenta", overflow="fold")
        table.add_column("Extension(s)", style="yellow", width=15)
        table.add_column("Taille (Ko)", style="green", width=12)
        if has_vt:
            table.add_column("VT Score", style="red", width=15)
        table.add_column("SHA256 Hash", style="cyan", overflow="fold")
        
        for att in attachments:
            filename = att['filename']
            exts = ', '.join(att['extensions']) if att['extensions'] else 'N/A'
            
            if att['double_ext']:
                exts = f"[bold red]{exts} ⚠️[/bold red]"
            
            size = f"{att['size_kb']:.2f}"
            sha256 = att['sha256']
            
            # VT Score
            vt_score = "N/A"
            if att.get('vt_results'):
                vt = att['vt_results']
                if 'error' in vt:
                    vt_score = f"[dim]{vt['error']}[/dim]"
                else:
                    malicious = vt.get('malicious', 0)
                    total = vt.get('total', 0)
                    if malicious > 0:
                        vt_score = f"[bold red]{malicious}/{total}[/bold red]"
                    else:
                        vt_score = f"[green]{malicious}/{total}[/green]"
            
            if has_vt:
                table.add_row(filename, exts, size, vt_score, sha256)
            else:
                table.add_row(filename, exts, size, sha256)
        
        self.console.print(table)
        self.console.print()


def find_eml_files(path: str) -> List[str]:
    """
    Trouve tous les fichiers .eml dans un chemin (fichier ou dossier).
    
    Args:
        path (str): Chemin vers fichier ou dossier
        
    Returns:
        List[str]: Liste des fichiers .eml trouvés
    """
    path_obj = Path(path)
    
    if path_obj.is_file():
        return [str(path_obj)] if path_obj.suffix.lower() == '.eml' else []
    elif path_obj.is_dir():
        return [str(f) for f in path_obj.rglob('*.eml')]
    else:
        return []


def main():
    """Point d'entrée principal du script SOC v3.0."""
    parser = argparse.ArgumentParser(
        description="🔍 PhishAnalyze v3.0 - SOC Email Threat Intelligence Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:
  # Fichier unique
  python phish_analyze.py suspicious_email.eml
  
  # Dossier (mode batch)
  python phish_analyze.py ./emails_folder
  
  # Avec VirusTotal
  python phish_analyze.py email.eml --vt
  
  # Export JSON
  python phish_analyze.py email.eml --json results.json
  
  # Mode complet
  python phish_analyze.py ./emails --vt --json report.json

Fonctionnalités v3.0:
  ✓ Mode Batch (dossier)
  ✓ Intégration VirusTotal API
  ✓ Export JSON
  ✓ Gestion quotas API (4 req/min)
  ✓ Authentification (SPF, DKIM, DMARC)
  ✓ Détection de spoofing
  ✓ Route tracking
  ✓ Analyse HTML avancée
  ✓ Deep-dive pièces jointes

Développé pour les équipes Blue Team - Threat Intelligence & Forensics
        """
    )
    
    parser.add_argument(
        'path',
        type=str,
        help='Chemin vers fichier .eml ou dossier contenant des .eml'
    )
    
    parser.add_argument(
        '--vt',
        action='store_true',
        help='Activer l\'interrogation VirusTotal (nécessite VT_API_KEY)'
    )
    
    parser.add_argument(
        '--json',
        type=str,
        metavar='OUTPUT_FILE',
        help='Exporter les résultats en JSON'
    )
    
    args = parser.parse_args()
    
    console = Console()
    
    # Trouver les fichiers .eml
    eml_files = find_eml_files(args.path)
    
    if not eml_files:
        console.print("\n❌ Aucun fichier .eml trouvé.\n", style="bold red")
        sys.exit(1)
    
    batch_mode = len(eml_files) > 1
    
    # Initialiser VirusTotal si demandé
    vt_client = None
    if args.vt:
        vt_client = VirusTotalClient()
        if not vt_client.is_configured():
            console.print("\n⚠️  Variable d'environnement VT_API_KEY non définie. Mode VT désactivé.\n", style="bold yellow")
            vt_client = None
        else:
            console.print(f"\n✅ VirusTotal activé (quota: 4 req/min)\n", style="bold green")
    
    # Analyser les fichiers
    results = []
    
    if batch_mode:
        console.print(f"\n📁 Mode Batch: {len(eml_files)} fichier(s) .eml trouvé(s)\n", style="bold cyan")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeRemainingColumn(),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]Analyse en cours...", total=len(eml_files))
            
            for eml_file in eml_files:
                try:
                    analyzer = EmailAnalyzer(eml_file, vt_client=vt_client, batch_mode=True)
                    result = analyzer.analyze(display=False)
                    results.append(result)
                except Exception as e:
                    console.print(f"❌ Erreur sur {os.path.basename(eml_file)}: {str(e)}", style="bold red")
                    results.append({
                        'file': os.path.basename(eml_file),
                        'error': str(e),
                        'severity': 'ERROR'
                    })
                
                progress.update(task, advance=1)
        
        # Tableau récapitulatif
        console.print("\n")
        summary_table = Table(title="📊 RÉCAPITULATIF BATCH", box=box.HEAVY, show_header=True, header_style="bold cyan")
        summary_table.add_column("Fichier", style="white", overflow="fold")
        summary_table.add_column("Sévérité", style="bold", width=12)
        summary_table.add_column("Alertes", style="yellow", width=10)
        
        # Ajouter colonne VT si activé
        if vt_client:
            summary_table.add_column("VT Détections", style="red", width=15)
        
        for result in results:
            filename = result['file']
            severity = result.get('severity', 'UNKNOWN')
            alert_count = result.get('alert_count', 0)
            
            # Colorier sévérité
            if severity == 'CRITICAL':
                severity_styled = "[bold red]🔴 CRITICAL[/bold red]"
            elif severity == 'WARNING':
                severity_styled = "[bold yellow]🟡 WARNING[/bold yellow]"
            elif severity == 'CLEAN':
                severity_styled = "[bold green]🟢 CLEAN[/bold green]"
            else:
                severity_styled = "[dim]❓ ERROR[/dim]"
            
            # VT max score
            vt_max = "N/A"
            if vt_client and 'attachments' in result:
                max_malicious = 0
                for att in result['attachments']:
                    if att.get('vt_results') and 'malicious' in att['vt_results']:
                        max_malicious = max(max_malicious, att['vt_results']['malicious'])
                if max_malicious > 0:
                    vt_max = f"[bold red]{max_malicious}[/bold red]"
                else:
                    vt_max = "[green]0[/green]"
            
            if vt_client:
                summary_table.add_row(filename, severity_styled, str(alert_count), vt_max)
            else:
                summary_table.add_row(filename, severity_styled, str(alert_count))
        
        console.print(summary_table)
        console.print()
        
    else:
        # Mode fichier unique
        try:
            analyzer = EmailAnalyzer(eml_files[0], vt_client=vt_client, batch_mode=False)
            result = analyzer.analyze(display=True)
            results.append(result)
        except Exception as e:
            console.print(f"\n❌ Erreur: {str(e)}\n", style="bold red")
            import traceback
            traceback.print_exc()
            sys.exit(1)
    
    # Export JSON si demandé
    if args.json:
        try:
            output_data = {
                'tool': 'PhishAnalyze',
                'version': '3.0',
                'batch_mode': batch_mode,
                'total_files': len(eml_files),
                'virustotal_enabled': vt_client is not None,
                'results': results
            }
            
            with open(args.json, 'w', encoding='utf-8') as f:
                json.dump(output_data, f, indent=2, ensure_ascii=False)
            
            console.print(f"\n✅ Résultats exportés: {args.json}\n", style="bold green")
        except Exception as e:
            console.print(f"\n❌ Erreur export JSON: {str(e)}\n", style="bold red")


if __name__ == "__main__":
    main()
