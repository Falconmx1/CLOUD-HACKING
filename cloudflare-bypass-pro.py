#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
🛡️ CLOUDFLARE-BYPASS-PRO v1.0 - El que le tumba el escudo a Cloudflare 🛡️
Autor: Falconmx1
GitHub: https://github.com/Falconmx1/CLOUD-HACKING
Descripción: Multi-técnica para encontrar IP real detrás de Cloudflare
"""

import argparse
import sys
import json
import socket
import dns.resolver
import dns.reversename
import requests
import ssl
import OpenSSL
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import init, Fore, Style
from fake_useragent import UserAgent
import time
import re

# Inicializar colorama
init(autoreset=True)

# ==================== CONFIGURACIÓN ====================
VERDE = Fore.GREEN
ROJO = Fore.RED
AMARILLO = Fore.YELLOW
AZUL = Fore.CYAN
MAGENTA = Fore.MAGENTA
BLANCO = Fore.WHITE
RESET = Style.RESET_ALL

VERSION = "1.0"
BANNER = f"""
{MAGENTA}╔═══════════════════════════════════════════════════════════════╗
{MAGENTA}║     🛡️  CLOUDFLARE-BYPASS-PRO v{VERSION} - EL ROMPE ESCUDOS 🛡️    ║
{MAGENTA}║            Creado por: Falconmx1 🔥                          ║
{MAGONT}║     "Detrás de Cloudflare siempre hay una IP desnuda"         ║
{MAGENTA}╚═══════════════════════════════════════════════════════════════╝{RESET}
"""

class CloudflareBypass:
    def __init__(self, domain, threads=50, output=None, verbose=False, proxy=None):
        self.domain = domain.lower().replace('http://', '').replace('https://', '').replace('www.', '')
        self.threads = threads
        self.output = output
        self.verbose = verbose
        self.proxy = proxy
        self.ua = UserAgent()
        self.lock = threading.Lock()
        
        # Resultados
        self.results = {
            "domain": self.domain,
            "timestamp": datetime.now().isoformat(),
            "real_ips": [],
            "techniques": {},
            "subdomains": [],
            "ssl_ips": [],
            "dns_history": [],
            "cloudflare_status": True
        }
        
        # Proxies si se especifican
        self.proxies = None
        if proxy:
            self.proxies = {
                'http': proxy,
                'https': proxy
            }
    
    # ========== UTILIDADES ==========
    def log(self, message, level="info"):
        """Sistema de logging"""
        with self.lock:
            timestamp = datetime.now().strftime('%H:%M:%S')
            if level == "info":
                print(f"{AZUL}[{timestamp}][*]{RESET} {message}")
            elif level == "success":
                print(f"{VERDE}[{timestamp}][+]{RESET} {message}")
            elif level == "error":
                print(f"{ROJO}[{timestamp}][-]{RESET} {message}")
            elif level == "warning":
                print(f"{AMARILLO}[{timestamp}][!]{RESET} {message}")
            elif level == "found":
                print(f"{MAGENTA}[{timestamp}][🔥]{RESET} {message}")
            elif level == "debug" and self.verbose:
                print(f"{BLANCO}[{timestamp}][DEBUG]{RESET} {message}")
    
    def save_results(self):
        """Guarda resultados"""
        filename = self.output or f"cf_bypass_{self.domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=4)
        self.log(f"Resultados guardados en: {filename}", "success")
    
    def is_valid_ip(self, ip):
        """Valida IP"""
        try:
            socket.inet_aton(ip)
            return True
        except:
            return False
    
    def check_cloudflare(self, ip):
        """Verifica si una IP está detrás de Cloudflare"""
        try:
            headers = {'Host': self.domain, 'User-Agent': self.ua.random}
            response = requests.get(f"http://{ip}", headers=headers, timeout=5, proxies=self.proxies)
            server = response.headers.get('Server', '').lower()
            cf_ray = response.headers.get('CF-Ray', '')
            
            if 'cloudflare' in server or cf_ray:
                return False  # Sigue en Cloudflare
            return True  # IP real encontrada
        except:
            return False
    
    # ========== TÉCNICA 1: HISTORIAL DNS (SecurityTrails, VirusTotal) ==========
    def technique_dns_history(self):
        """Busca IPs en registros DNS históricos"""
        self.log("Técnica 1: Buscando historial DNS...", "info")
        
        ips_found = []
        
        # SecurityTrails API (versión gratuita vía hackertarget)
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
            response = requests.get(url, timeout=10, proxies=self.proxies)
            if response.status_code == 200:
                for line in response.text.strip().split('\n'):
                    if ',' in line:
                        parts = line.split(',')
                        if len(parts) >= 2:
                            ip = parts[1]
                            if self.is_valid_ip(ip) and ip not in ips_found:
                                ips_found.append(ip)
                                self.log(f"  IP histórica: {ip}", "found")
        except Exception as e:
            self.log(f"  Error con hackertarget: {str(e)[:50]}", "debug")
        
        # DNSlytics (otra fuente)
        try:
            url = f"https://dnslytics.com/domain/{self.domain}"
            response = requests.get(url, timeout=10, headers={'User-Agent': self.ua.random})
            # Extraer IPs del HTML (búsqueda simple)
            ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', response.text)
            for ip in ips:
                if self.is_valid_ip(ip) and ip not in ips_found:
                    ips_found.append(ip)
                    self.log(f"  IP encontrada en DNSlytics: {ip}", "found")
        except:
            pass
        
        self.results['techniques']['dns_history'] = ips_found
        return ips_found
    
    # ========== TÉCNICA 2: CERTIFICADOS SSL (CRT.SH, CENSYS) ==========
    def technique_ssl_certificates(self):
        """Extrae IPs de certificados SSL"""
        self.log("Técnica 2: Analizando certificados SSL...", "info")
        
        ips_found = []
        
        # CRT.sh
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = requests.get(url, timeout=15, proxies=self.proxies)
            if response.status_code == 200:
                certs = response.json()
                for cert in certs[:100]:  # Limitar a 100
                    name = cert.get('name_value', '')
                    if name and '*' not in name:
                        try:
                            ip = socket.gethostbyname(name)
                            if self.is_valid_ip(ip) and ip not in ips_found:
                                # Verificar si es IP real
                                if self.check_cloudflare(ip):
                                    ips_found.append(ip)
                                    self.log(f"  IP real via SSL: {ip} ({name})", "found")
                        except:
                            pass
        except Exception as e:
            self.log(f"  Error con crt.sh: {str(e)[:50]}", "debug")
        
        # Facebook IP (a veces tienen IPs reales en certificados)
        try:
            # Usar Facebook API para obtener IPs
            url = f"https://api.facebook.com/method/admin.getIPListForDomain?domain={self.domain}"
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                ips = response.text.strip().split('\n')
                for ip in ips:
                    if self.is_valid_ip(ip) and ip not in ips_found:
                        if self.check_cloudflare(ip):
                            ips_found.append(ip)
                            self.log(f"  IP via Facebook API: {ip}", "found")
        except:
            pass
        
        self.results['techniques']['ssl_certificates'] = ips_found
        return ips_found
    
    # ========== TÉCNICA 3: SUBNET SCANNING (BUSCAR EN LA MISMA RED) ==========
    def technique_subnet_scan(self, known_ips):
        """Escanea subredes cercanas a IPs conocidas"""
        self.log("Técnica 3: Escaneando subredes cercanas...", "info")
        
        if not known_ips:
            self.log("  No hay IPs base para escanear", "warning")
            return []
        
        ips_found = []
        
        def scan_ip(base_ip, offset):
            parts = base_ip.split('.')
            if len(parts) == 4:
                for i in range(1, 255):
                    new_ip = f"{parts[0]}.{parts[1]}.{parts[2]}.{i}"
                    try:
                        # Verificar si responde con el dominio correcto
                        headers = {'Host': self.domain, 'User-Agent': self.ua.random}
                        response = requests.get(f"http://{new_ip}", headers=headers, timeout=2)
                        if response.status_code < 500:
                            if self.check_cloudflare(new_ip):
                                ips_found.append(new_ip)
                                self.log(f"  IP encontrada en subred: {new_ip}", "found")
                    except:
                        pass
        
        threads = []
        for ip in known_ips[:3]:  # Limitar a 3 IPs base
            thread = threading.Thread(target=scan_ip, args=(ip, 0))
            thread.start()
            threads.append(thread)
        
        for thread in threads:
            thread.join(timeout=30)
        
        self.results['techniques']['subnet_scan'] = ips_found
        return ips_found
    
    # ========== TÉCNICA 4: FUERZA BRETA DE SUBDOMINIOS ==========
    def technique_subdomain_bruteforce(self):
        """Busca subdominios que puedan no estar en Cloudflare"""
        self.log("Técnica 4: Fuerza bruta de subdominios...", "info")
        
        subdomains = [
            'direct', 'origin', 'cdn', 'static', 'ftp', 'mail', 'webmail',
            'ssh', 'vpn', 'remote', 'access', 'admin', 'dev', 'staging',
            'test', 'qa', 'backup', 'proxy', 'lb', 'loadbalancer', 'ns1',
            'ns2', 'mx', 'pop', 'smtp', 'imap', 'autodiscover', 'autoconfig',
            'cpanel', 'whm', 'webdisk', 'cpcalendars', 'cpcontacts', 'blog',
            'shop', 'store', 'api', 'app', 'dashboard', 'panel', 'secure',
            'login', 'signin', 'auth', 'oauth', 'sso', 'identity', 'accounts',
            'account', 'user', 'users', 'profile', 'profiles', 'member',
            'members', 'customer', 'customers', 'client', 'clients', 'partner',
            'partners', 'vendor', 'vendors', 'supplier', 'suppliers', 'beta',
            'alpha', 'demo', 'sandbox', 'playground', 'lab', 'labs', 'internal',
            'intranet', 'corp', 'corporate', 'company', 'office', 'hr', 'payroll',
            'finance', 'accounting', 'sales', 'marketing', 'support', 'help',
            'helpdesk', 'ticket', 'tickets', 'service', 'services', 'status',
            'health', 'monitor', 'monitoring', 'graph', 'graphs', 'stats',
            'statistics', 'analytics', 'report', 'reports', 'dashboard',
            'dash', 'portal', 'gateway', 'edge', 'perimeter', 'firewall',
            'waf', 'security', 'safe', 'protect', 'protection', 'shield'
        ]
        
        found_ips = []
        
        def check_sub(sub):
            subdomain = f"{sub}.{self.domain}"
            try:
                ip = socket.gethostbyname(subdomain)
                if self.is_valid_ip(ip) and ip not in found_ips:
                    # Verificar si está en Cloudflare
                    if self.check_cloudflare(ip):
                        found_ips.append(ip)
                        self.log(f"  🔥 IP real encontrada via {subdomain}: {ip}", "found")
                        self.results['subdomains'].append({
                            'subdomain': subdomain,
                            'ip': ip
                        })
            except:
                pass
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(check_sub, subdomains)
        
        self.results['techniques']['subdomain_bruteforce'] = found_ips
        return found_ips
    
    # ========== TÉCNICA 5: FUERZA BRUTA DE PUERTOS (HTTP/HTTPS) ==========
    def technique_port_scan(self):
        """Escanea puertos comunes en busca de servicios web"""
        self.log("Técnica 5: Escaneando puertos alternativos...", "info")
        
        # Primero obtener IP de Cloudflare
        try:
            cloudflare_ip = socket.gethostbyname(self.domain)
            self.log(f"  IP pública (Cloudflare): {cloudflare_ip}", "debug")
        except:
            self.log("  No se pudo obtener IP de Cloudflare", "error")
            return []
        
        ports = [80, 443, 8080, 8443, 8888, 8000, 8008, 8081, 8082, 8083, 
                 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8091, 8092,
                 3000, 3001, 3002, 3003, 5000, 5001, 5002, 5003, 5004,
                 5005, 5006, 5007, 5008, 5009, 9000, 9001, 9002, 9003,
                 9004, 9005, 9006, 9007, 9008, 9009, 9090, 9091, 9092,
                 9093, 9094, 9095, 9096, 9097, 9098, 9099]
        
        found_ips = []
        
        def check_port(port):
            try:
                # Probar conexión directa a la IP de Cloudflare pero en puerto diferente
                headers = {'Host': self.domain, 'User-Agent': self.ua.random}
                url = f"http://{cloudflare_ip}:{port}"
                response = requests.get(url, headers=headers, timeout=3)
                
                if response.status_code < 500:
                    # Verificar que no sea Cloudflare
                    server = response.headers.get('Server', '').lower()
                    if 'cloudflare' not in server and not response.headers.get('CF-Ray'):
                        found_ips.append({
                            'ip': cloudflare_ip,
                            'port': port,
                            'status_code': response.status_code
                        })
                        self.log(f"  🔥 Servicio encontrado en {cloudflare_ip}:{port}", "found")
            except:
                pass
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(check_port, ports)
        
        self.results['techniques']['port_scan'] = found_ips
        return found_ips
    
    # ========== TÉCNICA 6: DNS MISCONFIGURATIONS (MX, NS, TXT) ==========
    def technique_dns_records(self):
        """Busca IPs en registros MX, NS, TXT"""
        self.log("Técnica 6: Analizando registros DNS...", "info")
        
        found_ips = []
        record_types = ['MX', 'NS', 'TXT', 'AAAA', 'SOA']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.domain, record_type, raise_on_no_answer=False)
                for rdata in answers:
                    if record_type == 'MX':
                        mx_domain = str(rdata.exchange).rstrip('.')
                        try:
                            ip = socket.gethostbyname(mx_domain)
                            if self.is_valid_ip(ip) and ip not in found_ips:
                                if self.check_cloudflare(ip):
                                    found_ips.append(ip)
                                    self.log(f"  IP via MX: {ip} ({mx_domain})", "found")
                        except:
                            pass
                    
                    elif record_type == 'NS':
                        ns_domain = str(rdata).rstrip('.')
                        try:
                            ip = socket.gethostbyname(ns_domain)
                            if self.is_valid_ip(ip) and ip not in found_ips:
                                if self.check_cloudflare(ip):
                                    found_ips.append(ip)
                                    self.log(f"  IP via NS: {ip} ({ns_domain})", "found")
                        except:
                            pass
                    
                    elif record_type == 'AAAA':
                        ip = str(rdata)
                        if ip not in found_ips:
                            found_ips.append(ip)
                            self.log(f"  IPv6 encontrada: {ip}", "found")
                    
                    elif record_type == 'TXT':
                        txt = str(rdata)
                        # Buscar IPs en texto
                        ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', txt)
                        for ip in ips:
                            if self.is_valid_ip(ip) and ip not in found_ips:
                                if self.check_cloudflare(ip):
                                    found_ips.append(ip)
                                    self.log(f"  IP en TXT: {ip}", "found")
            except:
                pass
        
        self.results['techniques']['dns_records'] = found_ips
        return found_ips
    
    # ========== TÉCNICA 7: FAVICON HASH (BUSCAR MISMO ICONO EN OTRAS IPs) ==========
    def technique_favicon_hash(self):
        """Busca IPs con el mismo favicon (mismo servidor)"""
        self.log("Técnica 7: Analizando favicon...", "info")
        
        try:
            # Obtener favicon del dominio
            url = f"https://{self.domain}/favicon.ico"
            response = requests.get(url, timeout=5, proxies=self.proxies)
            
            if response.status_code == 200:
                # Calcular hash del favicon (simple)
                import hashlib
                favicon_hash = hashlib.md5(response.content).hexdigest()
                self.log(f"  Favicon hash: {favicon_hash}", "debug")
                
                # Buscar en shodan (simulado)
                self.log("  Buscando en Shodan (simulado)...", "debug")
                # Aquí iría API de Shodan
                
                self.results['favicon_hash'] = favicon_hash
        except:
            pass
    
    # ========== TÉCNICA 8: GOOGLE DORKING ==========
    def technique_google_dorks(self):
        """Busca IPs en Google (simulado)"""
        self.log("Técnica 8: Google dorking...", "info")
        
        dorks = [
            f'site:{self.domain} -www',
            f'intitle:"{self.domain}" inurl:ip',
            f'"{self.domain}" "server at"'
        ]
        
        self.log("  Esta técnica requiere búsqueda manual", "warning")
        self.log(f"  Prueba: site:{self.domain} -www", "debug")
    
    # ========== FUNCIÓN PRINCIPAL ==========
    def run(self):
        """Ejecuta todas las técnicas"""
        print(BANNER)
        self.log(f"Objetivo: {self.domain}", "info")
        self.log(f"Iniciando bypass de Cloudflare con {self.threads} hilos...", "info")
        print()
        
        all_ips = []
        
        # Técnica 1: Historial DNS
        ips = self.technique_dns_history()
        all_ips.extend(ips)
        print()
        
        # Técnica 2: Certificados SSL
        ips = self.technique_ssl_certificates()
        all_ips.extend(ips)
        print()
        
        # Técnica 4: Subdominios (la más efectiva)
        ips = self.technique_subdomain_bruteforce()
        all_ips.extend(ips)
        print()
        
        # Técnica 5: Puertos
        ips = self.technique_port_scan()
        all_ips.extend(ips)
        print()
        
        # Técnica 6: Registros DNS
        ips = self.technique_dns_records()
        all_ips.extend(ips)
        print()
        
        # Técnica 3: Subnet scan (si tenemos IPs)
        if all_ips:
            ips = self.technique_subnet_scan(all_ips)
            all_ips.extend(ips)
            print()
        
        # Técnica 7 y 8 (informativas)
        self.technique_favicon_hash()
        self.technique_google_dorks()
        print()
        
        # Limpiar y deduplicar IPs reales
        real_ips = []
        for ip in all_ips:
            if isinstance(ip, dict):
                real_ips.append(ip)
            elif ip not in real_ips and self.is_valid_ip(ip):
                if self.check_cloudflare(ip):
                    real_ips.append(ip)
        
        self.results['real_ips'] = list(set(real_ips)) if real_ips else []
        
        # Mostrar resumen
        print(f"\n{MAGENTA}{'='*60}{RESET}")
        print(f"{MAGENTA}📊 RESULTADOS FINALES{RESET}")
        print(f"{MAGENTA}{'='*60}{RESET}")
        
        if self.results['real_ips']:
            print(f"{VERDE}✅ IPs reales encontradas:{RESET}")
            for ip in self.results['real_ips']:
                print(f"   {VERDE}→ {ip}{RESET}")
        else:
            print(f"{ROJO}❌ No se encontraron IPs reales{RESET}")
            print(f"{AMARILLO}   Sugerencias:{RESET}")
            print(f"   {AMARILLO}• Prueba con más subdominios{RESET}")
            print(f"   {AMARILLO}• Busca manualmente en crt.sh{RESET}")
            print(f"   {AMARILLO}• Revisa los registros MX/NS{RESET}")
        
        # Guardar resultados
        self.save_results()
        print()

def main():
    parser = argparse.ArgumentParser(
        description='🛡️ Cloudflare Bypass Pro - Encuentra la IP real detrás de Cloudflare',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python3 cloudflare-bypass-pro.py -d ejemplo.com
  python3 cloudflare-bypass-pro.py -d ejemplo.com --threads 100 -v
  python3 cloudflare-bypass-pro.py -d ejemplo.com --proxy http://127.0.0.1:8080
        """
    )
    
    parser.add_argument('-d', '--domain', required=True, help='Dominio a investigar')
    parser.add_argument('-t', '--threads', type=int, default=50, help='Número de hilos (default: 50)')
    parser.add_argument('-o', '--output', help='Archivo de salida (JSON)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Modo verbose')
    parser.add_argument('--proxy', help='Proxy (ej: http://127.0.0.1:8080)')
    parser.add_argument('--no-banner', action='store_true', help='No mostrar banner')
    
    args = parser.parse_args()
    
    bypass = CloudflareBypass(
        domain=args.domain,
        threads=args.threads,
        output=args.output,
        verbose=args.verbose,
        proxy=args.proxy
    )
    
    try:
        bypass.run()
    except KeyboardInterrupt:
        print(f"\n{ROJO}[!] Proceso interrumpido{RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"{ROJO}[!] Error: {str(e)}{RESET}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
