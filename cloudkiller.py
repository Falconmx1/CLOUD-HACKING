#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
☁️ CLOUDKILLER v1.0 - El destructor de nubes ☁️
Autor: Falconmx1
GitHub: https://github.com/Falconmx1/CLOUD-HACKING
Descripción: Herramienta todo-en-uno para pentesting en AWS/Azure/GCP
"""

import argparse
import sys
import json
import os
import socket
import dns.resolver
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import boto3
from colorama import init, Fore, Style
from fake_useragent import UserAgent

# Inicializar colorama
init(autoreset=True)

# ==================== CONFIGURACIÓN ====================
VERDE = Fore.GREEN
ROJO = Fore.RED
AMARILLO = Fore.YELLOW
AZUL = Fore.CYAN
MAGENTA = Fore.MAGENTA
RESET = Style.RESET_ALL

VERSION = "1.0"
BANNER = f"""
{MAGENTA}╔═══════════════════════════════════════════════════════════════╗
{MAGENTA}║     ☁️  CLOUDKILLER v{VERSION} - EL DESTRUCTOR DE NUBES ☁️          ║
{MAGENTA}║            Creado por: Falconmx1 🔥                          ║
{MAGENTA}╚═══════════════════════════════════════════════════════════════╝{RESET}
"""

# ==================== CLASE PRINCIPAL ====================
class CloudKiller:
    def __init__(self, target, threads=20, output=None, verbose=False):
        self.target = target.lower()
        self.threads = threads
        self.output = output
        self.verbose = verbose
        self.ua = UserAgent()
        self.lock = threading.Lock()
        
        # Limpiar target (quitar protocolos y www)
        self.clean_target = self.target.replace('http://', '').replace('https://', '').replace('www.', '')
        self.domain_main = self.clean_target.split('.')[0] if '.' in self.clean_target else self.clean_target
        
        # Resultados
        self.results = {
            "target": self.target,
            "clean_target": self.clean_target,
            "timestamp": datetime.now().isoformat(),
            "cloud_provider": "Desconocido",
            "real_ips": [],
            "buckets": [],
            "subdomains": [],
            "open_ports": [],
            "vulnerabilities": [],
            "services": []
        }
        
    # ========== FUNCIONES DE UTILIDAD ==========
    def log(self, message, level="info"):
        """Sistema de logging con colores"""
        with self.lock:
            if level == "info":
                print(f"{AZUL}[*]{RESET} {message}")
            elif level == "success":
                print(f"{VERDE}[+]{RESET} {message}")
            elif level == "error":
                print(f"{ROJO}[-]{RESET} {message}")
            elif level == "warning":
                print(f"{AMARILLO}[!]{RESET} {message}")
            elif level == "debug" and self.verbose:
                print(f"{MAGENTA}[DEBUG]{RESET} {message}")
    
    def save_results(self):
        """Guarda resultados en JSON"""
        if self.output:
            with open(self.output, 'w') as f:
                json.dump(self.results, f, indent=4)
            self.log(f"Resultados guardados en: {self.output}", "success")
        else:
            # Auto-generar nombre de archivo
            filename = f"cloudkiller_{self.clean_target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=4)
            self.log(f"Resultados guardados en: {filename}", "success")
    
    def print_summary(self):
        """Muestra resumen de lo encontrado"""
        print(f"\n{MAGENTA}{'='*60}{RESET}")
        print(f"{MAGENTA}📊 RESUMEN DEL ATAQUE{RESET}")
        print(f"{MAGENTA}{'='*60}{RESET}")
        print(f"Target: {self.target}")
        print(f"Proveedor Cloud: {self.results['cloud_provider']}")
        print(f"IPs Reales: {len(self.results['real_ips'])}")
        print(f"Buckets Encontrados: {len(self.results['buckets'])}")
        print(f"Subdominios: {len(self.results['subdomains'])}")
        print(f"Puertos Abiertos: {len(self.results['open_ports'])}")
        print(f"Vulnerabilidades: {len(self.results['vulnerabilities'])}")
        print(f"{MAGENTA}{'='*60}{RESET}")
    
    # ========== DETECCIÓN DE PROVEEDORES ==========
    def detect_cloud_provider(self):
        """Detecta si el target está en AWS, Azure, GCP o Cloudflare"""
        self.log("Detectando proveedor cloud...", "info")
        
        headers = {'User-Agent': self.ua.random}
        
        try:
            response = requests.get(f"http://{self.clean_target}", headers=headers, timeout=5, allow_redirects=True)
            server_header = response.headers.get('Server', '').lower()
            via_header = response.headers.get('Via', '').lower()
            cf_ray = response.headers.get('CF-Ray', '')
            x_powered = response.headers.get('X-Powered-By', '').lower()
            
            # Detección múltiple
            if 'cloudflare' in server_header or 'cloudflare' in via_header or cf_ray:
                provider = 'Cloudflare (protegiendo algún cloud)'
                self.log("Cloudflare detectado!", "warning")
                self.detect_real_ip()
            elif 'aws' in server_header or 'amazon' in server_header or 's3' in via_header:
                provider = 'AWS'
                self.log("AWS detectado!", "success")
            elif 'azure' in server_header or 'microsoft' in server_header or 'iis' in server_header:
                provider = 'Azure'
                self.log("Azure detectado!", "success")
            elif 'gcp' in server_header or 'google' in server_header or 'gws' in server_header:
                provider = 'GCP'
                self.log("GCP detectado!", "success")
            elif 'cloud' in server_header or 'cloud' in x_powered:
                provider = f'Posible cloud: {server_header}'
                self.log(f"Posible cloud: {server_header}", "warning")
            else:
                provider = 'Desconocido/no cloud'
                self.log("No se detectó proveedor cloud específico", "warning")
            
            self.results['cloud_provider'] = provider
            self.results['http_headers'] = dict(response.headers)
            
        except Exception as e:
            self.log(f"Error detectando proveedor: {str(e)}", "error")
            self.results['cloud_provider'] = 'Error en detección'
    
    # ========== BYPASS CLOUDFLARE ==========
    def detect_real_ip(self):
        """Multi-técnica para encontrar IP real detrás de Cloudflare"""
        self.log("Buscando IP real detrás de Cloudflare...", "info")
        
        real_ips = []
        
        # Técnica 1: Security Trails API (pública)
        self.log("Técnica 1: Historial DNS...", "debug")
        try:
            response = requests.get(f"https://api.hackertarget.com/hostsearch/?q={self.clean_target}", timeout=5)
            if response.status_code == 200:
                for line in response.text.split('\n'):
                    if ',' in line:
                        ip = line.split(',')[1]
                        if ip not in real_ips and self.is_valid_ip(ip):
                            real_ips.append(ip)
                            self.log(f"IP encontrada: {ip}", "success")
        except:
            pass
        
        # Técnica 2: Certificados SSL (CRT.sh)
        self.log("Técnica 2: Certificados SSL...", "debug")
        try:
            response = requests.get(f"https://crt.sh/?q=%.{self.clean_target}&output=json", timeout=5)
            if response.status_code == 200:
                certs = response.json()
                for cert in certs[:50]:  # Limitar a 50
                    name = cert.get('name_value', '')
                    if name and '*' not in name:
                        try:
                            ip = socket.gethostbyname(name)
                            if ip not in real_ips and self.is_valid_ip(ip):
                                real_ips.append(ip)
                                self.log(f"IP encontrada via SSL: {ip} ({name})", "success")
                        except:
                            pass
        except:
            pass
        
        # Técnica 3: Subdominios comunes
        self.log("Técnica 3: Fuerza bruta de subdominios...", "info")
        common_subs = [
            'direct', 'origin', 'cdn', 'static', 'ftp', 'mail', 'webmail',
            'ssh', 'vpn', 'remote', 'access', 'admin', 'dev', 'staging',
            'test', 'qa', 'backup', 'proxy', 'lb', 'loadbalancer'
        ]
        
        for sub in common_subs:
            subdomain = f"{sub}.{self.clean_target}"
            try:
                ip = socket.gethostbyname(subdomain)
                # Verificar si NO está en Cloudflare
                try:
                    response = requests.get(f"http://{ip}", timeout=2, headers={'Host': self.clean_target})
                    if 'cloudflare' not in response.headers.get('Server', '').lower():
                        if ip not in real_ips and self.is_valid_ip(ip):
                            real_ips.append(ip)
                            self.log(f"IP real posible: {ip} ({subdomain})", "success")
                except:
                    if ip not in real_ips and self.is_valid_ip(ip):
                        real_ips.append(ip)
                        self.log(f"IP encontrada: {ip} ({subdomain})", "success")
            except:
                pass
        
        if real_ips:
            self.results['real_ips'] = list(set(real_ips))
            self.log(f"Total IPs reales encontradas: {len(real_ips)}", "success")
        else:
            self.log("No se encontraron IPs reales", "error")
    
    def is_valid_ip(self, ip):
        """Valida si es una IP válida"""
        try:
            socket.inet_aton(ip)
            return True
        except:
            return False
    
    # ========== ENUMERACIÓN DE BUCKETS S3 ==========
    def enumerate_s3_buckets(self):
        """Enumera buckets S3 de forma inteligente"""
        self.log("Enumerando buckets S3...", "info")
        
        # Wordlist inteligente basada en el dominio
        bucket_names = self.generate_bucket_names()
        
        # Usar ThreadPoolExecutor para velocidad
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.check_s3_bucket, name): name for name in bucket_names}
            for future in as_completed(futures):
                future.result()  # Los resultados se guardan dentro de check_s3_bucket
    
    def generate_bucket_names(self):
        """Genera nombres de buckets personalizados"""
        base_names = [
            self.domain_main,
            self.clean_target,
            f"{self.domain_main}-backup",
            f"{self.domain_main}-dev",
            f"{self.domain_main}-prod",
            f"{self.domain_main}-staging",
            f"{self.domain_main}-test",
            f"{self.domain_main}-data",
            f"{self.domain_main}-files",
            f"{self.domain_main}-static",
            f"{self.domain_main}-assets",
            f"{self.domain_main}-media",
            f"{self.domain_main}-uploads",
            f"{self.domain_main}-public",
            f"{self.domain_main}-private",
            f"{self.domain_main}-bucket",
            f"{self.domain_main}-s3",
            f"{self.domain_main}-storage",
            f"{self.domain_main}-resources",
            f"{self.domain_main}-content",
            f"{self.domain_main}-images",
            f"{self.domain_main}-videos",
            f"{self.domain_main}-docs",
            f"{self.domain_main}-config",
            f"{self.domain_main}-logs",
            f"{self.domain_main}-temp",
            f"{self.domain_main}-tmp",
            f"{self.domain_main}-old",
            f"{self.domain_main}-archive",
            f"{self.domain_main}-2024",
            f"{self.domain_main}-2025",
            f"{self.domain_main}-backups",
            f"{self.domain_main}-database",
            f"{self.domain_main}-db",
            f"{self.domain_main}-sql",
            f"{self.domain_main}-mysql",
            f"{self.domain_main}-postgres",
            f"{self.domain_main}-mongo",
            f"{self.domain_main}-redis",
            f"{self.domain_main}-elastic",
            f"{self.domain_main}-search",
            f"{self.domain_main}-cache",
            f"{self.domain_main}-session",
            f"{self.domain_main}-user",
            f"{self.domain_main}-users",
            f"{self.domain_main}-customer",
            f"{self.domain_main}-customers",
            f"{self.domain_main}-client",
            f"{self.domain_main}-clients",
            f"{self.domain_main}-admin",
            f"{self.domain_main}-administrator",
            f"{self.domain_main}-root",
            f"{self.domain_main}-system",
            f"{self.domain_main}-app",
            f"{self.domain_main}-application",
            f"{self.domain_main}-web",
            f"{self.domain_main}-website",
            f"{self.domain_main}-www",
            f"{self.domain_main}-api",
            f"{self.domain_main}-rest",
            f"{self.domain_main}-graphql",
            f"{self.domain_main}-service",
            f"{self.domain_main}-services",
            f"{self.domain_main}-microservice",
            f"{self.domain_main}-function",
            f"{self.domain_main}-lambda"
        ]
        
        # Agregar variaciones con guiones
        variations = []
        for name in base_names:
            variations.append(name)
            variations.append(name.replace('.', '-'))
            variations.append(name.replace('.', ''))
        
        # Quitar duplicados y limitar
        return list(set(variations))[:200]  # Máximo 200 buckets
    
    def check_s3_bucket(self, bucket_name):
        """Verifica si un bucket existe y su estado"""
        # URLs posibles de S3
        urls = [
            f"http://{bucket_name}.s3.amazonaws.com",
            f"http://s3.amazonaws.com/{bucket_name}",
            f"http://{bucket_name}.s3-website-us-east-1.amazonaws.com",
            f"http://{bucket_name}.s3-website-us-west-1.amazonaws.com",
            f"http://{bucket_name}.s3-website-eu-west-1.amazonaws.com",
            f"http://{bucket_name}.s3-website-ap-southeast-1.amazonaws.com"
        ]
        
        headers = {'User-Agent': self.ua.random}
        
        for url in urls:
            try:
                response = requests.get(url, headers=headers, timeout=3, allow_redirects=False)
                
                bucket_info = {
                    'bucket': bucket_name,
                    'url': url,
                    'status_code': response.status_code
                }
                
                if response.status_code == 200:
                    # Bucket público
                    bucket_info['status'] = 'PUBLICO'
                    bucket_info['files'] = self.list_s3_files(bucket_name)
                    self.log(f"🔥 Bucket PÚBLICO encontrado: {url}", "success")
                    self.results['buckets'].append(bucket_info)
                    break
                    
                elif response.status_code == 403:
                    # Bucket existe pero privado
                    bucket_info['status'] = 'PRIVADO'
                    self.log(f"🔒 Bucket privado: {url}", "warning")
                    self.results['buckets'].append(bucket_info)
                    break
                    
                elif response.status_code == 404:
                    # No existe, continuar
                    continue
                    
            except requests.exceptions.ConnectionError:
                continue
            except Exception as e:
                self.log(f"Error con {url}: {str(e)[:50]}", "debug")
    
    def list_s3_files(self, bucket_name):
        """Lista archivos de un bucket público usando boto3"""
        files = []
        try:
            # Intentar con boto3
            s3 = boto3.client('s3', config=boto3.session.Config(signature_version='unsigned'))
            response = s3.list_objects_v2(Bucket=bucket_name, MaxKeys=50)
            
            if 'Contents' in response:
                for obj in response['Contents']:
                    files.append({
                        'key': obj['Key'],
                        'size': obj['Size'],
                        'last_modified': str(obj['LastModified']),
                        'url': f"https://{bucket_name}.s3.amazonaws.com/{obj['Key']}"
                    })
                
                self.log(f"  📁 {len(files)} archivos encontrados en {bucket_name}", "success")
                
                # Mostrar algunos archivos
                for f in files[:5]:  # Mostrar primeros 5
                    self.log(f"    - {f['key']} ({f['size']} bytes)", "debug")
                    
        except Exception as e:
            # Fallback a requests
            try:
                response = requests.get(f"https://{bucket_name}.s3.amazonaws.com/?max-keys=20", timeout=5)
                if response.status_code == 200 and '<Contents>' in response.text:
                    self.log(f"  ⚠️ Bucket listable via XML (revisar manualmente)", "warning")
                    files.append("XML listing available - check manually")
            except:
                pass
        
        return files
    
    # ========== ENUMERACIÓN DE SUBDOMINIOS ==========
    def enumerate_subdomains(self):
        """Encuentra subdominios del target"""
        self.log("Enumerando subdominios...", "info")
        
        # Wordlist de subdominios comunes
        sub_wordlist = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test',
            'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3',
            'mail2', 'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx', 'static',
            'docs', 'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar', 'wiki',
            'web', 'media', 'email', 'images', 'img', 'download', 'dns', 'piwik', 'stats',
            'analytics', 'partner', 'api', 'stage', 'staging', 'live', 'prod', 'production',
            'app', 'application', 'dashboard', 'adminer', 'phpmyadmin', 'phpPgAdmin',
            'mysqladmin', 'pgadmin', 'redis', 'memcached', 'elastic', 'log', 'logs',
            'backup', 'backups', 'dump', 'dumpster', 'transfer', 'upload', 'uploads',
            'downloads', 'files', 'storage', 'bucket', 's3', 'assets', 'css', 'js',
            'javascript', 'style', 'img', 'png', 'jpg', 'gif', 'video', 'videos',
            'audio', 'music', 'mp3', 'doc', 'docs', 'document', 'documents', 'pdf',
            'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'text', 'csv', 'tsv', 'xml', 'json',
            'yaml', 'yml', 'config', 'conf', 'cfg', 'settings', 'env', 'environment',
            'local', 'development', 'dev', 'testing', 'test', 'acceptance', 'staging',
            'preprod', 'preproduction', 'prod', 'production', 'release', 'releases',
            'build', 'builds', 'ci', 'cd', 'jenkins', 'git', 'github', 'gitlab',
            'bitbucket', 'svn', 'subversion', 'mercurial', 'hg', 'cvs', 'vcs',
            'repo', 'repository', 'repositories', 'code', 'source', 'src'
        ]
        
        found = []
        
        def check_sub(sub):
            subdomain = f"{sub}.{self.clean_target}"
            try:
                ip = socket.gethostbyname(subdomain)
                with self.lock:
                    found.append({'subdomain': subdomain, 'ip': ip})
                    self.log(f"Subdominio: {subdomain} -> {ip}", "success")
            except:
                pass
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(check_sub, sub_wordlist)
        
        self.results['subdomains'] = found
        self.log(f"Total subdominios encontrados: {len(found)}", "success")
    
    # ========== ESCANEO DE PUERTOS BÁSICO ==========
    def scan_ports(self):
        """Escanea puertos comunes en IPs encontradas"""
        if not self.results['real_ips'] and not self.results['subdomains']:
            self.log("No hay IPs para escanear", "warning")
            return
        
        self.log("Escaneando puertos comunes...", "info")
        
        common_ports = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            111: 'RPC',
            135: 'RPC',
            139: 'NetBIOS',
            143: 'IMAP',
            443: 'HTTPS',
            445: 'SMB',
            993: 'IMAPS',
            995: 'POP3S',
            1723: 'PPTP',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5900: 'VNC',
            5985: 'WinRM',
            5986: 'WinRM',
            6379: 'Redis',
            8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt',
            27017: 'MongoDB'
        }
        
        all_ips = []
        all_ips.extend(self.results['real_ips'])
        for sub in self.results['subdomains']:
            if sub['ip'] not in all_ips:
                all_ips.append(sub['ip'])
        
        def check_port(ip_port):
            ip, port = ip_port
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                sock.close()
                
                if result == 0:
                    service = common_ports.get(port, 'Unknown')
                    with self.lock:
                        self.results['open_ports'].append({
                            'ip': ip,
                            'port': port,
                            'service': service
                        })
                        self.log(f"Puerto abierto: {ip}:{port} ({service})", "success")
            except:
                pass
        
        tasks = []
        for ip in all_ips:
            for port in common_ports.keys():
                tasks.append((ip, port))
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(check_port, tasks)
        
        self.log(f"Total puertos abiertos: {len(self.results['open_ports'])}", "success")
    
    # ========== VERIFICACIÓN DE VULNERABILIDADES ==========
    def check_vulnerabilities(self):
        """Verifica vulnerabilidades comunes en servicios encontrados"""
        self.log("Verificando vulnerabilidades comunes...", "info")
        
        for port_info in self.results['open_ports']:
            ip = port_info['ip']
            port = port_info['port']
            service = port_info['service']
            
            # Verificar puertos administrativos expuestos
            if port in [3306, 5432, 27017, 6379]:  # Bases de datos
                vuln = {
                    'ip': ip,
                    'port': port,
                    'service': service,
                    'vulnerability': 'Base de datos expuesta públicamente',
                    'risk': 'ALTO',
                    'check': f"Intenta conectar a {ip}:{port}"
                }
                self.results['vulnerabilities'].append(vuln)
                self.log(f"⚠️  Base de datos expuesta: {ip}:{port}", "warning")
            
            # Verificar servicios sin cifrar
            if port in [21, 23, 110, 143]:  # Servicios sin cifrar
                vuln = {
                    'ip': ip,
                    'port': port,
                    'service': service,
                    'vulnerability': 'Tráfico sin cifrar (credenciales en texto claro)',
                    'risk': 'MEDIO',
                    'check': f"Sniffear tráfico en {ip}:{port}"
                }
                self.results['vulnerabilities'].append(vuln)
                self.log(f"⚠️  Servicio sin cifrar: {ip}:{port}", "warning")
    
    # ========== FUNCIÓN PRINCIPAL ==========
    def run(self):
        """Ejecuta todos los módulos"""
        print(BANNER)
        self.log(f"Objetivo: {self.target}", "info")
        self.log(f"Iniciando ataque a las nubes... ☁️", "info")
        
        # Detección inicial
        self.detect_cloud_provider()
        
        # Enumeración
        self.enumerate_s3_buckets()
        self.enumerate_subdomains()
        
        # Escaneo si tenemos IPs
        if self.results['real_ips'] or self.results['subdomains']:
            self.scan_ports()
            self.check_vulnerabilities()
        
        # Resumen y guardado
        self.print_summary()
        self.save_results()
        
        self.log("Ataque completado!", "success")

# ==================== MAIN ====================
def main():
    parser = argparse.ArgumentParser(
        description='☁️ CloudKiller - Herramienta de pentesting cloud todo-en-uno',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python3 cloudkiller.py -t ejemplo.com
  python3 cloudkiller.py -t 192.168.1.1 --threads 50 -v
  python3 cloudkiller.py -t empresa.com -o resultados.json
        """
    )
    
    parser.add_argument('-t', '--target', required=True, help='Dominio o IP objetivo')
    parser.add_argument('--threads', type=int, default=20, help='Número de hilos (default: 20)')
    parser.add_argument('-o', '--output', help='Archivo de salida para resultados (JSON)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Modo verbose (muestra más detalles)')
    parser.add_argument('--no-banner', action='store_true', help='No mostrar el banner')
    
    args = parser.parse_args()
    
    # Crear instancia y ejecutar
    killer = CloudKiller(
        target=args.target,
        threads=args.threads,
        output=args.output,
        verbose=args.verbose
    )
    
    try:
        killer.run()
    except KeyboardInterrupt:
        print(f"\n{ROJO}[!] Ataque interrumpido por el usuario{RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"{ROJO}[!] Error fatal: {str(e)}{RESET}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
