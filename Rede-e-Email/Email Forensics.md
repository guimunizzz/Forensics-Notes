---
tags: [dfir, email-forensics, soc, blue-team]
area: Blue Team / DFIR
status: estudo-ativo
---

# Email Forensics

> [!info] Sobre esta nota
> Email forensics é onde a forense de rede encontra o fator humano: o mesmo tráfego SMTP/IMAP/POP3 que aparece em [Network Forensics](Network%20Forensics.md) carrega aqui a evidência de phishing, BEC, spoofing e malware entregue por anexo. Ferramentas como Wireshark e NetworkMiner (já vistas naquela nota) reaparecem, agora com foco no protocolo de e-mail; a diferença é que esta nota adiciona uma camada extra de análise — header, corpo e anexo — que não existe ao analisar tráfego genérico de rede.

## Sumário
1. [Introdução ao Email Forensics](#1-introdução-ao-email-forensics)
2. [Protocolos de Email](#2-protocolos-de-email)
3. [Ferramentas de Email Forensics](#3-ferramentas-de-email-forensics)
4. [Análise de Header do Email](#4-análise-de-header-do-email)
5. [Análise do Corpo do Email](#5-análise-do-corpo-do-email)
6. [Análise de Anexos](#6-análise-de-anexos)
7. [Identificação e Análise de Ameaças por Email](#7-identificação-e-análise-de-ameaças-por-email)
8. [Tópicos Complementares](#8-tópicos-complementares)
9. [Metodologia de Investigação (Checklist)](#9-metodologia-de-investigação-checklist)
10. [Cheatsheet de Referência Rápida](#10-cheatsheet-de-referência-rápida)

---

## 1. Introdução ao Email Forensics

**Email forensics** é a disciplina que analisa mensagens de e-mail, seus metadados e o tráfego que as transportou para produzir evidências usadas em investigações de segurança e processos legais — fraude, phishing, BEC, vazamento de dados, ameaças internas.

O e-mail é um dos vetores de ataque mais usados até hoje porque explora o elo mais fraco de qualquer ambiente: a pessoa que lê a mensagem. Por isso a investigação de e-mail normalmente cobre três camadas complementares:

| Camada | O que analisa | Pergunta que responde |
|---|---|---|
| **Header** | Metadados de roteamento e autenticação | "De onde essa mensagem realmente veio e por onde passou?" |
| **Corpo** | Texto, HTML, links | "O conteúdo tenta enganar ou manipular o destinatário?" |
| **Anexo** | Arquivos entregues junto à mensagem | "Existe payload malicioso escondido no anexo?" |

> [!tip] Pré-requisitos
> Fundamentos de redes e protocolos (ver [Network Forensics](Network%20Forensics.md)), noção básica de DNS e conceitos gerais de forense digital (cadeia de custódia, hashing de evidência).

---

## 2. Protocolos de Email

Três protocolos formam a espinha dorsal da comunicação por e-mail — cada um com um papel e riscos de segurança distintos.

### 2.1 SMTP (Simple Mail Transfer Protocol)

SMTP é o protocolo de **envio** ("push") — move a mensagem do servidor do remetente até o servidor do destinatário. Não criptografa o conteúdo por padrão (mitigado com STARTTLS/TLS).

**Fluxo prático — Bob envia e-mail para Alice:**
1. Bob escreve o e-mail no cliente (Outlook/Gmail) para `alice@yahoo.com`.
2. O cliente entrega a mensagem ao servidor de Bob (ex.: Gmail), que a armazena para envio.
3. O servidor de Bob (atuando como **cliente SMTP**) contata o servidor de Alice (Yahoo, atuando como **servidor SMTP**).
4. Após o handshake SMTP, a mensagem é transferida entre os dois servidores.
5. O servidor de Alice armazena a mensagem na caixa dela.
6. Alice usa seu cliente (ex.: Outlook) para buscar e ler a mensagem — aqui entram IMAP/POP3 (seção 2.2).

**Comandos SMTP (protocolo texto, cliente envia comando → servidor responde com código numérico):**

| Comando | Função |
|---|---|
| `EHLO` | Cliente se identifica e descobre os comandos suportados pelo servidor |
| `MAIL FROM` | Identifica o remetente |
| `RCPT TO` | Identifica o(s) destinatário(s) |
| `DATA` | Início do header + corpo da mensagem |
| `QUIT` | Encerra a sessão |

**Exemplo prático — sessão SMTP manual via telnet (para entender o protocolo na prática):**
```bash
telnet mailserver.exemplo.com 25
EHLO cliente.exemplo.com
MAIL FROM:<bob@gmail.com>
RCPT TO:<alice@yahoo.com>
DATA
Subject: Teste

Corpo da mensagem de teste.
.
QUIT
```

### 2.2 Porta 25 x Porta 587

| | **Porta 25** | **Porta 587** |
|---|---|---|
| Uso | Relay servidor → servidor | Cliente → seu próprio servidor de envio |
| Criptografia | Normalmente sem exigência de TLS | Geralmente exige SSL/TLS |
| Restrição | Muitos ISPs bloqueiam/restringem (vetor clássico de spam) | Porta recomendada para envio autenticado |

> [!tip] Regra prática
> Se um host interno está fazendo conexões de saída na porta 25 para múltiplos destinos externos (fora do MTA corporativo legítimo), é um forte indício de **host comprometido atuando como spam relay**.

### 2.3 IMAP x POP3 (recebimento)

| | **IMAP** | **POP3** |
|---|---|---|
| Onde vive o e-mail | No servidor, sincronizado entre dispositivos | Baixado e armazenado localmente |
| Melhor para | Acesso multi-dispositivo | Uso simples em um único dispositivo |
| Porta sem criptografia | 143 (hoje normalmente com STARTTLS) | 110 (hoje normalmente com STARTTLS) |
| Porta com TLS/SSL nativo | 993 | 995 |
| Risco forense | Estado sincronizado pode mudar entre a detecção e a coleta | Cópia local pode já ter sido apagada do servidor |

> [!warning] Implicação forense
> Em ambientes IMAP, uma ação do usuário ou do atacante (apagar, marcar como lido, mover pasta) se propaga para todos os dispositivos quase instantaneamente. Priorize preservar a evidência (exportar `.eml`/logs do servidor) assim que possível — o estado "ao vivo" é volátil.

> [!info] Nota sobre webmail
> Ao acessar Gmail/Yahoo pelo navegador, nem SMTP nem IMAP/POP3 aparecem no tráfego do cliente — é tudo HTTP/HTTPS. SMTP continua existindo, mas apenas na comunicação **servidor a servidor**.

---

## 3. Ferramentas de Email Forensics

| Ferramenta | Papel na investigação |
|---|---|
| **Wireshark** | Captura e analisa tráfego SMTP/IMAP/POP3 em trânsito, detectando erros de protocolo e falhas de segurança |
| **NetworkMiner** | Análise passiva de tráfego de rede, extrai sessões e mensagens de e-mail automaticamente |
| **The Sleuth Kit + Autopsy** | Extração forense de e-mails a partir de imagens de disco ou arquivos `.eml`/`.mbox`/`.pst`, com módulo dedicado de Email Parser |

### 3.1 Wireshark

```
smtp                       # isola tráfego SMTP
```
Clique com o botão direito em um pacote SMTP → **Follow → TCP Stream** para reconstruir a sessão inteira (comandos EHLO/MAIL FROM/RCPT TO/DATA e a resposta do servidor).

### 3.2 NetworkMiner

- Aba **Sessions**: mostra as sessões estabelecidas, permitindo identificar tráfego de e-mail.
- Aba **Keywords**: permite buscar termos específicos no tráfego capturado (ex.: um domínio suspeito).
- Aba **Hosts**: detalhes dos hosts com os quais houve comunicação — útil para mapear todos os servidores de e-mail envolvidos.

### 3.3 The Sleuth Kit / Autopsy — Email Parser

Fluxo para analisar um `.eml` no Autopsy:
1. **Add Data Source** → selecionar **Logical Files**.
2. Escolher **"Generate new hostname based on data source name"** → **Next**.
3. Adicionar o(s) arquivo(s) `.eml` (ou `.mbox`/`.pst`) → **Next**.
4. Em **Configure Ingest**, garantir que o módulo **Email Parser** esteja marcado.
5. **Finish** e aguardar o processamento.

O Email Parser reconhece **MBOX, EML e PST** pela assinatura do arquivo (não pela extensão), extrai as mensagens e gera artefatos no blackboard, incluindo anexos como arquivos derivados.

Após o processamento, os pontos de maior valor forense no Autopsy são:

| Artefato | Para que serve na investigação |
|---|---|
| **Data Artifacts / Email Messages** | Reconstrução da timeline e conteúdo de cada mensagem |
| **Communication Accounts** | Mapeia contas envolvidas — revela múltiplas contas ou padrões suspeitos |
| **Metadata** | Datas de criação/modificação — cruzar com a timeline do incidente |
| **Keyword Hits** | Localiza rapidamente termos-chave (domínios, nomes, valores) no volume de mensagens |

---

## 4. Análise de Header do Email

O header carrega os metadados de roteamento e autenticação — é normalmente o **primeiro lugar a olhar** para validar se um e-mail é legítimo.

### 4.1 Campos principais

| Campo | O que informa | O que observar (vetor de ataque) |
|---|---|---|
| **From** | Remetente declarado | Frequentemente forjado em spoofing/phishing — validar contra o domínio real |
| **To** | Destinatário(s) | Destinatários inesperados/irrelevantes podem indicar spear-phishing |
| **Subject** | Assunto | Linguagem de urgência/ameaça é bandeira vermelha clássica |
| **Date** | Data/hora de envio (RFC 2822) | Timestamps adulterados podem indicar fraude |
| **Received** | Um registro por servidor pelo qual a mensagem passou | A cadeia real de roteamento — a parte mais difícil de forjar de ponta a ponta |
| **MIME-Version** | Versão do padrão MIME usado | Versões incomuns/desatualizadas podem acompanhar conteúdo malicioso |
| **Content-Type** | Formato do corpo (`text/plain`, `text/html`, `multipart/mixed`...) | `text/html` pode esconder script ou iframe malicioso |
| **Message-ID** | Identificador único da mensagem | Formato fora do padrão esperado do domínio pode indicar forjamento |

### 4.2 Como acessar o header

No Outlook/O365: clique nos **"..."** do e-mail (ou botão direito) → **View → View Message Source**.

### 4.3 Como ler a cadeia de `Received`

> [!tip] Regra de ouro
> As linhas `Received` devem ser lidas **de baixo para cima** — a linha mais próxima do topo do header é o servidor mais recente (o que entregou a mensagem para você); a mais antiga (mais abaixo) é o ponto de origem mais próximo do remetente real.

**Exemplo anotado (header sintético para prática):**
```
Received: from mail.destinatario.com (mail.destinatario.com [203.0.113.10])
    by mx.destinatario.com; Wed, 08 Jul 2026 09:15:32 -0300
Received: from relay.suspeito.net (relay.suspeito.net [198.51.100.77])
    by mail.destinatario.com; Wed, 08 Jul 2026 09:15:20 -0300
From: "Suporte Banco XYZ" <suporte@bancoxyz.com>
Reply-To: financeiro@bancoxyz.com
Return-Path: <bounce@relay.suspeito.net>
Message-ID: <a1b2c3@relay.suspeito.net>
Received-SPF: fail (bancoxyz.com: domain does not designate 198.51.100.77 as permitted sender)
Authentication-Results: mx.destinatario.com; spf=fail; dkim=none; dmarc=fail
Subject: Sua conta será suspensa - ação urgente necessária
```

**Leitura do analista:**
- O `From` mostra `bancoxyz.com`, mas o `Message-ID` e o `Return-Path` apontam para `relay.suspeito.net` — **domínios não batem**.
- `Received-SPF: fail` e `dmarc=fail` confirmam que `198.51.100.77` **não** é um remetente autorizado para `bancoxyz.com`.
- O `Reply-To` diferente do `From` é outro sinal clássico — qualquer resposta vai para `financeiro@bancoxyz.com`, não necessariamente controlado pelo atacante, mas frequentemente também forjado ou usado para redirecionar a vítima.
- Assunto com linguagem de urgência/ameaça reforça a suspeita de phishing (ver seção 5.2).

> [!danger] Conclusão do exemplo
> Esse conjunto de evidências (SPF fail + DMARC fail + domínios divergentes + urgência no assunto) é suficiente para classificar a mensagem como **spoofing/phishing** com alta confiança, mesmo antes de olhar o corpo do e-mail.

---

## 5. Análise do Corpo do Email

### 5.1 Extração de conteúdo

Objetivo: isolar todo o texto, HTML, imagens e outros elementos do corpo (e dos anexos) em formato acessível para análise — sem executar nada. No Autopsy, isso é feito automaticamente pelo Email Parser: as abas **Communication Accounts**, **Metadata**, **Keyword Hits** e **Attachments** ficam disponíveis para o `.eml` processado.

### 5.2 Análise textual (engenharia social)

Pontos de checagem, com exemplo prático de e-mail de phishing:

```
Assunto: Account Need Update
De: "Suporte" <suporte@wellknownbank-secure.com>

Dear user,

Due to update in systems, your account will be temporarily suspended.
Please [Verify Account] within 24 hours to avoid permanent suspension.
```

| Sinal | Onde aparece no exemplo |
|---|---|
| Erro gramatical | "Account **Need** Update" → correto seria "Needs Update"; "Due to update in systems" → correto seria "Due to an update in our systems" |
| Saudação genérica | "Dear user" em vez do nome real do destinatário |
| Linguagem de ameaça/urgência | "will be temporarily suspended", prazo de 24h |
| Texto de link não descritivo | `[Verify Account]` não informa o destino real |
| Domínio suspeito | `wellknownbank-secure.com` imita a marca mas não é o domínio oficial |

### 5.3 Análise de links

- Passar o mouse sobre o link e comparar a **URL exibida** com a **URL real do destino** (hover ≠ href é sinal clássico de engano).
- Resolver links encurtados (bit.ly, tinyurl) antes de classificar como seguro/malicioso.
- No Autopsy, usar **Keyword Search** para extrair todas as URLs de um `.eml` de uma vez e depois checar cada uma como IOC (VirusTotal, urlscan.io).

### 5.4 Análise de HTML e código embutido

Scripts (JavaScript), CSS e outros códigos ativos dentro do HTML do corpo devem ser inspecionados manualmente — podem coletar dados do usuário ou redirecionar silenciosamente.

**Exemplo prático — decodificando um anexo/trecho em Base64:**
```bash
echo "SGVsbG8sIHRoaXMgaXMgYSBoaWRkZW4gcGF5bG9hZC4=" | base64 -d
# Saída: Hello, this is a hidden payload.
```
No Autopsy, o conteúdo decodificado de anexos em Base64 já é exibido diretamente na aba de detalhes do anexo — não é necessário decodificar manualmente na maioria dos casos, mas ferramentas online de decode Base64 servem como validação cruzada.

---

## 6. Análise de Anexos

Três fases complementares — da mais rápida/segura para a mais profunda:

### 6.1 Análise Estática

Examina características do arquivo **sem executá-lo**.

| O que checar | Por quê |
|---|---|
| **Tipo de arquivo real** (assinatura/magic bytes, não a extensão) | Um `.exe` pode estar disfarçado como `.pdf` |
| **Tamanho** | Tamanhos anormalmente grandes/pequenos podem indicar conteúdo oculto |
| **Metadados** | Datas de criação/modificação e autor ajudam a rastrear origem |
| **Hash (MD5/SHA-256)** | Comparar contra bases de malware conhecidas |
| **Strings extraídas** | Comandos, IPs ou URLs suspeitos embutidos no binário |

**Exemplo prático — checagem de assinatura de arquivo (Linux):**
```bash
file documento_suspeito.pdf
# Saída esperada: PDF document, version 1.x
# Se retornar algo como "PE32 executable", o arquivo NÃO é um PDF de verdade
```

**Exemplo prático — hash e strings:**
```bash
sha256sum anexo.xls
strings anexo.xls | grep -Ei "http|cmd|powershell"
```

**Ferramentas online de análise estática:**
- **VirusTotal** — sobe o arquivo/hash e compara contra dezenas de engines de antivírus; mostra também **Relationships** (URLs, domínios e IPs conectados ao arquivo).
- **Hybrid Analysis** (powered by Falcon Sandbox) — análise estática e dinâmica combinadas.
- **`strings`** (Linux/Unix) — extração offline de strings legíveis do binário.

### 6.2 Análise Dinâmica (Sandbox)

Executa o anexo em ambiente isolado para observar o comportamento real.

| Tool | Característica |
|---|---|
| **Any.Run** | Sandbox interativo online, permite acompanhar processos em tempo real |
| **Cuckoo Sandbox** | Open-source, self-hosted, relatórios detalhados de rede/arquivo/registro |
| **Joe Sandbox** | Suporta amplo leque de tipos de arquivo e SOs |
| **VMRay** | Foco em detecção avançada com técnicas anti-evasão |

O que observar durante a execução:
- **Atividade de rede**: requisições HTTP, DNS queries, conexões estabelecidas (possível C2).
- **Mudanças em arquivo/registro**: criação de arquivos, chaves de registro persistentes.
- **Comportamento**: keylogging, autorreplicação, tentativas de propagação lateral.

**Exemplo de fluxo prático (anexo `.xlsx` suspeito no Any.Run):**
1. Upload do arquivo → execução automática em VM isolada.
2. Aba **HTTP Requests** → mostra chamadas de rede feitas pelo processo do Excel/macro.
3. Aba **Connections** → IPs/portas contactados.
4. Aba **DNS Requests** → domínios resolvidos (possíveis C2).
5. Aba **Threats** → classificação automática se malicioso.
6. Aba **Files** → arquivos criados/modificados durante a execução.

> [!warning] Cuidado operacional
> Nunca execute um anexo suspeito fora de um sandbox isolado (sem rede de produção, sem snapshot compartilhado). O objetivo da análise dinâmica é justamente permitir a detonação seguro — qualquer atalho aqui pode comprometer o ambiente real.

### 6.3 Detecção Baseada em Assinatura

Complementa as duas fases anteriores comparando hash/padrões do anexo contra bases de assinaturas conhecidas (motor de antivírus, YARA rules). Rápido, mas não cobre ameaças 0-day — mesma limitação já discutida em [Network Forensics](Network%20Forensics.md) para Snort/Suricata.

---

## 7. Identificação e Análise de Ameaças por Email

| Ameaça | Exemplo | Pontos de análise |
|---|---|---|
| **Phishing** | E-mail fingindo ser do banco pedindo para "atualizar" dados via link | Legitimidade do remetente, linguagem/tom, segurança do link |
| **Spear Phishing** | Ataque personalizado usando dados já coletados sobre a vítima | Grau de personalização e uso de dados pessoais específicos |
| **Spam** | Ofertas de produtos, promoções falsas em massa | Conteúdo não solicitado, padrões de envio em massa, horário de envio |
| **Malware** | Anexo aparentemente relacionado ao trabalho que instala ransomware | Anexos maliciosos, macros, executáveis — análise dinâmica é essencial |
| **BEC (Business Email Compromise)** | Instruções fraudulentas de pagamento fingindo ser do CFO | Pedidos financeiros urgentes e incomuns; comparar estilo de comunicação com e-mails anteriores legítimos |
| **Email Spoofing** | Forjar o endereço do remetente para se passar por um executivo | Checar `From`, `Return-Path`, `Reply-To`, IP e domínio real via `Received` |
| **Domain Impersonation** | Uso de `examp1e.com` no lugar de `example.com` | Comparação caractere a caractere da URL/domínio, consulta DNS/WHOIS |
| **Credential Harvesting** | Formulário falso de login para roubar credenciais | Checar links/formulários e a segurança do site de destino |
| **Whaling** | Spear phishing direcionado a executivos seniores | Conteúdo detalhado e customizado visando alto escalão |
| **Extortion** | E-mail de extorsão ameaçando vazar dados/travar sistemas | Detectar conteúdo de ameaça e pedido de resgate sob pressão de tempo |
| **Brand Impersonation** | E-mail imitando visualmente uma marca conhecida | Comparar logotipos/estilo com fontes oficiais da marca |
| **Data Exfiltration** | Funcionário enviando dados confidenciais para concorrente | Checar anexos e conteúdo textual em busca de vazamento não autorizado |

> [!info] Padrão comum
> Praticamente todas essas ameaças deixam rastro em pelo menos duas das três camadas (header + corpo, ou corpo + anexo) — por isso a metodologia da seção 9 sempre passa pelas três, mesmo quando o indício inicial já parece claro em uma só.

---

## 8. Tópicos Complementares

> [!info] Sobre esta seção
> Conceitos que não vieram no material original mas que fecham lacunas técnicas importantes: como SPF/DKIM/DMARC realmente funcionam por baixo dos panos, como lidar com os formatos de arquivo de e-mail além do `.eml`, e como email forensics se encaixa no fluxo maior de um SOC.

### 8.1 SPF, DKIM e DMARC — como funcionam de fato

Os headers `Received-SPF` e `Authentication-Results` aparecem em quase todo caso de spoofing/phishing (seções 4.3 e 7), mas vale entender o mecanismo por trás:

| Mecanismo | O que verifica | Onde é publicado | Falha comum |
|---|---|---|---|
| **SPF** (Sender Policy Framework) | Se o IP do servidor de envio está autorizado a enviar em nome do domínio | Registro **TXT** no DNS do domínio (ex.: `v=spf1 include:_spf.google.com ~all`) | Domínio spoofado não está na lista de IPs autorizados → `spf=fail` |
| **DKIM** (DomainKeys Identified Mail) | Assinatura criptográfica do conteúdo da mensagem, valida que não foi alterada em trânsito | Chave pública em registro **TXT** DNS (`selector._domainkey.dominio.com`) | Mensagem forjada não tem a assinatura privada correta → `dkim=fail` ou `dkim=none` |
| **DMARC** (Domain-based Message Authentication) | Política de o que fazer quando SPF e/ou DKIM falham (`reject`, `quarantine`, `none`) + relatórios | Registro **TXT** (`_dmarc.dominio.com`) | Domínio sem DMARC configurado (`p=none`) permite que spoofing passe sem ser bloqueado, mesmo com SPF/DKIM corretos |

**Exemplo prático — consultando os registros de um domínio:**
```bash
dig txt dominio.com | grep spf
dig txt _dmarc.dominio.com
```

> [!tip] Leitura rápida do Authentication-Results
> `Authentication-Results: mx.exemplo.com; spf=pass; dkim=pass; dmarc=pass` → mensagem autenticada com alta confiança.
> `spf=fail; dkim=none; dmarc=fail` → forte indício de spoofing, como no exemplo da seção 4.3.

### 8.2 Formatos de arquivo de email e como tratá-los

| Formato | Descrição | Como analisar |
|---|---|---|
| **`.eml`** | Mensagem única em texto puro (header + corpo em MIME) | Abrir direto em qualquer editor de texto ou ingerir no Autopsy |
| **`.msg`** | Formato binário proprietário do Outlook (uma mensagem) | `msgconvert` (Perl) converte para `.eml`; ou abrir direto no Outlook |
| **`.pst` / `.ost`** | Arquivo de mailbox completo do Outlook (`.pst` = arquivo pessoal/offline; `.ost` = cache sincronizado do Exchange) | `readpst` (libpst) extrai mensagens para `.eml`/`mbox`; Autopsy também ingere `.pst` diretamente |
| **`.mbox`** | Múltiplas mensagens concatenadas em um único arquivo texto (padrão Unix/Thunderbird) | Autopsy ingere nativamente; ou dividir com scripts/`mboxgrep` |

**Exemplo prático — extraindo um `.pst` no Linux:**
```bash
readpst -o ./saida caixa_postal.pst
```

### 8.3 Correlação com SIEM/XDR

Assim como em [Network Forensics](Network%20Forensics.md), o valor de uma investigação de e-mail cresce quando correlacionada:
- IOCs extraídos do header/anexo (IP de origem, hash do anexo, domínio do link) → enriquecer em **VirusTotal/AbuseIPDB** e verificar se já apareceram em outros alertas do ambiente (ex.: Cortex XSIAM).
- Se o usuário clicou no link ou executou o anexo, cruzar com **logs de EDR do endpoint** para timeline completa (e-mail recebido → clique → execução → C2).
- Regras de detecção (Snort/Suricata "ET POLICY"/"ET CURRENT_EVENTS" vistas em [Network Forensics](Network%20Forensics.md)) frequentemente disparam justamente no momento em que o anexo malicioso já baixado tenta se comunicar — fechando o ciclo entre email forensics e network forensics.

### 8.4 Cadeia de custódia específica para email

- Preferir sempre exportar a mensagem **original em `.eml`** (preserva o header bruto) em vez de print/cópia do texto renderizado pelo cliente.
- Gerar hash (SHA-256) do `.eml` exportado imediatamente após a coleta.
- Documentar a fonte exata da exportação (qual caixa, qual administrador exportou, timestamp do servidor vs. timestamp local).

### 8.5 Cuidado com fuso horário nos headers `Received`

Cada servidor no caminho pode registrar o horário em seu **próprio fuso horário** (offset like `-0300`, `+0000` etc.). Ao montar a timeline do incidente, **normalize todos os timestamps para UTC** antes de comparar — comparar horários "brutos" de servidores em fusos diferentes é uma fonte comum de erro de investigação.

---

## 9. Metodologia de Investigação (Checklist)

> [!todo] Como usar
> Sequência sugerida para investigar um e-mail suspeito do zero até a conclusão. Adaptar conforme o tipo de ameaça já suspeitado (ex.: BEC foca mais em header/estilo; malware foca mais em anexo).

- [ ] Preservar a mensagem original em `.eml` + hash da evidência
- [ ] Ler o header **de baixo para cima** na cadeia `Received`
- [ ] Verificar `SPF` / `DKIM` / `DMARC` em `Authentication-Results`
- [ ] Comparar `From`, `Reply-To` e `Return-Path` — domínios devem bater
- [ ] Validar formato do `Message-ID` contra o domínio esperado
- [ ] Analisar o texto do corpo (tom, urgência, gramática, saudação)
- [ ] Passar o mouse em todos os links e comparar com o destino real
- [ ] Verificar `Content-Type`/HTML embutido em busca de script malicioso
- [ ] Rodar hash dos anexos contra VirusTotal
- [ ] Confirmar tipo real do arquivo (magic bytes) vs. extensão declarada
- [ ] Se necessário, detonar anexo em sandbox (Any.Run/Cuckoo) e observar rede/arquivo/registro
- [ ] Extrair IOCs (IP, domínio, hash, URL) e enriquecer com threat intel
- [ ] Cruzar com logs de EDR/SIEM se houve clique ou execução
- [ ] Normalizar timestamps para UTC e montar timeline final
- [ ] Documentar achados em relatório íntegro e imparcial

---

## 10. Cheatsheet de Referência Rápida

**Wireshark:**
```
smtp
```
Botão direito no pacote → Follow → TCP Stream

**Consulta de autenticação de domínio:**
```bash
dig txt dominio.com | grep spf
dig txt _dmarc.dominio.com
```

**Extração de arquivos de mailbox:**
```bash
readpst -o ./saida caixa_postal.pst      # .pst/.ost → .eml/mbox
msgconvert mensagem.msg                   # .msg → .eml
```

**Análise estática de anexo:**
```bash
file anexo_suspeito
sha256sum anexo_suspeito
strings anexo_suspeito | grep -Ei "http|cmd|powershell"
```

**Portas de referência rápida:**

| Protocolo | Sem TLS | Com TLS/SSL |
|---|---|---|
| SMTP (envio cliente) | 25 (relay) | 587 |
| IMAP | 143 (STARTTLS) | 993 |
| POP3 | 110 (STARTTLS) | 995 |

---

## Ver também
- [Network Forensics](Network%20Forensics.md)
- [Forense Digital em Windows](../Windows/Forense%20Digital%20em%20Windows.md)
- [DFIR em Linux](../Linux/DFIR%20em%20Linux.md)
- [Forense de Memória em Windows](../Windows/Forense%20de%20Memória%20em%20Windows.md)
- [Anti-Forense e Ofuscação de Dados](../Anti-Forense/Anti-Forense%20e%20Ofuscação%20de%20Dados.md)
