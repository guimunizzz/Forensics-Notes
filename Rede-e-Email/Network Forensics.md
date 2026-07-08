---
tags: [dfir, network-forensics, soc, blue-team]
area: Blue Team / DFIR
status: estudo-ativo
---

# Network Forensics

> [!info] Sobre esta nota
> Cobre a forense de rede de ponta a ponta: como capturar tráfego (Wireshark/TCPdump), como analisá-lo em busca de malware, insider threats e exfiltração, como detecção baseada em assinatura (Snort/Suricata/Zeek) e NetFlow encaixam nesse fluxo, e como lidar com tráfego criptografado (TLS/SSL). É a contraparte "rede" das notas de [Forense Digital em Windows](../Windows/Forense%20Digital%20em%20Windows.md), [DFIR em Linux](../Linux/DFIR%20em%20Linux.md), [Forense de Memória em Windows](../Windows/Forense%20de%20Memória%20em%20Windows.md) e [Forense de Memória em Linux](../Linux/Forense%20de%20Memória%20em%20Linux.md) — enquanto aquelas analisam um host isolado (disco/memória), esta nota olha para o que trafegou *entre* hosts, o que costuma ser o primeiro sinal de um incidente antes mesmo de se chegar ao endpoint.

## Sumário
1. [Introdução](#1-introdução)
2. [Princípios Fundamentais](#2-princípios-fundamentais)
3. [Ferramentas Principais](#3-ferramentas-principais)
4. [Captura de Tráfego](#4-captura-de-tráfego)
5. [Análise de Tráfego de Rede (NTA)](#5-análise-de-tráfego-de-rede-nta)
6. [Detecção Baseada em Assinaturas](#6-detecção-baseada-em-assinaturas)
7. [NetFlow-Based Network Forensics](#7-netflow-based-network-forensics)
8. [Análise de TLS/SSL](#8-análise-de-tlsssl)
9. [Tópicos Complementares](#9-tópicos-complementares)
10. [Metodologia de Investigação (Checklist)](#10-metodologia-de-investigação-checklist)
11. [Cheatsheet de Comandos e Filtros](#11-cheatsheet-de-comandos-e-filtros)

---

## 1. Introdução

**Network Forensics** é a subárea da forense digital que investiga, monitora e analisa tráfego de rede e dados de log para identificar violações de segurança ou de política. É usada para reconstruir a origem de ataques (DoS/DDoS, malware, insider threats, exfiltração de dados) e para gerar evidências que sustentem processos legais ou investigações internas.

Diferente da forense de disco/memória (que analisa um artefato estático), a forense de rede lida com **dados voláteis e em fluxo constante** — por isso a captura tempestiva (ao vivo ou via NetFlow/logs) é crítica: se o pacote não foi capturado, ele se perde.

> [!tip] Pré-requisitos
> Fundamentos de redes (modelo OSI/TCP-IP), protocolos (TCP, UDP, DNS, HTTP/HTTPS, ARP) e leitura básica de pacotes antes de aprofundar nesta nota.

---

## 2. Princípios Fundamentais

O ciclo de trabalho em network forensics segue quatro fases:

| Fase | Objetivo | Exemplo prático |
|---|---|---|
| **1. Coleta (Collection)** | Monitorar e registrar tráfego continuamente via sniffers, log servers ou ferramentas de monitoramento | SPAN port em um switch core capturando para um sensor Wireshark/Zeek |
| **2. Investigação** | Determinar tipo de incidente, timeline, sistemas afetados e dano potencial | Cruzar timestamps de conexão suspeita com logs de EDR do host |
| **3. Análise** | Aplicar ferramentas e técnicas para extrair evidências do dado bruto | Follow TCP Stream para reconstruir um upload malicioso |
| **4. Reporting** | Compilar achados em relatório íntegro e imparcial (pode virar peça em processo legal) | Relatório com hash do PCAP original, timeline e IOCs extraídos |

> [!warning] Integridade da evidência
> A integridade da evidência (hash do PCAP, cadeia de custódia) deve ser preservada desde a coleta — ver seção [9.1](#91-cadeia-de-custódia).

---

## 3. Ferramentas Principais

| Ferramenta | Tipo | Uso principal |
|---|---|---|
| **Wireshark** | Analisador de protocolo (GUI + CLI) | Captura e análise detalhada de pacotes, suporta centenas de protocolos |
| **TCPdump** | Captura via linha de comando | Captura leve em servidores Linux/Unix, ideal para gerar `.pcap` que depois é analisado no Wireshark |
| **Snort** | NIDS/NIPS baseado em assinatura | Detecção de ataques conhecidos via regras |
| **Suricata** | NIDS multi-thread, assinatura + anomalia | Alta performance em redes de alta velocidade |
| **Zeek (ex-Bro)** | Monitoramento avançado, assinatura + anomalia | Geração de logs estruturados (conn.log, dns.log, http.log) ideais para threat hunting |
| **NetworkMiner** | Análise passiva de tráfego | Extração de arquivos, sessões e usuários a partir de um PCAP, sem gerar tráfego próprio |

Cada ferramenta cobre uma etapa do fluxo de trabalho: **captura → detecção → análise profunda → extração de artefatos**.

---

## 4. Captura de Tráfego

### 4.1 Captura ao vivo e SPAN/Port Mirroring

Captura de tráfego é o processo de copiar os pacotes brutos que trafegam entre dispositivos. Para capturar em um único host, basta rodar a ferramenta localmente. Para capturar tráfego de **toda a rede**, é necessário direcionar o tráfego até o ponto de coleta usando **SPAN port (port mirroring)** em um switch gerenciável.

Dois cuidados essenciais na captura:
- **Filtering**: aplicar filtros de captura reduz ruído, economiza espaço e agiliza a análise.
- **Timestamping**: o timestamp de cada pacote é o que permite reconstruir a ordem cronológica dos eventos — fundamental para correlação com outras fontes (EDR, SIEM, logs de firewall).

### 4.2 Wireshark — Capture Filters x Display Filters

É comum confundir os dois tipos de filtro — eles têm sintaxes diferentes:

- **Capture Filter**: filtra o que é efetivamente capturado, usando sintaxe **BPF** (Berkeley Packet Filter), mais simples e limitada.
- **Display Filter**: filtra o que é **exibido** de um tráfego já capturado, usando a sintaxe rica do Wireshark.

**Exemplos de Capture Filter (BPF):**
```
host 192.168.1.1              # filtra por IP
port 80                       # filtra por porta
tcp                           # filtra por protocolo
src host 192.168.1.1 and dst port 80   # combinado
```

**Exemplos de Display Filter:**
```
ip.addr == 192.168.1.1
ip.src == 192.168.1.1
ip.dst == 192.168.1.1
tcp.port == 80 || udp.port == 53
dns
eth.src == 00:11:22:33:44:55
tcp.port == 443 && http                        # HTTPS
http.host == "www.example.com"
tcp.flags.syn == 1 && tcp.flags.ack == 0        # SYN scan / handshake início
tcp.stream eq 5                                 # isola um fluxo TCP específico
tcp.analysis.flags && !tcp.analysis.window_update   # anomalias TCP, exclui window updates
```

> [!tip] Prática recomendada
> Ao investigar um incidente, sempre gerenciar o tamanho dos arquivos de captura via *Capture → Options*, definindo rotação por contagem de pacotes, tamanho (KB) ou tempo — evita `.pcap` gigantes e inviáveis de transportar/analisar.

### 4.3 TCPdump na prática

Instalação:
```bash
# Debian/Ubuntu
apt install tcpdump

# RHEL
yum install tcpdump
```

Captura exige privilégio de root:
```bash
sudo tcpdump
```

Comandos essenciais:
```bash
tcpdump -i eth0                                        # captura na interface eth0
sudo tcpdump -i ens33 -w evidencia.pcap                 # salva em arquivo para analisar depois no Wireshark
tcpdump -i eth0 src 192.168.1.1                         # filtra por IP de origem
tcpdump -i eth0 dst 192.168.1.1                         # filtra por IP de destino
tcpdump -i eth0 port 80                                 # filtra por porta
tcpdump -i eth0 src 192.168.1.1 and dst 10.0.0.1         # fluxo entre dois IPs
tcpdump -i eth0 'tcp'                                    # apenas TCP
tcpdump -i eth0 net 192.168.1.0/24                       # toda a rede /24
tcpdump -i eth0 ether host 00:1A:2B:3C:4D:5E             # por MAC address
tcpdump -i eth0 'tcp[tcpflags] & (tcp-syn) != 0'         # pacotes com flag SYN (tentativas de conexão)
tcpdump -i eth0 udp port 53                              # consultas DNS
```
Parar a captura: `Ctrl+C`.

---

## 5. Análise de Tráfego de Rede (NTA)

**Network Traffic Analysis (NTA)** é o processo de coletar, examinar e interpretar o tráfego que passa pela rede. Não existe um padrão único e fechado — a interpretação correta depende do contexto do ambiente monitorado.

O que a NTA ajuda a detectar:
- Tentativas de acesso não autorizado
- Propagação de malware e exfiltração de dados via portas específicas
- Ameaças internas (insider threats)
- Ataques DoS/DDoS (picos anômalos de tráfego)
- ARP Spoofing

Pilares de uma boa análise: **filtragem, análise de protocolo, análise de sessão, análise comportamental e revisão pós-incidente**.

### 5.1 Detecção de Malware

Fluxo de trabalho no Wireshark:
1. Abrir o `.pcap` e ir em **Statistics → Protocol Hierarchy** para visão geral dos protocolos.
2. Interpretar os números:
   - Grande volume de **TCP** vs poucos pacotes **UDP** → tráfego majoritariamente orientado a conexão; UDP residual costuma ser DNS.
   - Presença de **DNS** pode indicar resolução para servidor de C2 (Command & Control).
   - Poucos pacotes de **VNC** já são suspeitos — indicam acesso remoto não autorizado.
   - Alto volume de **TLS** → tráfego criptografado, pode esconder atividade maliciosa (exige decriptação, ver seção 8).
   - Pacotes classificados apenas como **"Data"** (sem protocolo identificado) merecem investigação manual.
3. Ir em **Statistics → Conversations** para ver pares de IP, bytes trocados, duração e taxa de transferência.
   - Tráfego **assimétrico** (muito recebido, pouco enviado) → possível download malicioso ou exfiltração.
   - **Alta taxa de bits/s** em um sentido específico → possível upload/exfiltração de dados.
4. Criar filtros direcionados a IPs suspeitos, ex.:
   ```
   140.223.29.110 or tcp.dstport == 5500 and vnc
   ```
5. Investigar DNS suspeito:
   ```
   dns and dns.qry.name == "testmyids.com"
   ```
6. Usar **Follow → TCP Stream / UDP Stream** para reconstruir a conversa completa e visualizar comandos/dados trafegados pelo malware.

> [!warning] Limitação em tráfego SSL/TLS
> Não é possível filtrar o payload diretamente sem decriptação prévia (ver seção 8.2).

### 5.2 Detecção de Insider Threat

Ameaças internas geralmente violam padrões esperados de uso da rede. Passos de análise:

1. **Protocol Hierarchy** para identificar uso de protocolos que violam política corporativa (ex.: alto volume de DCE/RPC ou Microsoft Network Logon fora do esperado).
2. Buscar tráfego em **portas não padrão** ou protocolos inesperados.
3. Analisar atividade **fora do horário comercial** e em feriados — padrão clássico de insider threat.
4. Revisar protocolos de mensageria (**SMTP, IMAP**) — vetor comum de vazamento de dados.
5. Identificar conexões inesperadas de rede interna para redes externas, especialmente de alto volume.
6. Analisar consultas **DNS** repetidas ou suspeitas partindo de usuários internos.
7. **Detectar dispositivos não autorizados** comparando prefixos MAC conhecidos (ex.: só existem dispositivos Apple na rede, prefixo `98:CA:33`):
   ```
   (!(eth.src contains 98:CA:33) and arp) && !(eth.dst == ff:ff:ff:ff:ff:ff)
   ```
   Esse filtro exclui os dispositivos Apple legítimos e o broadcast ARP, sobrando só o que não deveria estar na rede.

### 5.3 Detecção de Transferência Anômala de Dados

1. Levantar estatísticas gerais (**Statistics → Protocol Hierarchy**): total de pacotes, IPs contatados, protocolos, distribuição.
2. Definir estratégia de filtragem para transferências grandes e inesperadas:
   ```
   ip.src == 192.168.0.1 && tcp.len > 1000
   ```
3. Analisar uso de protocolos antigos/inseguros pouco usuais na rede.
4. Usar **Conversations/Endpoints** para achar IPs enviando/recebendo volumes anômalos.
5. Comparar com o padrão normal de tráfego — picos súbitos, horários incomuns ou uso inesperado de porta/protocolo são sinais de alerta.
6. Usar **IO Graphs** para visualizar tendências ao longo do tempo e identificar picos anômalos visualmente.

---

## 6. Detecção Baseada em Assinaturas

**Signature-based Detection** identifica ameaças usando assinaturas conhecidas: hashes, IPs, URLs ou padrões de tráfego de malwares/exploits já catalogados. É rápida e eficaz contra ameaças conhecidas, mas **não detecta ataques 0-day**.

Categorias comuns cobertas por assinaturas:
- **Ataques de rede**: port scan, SQL Injection, XSS
- **Malware**: comunicação, infecção, atualização
- **Ransomware**: rotinas de criptografia e padrões de comunicação
- **Phishing**: URLs e conteúdo de e-mail maliciosos
- **Exploits**: ataques diretos a serviços/sistemas (ex.: Windows)

### 6.1 Snort

Instalação (Ubuntu 22.04):
```bash
apt install snort
snort -V                    # confere versão
curl testmyids.com          # gera tráfego de teste para validar alerta
```

Analisando um PCAP com Snort:
```bash
snort -r <pcap_file> -c <snort_config_file>
snort -r /tmp/2024-01-23-infection-traffic.pcap -c /etc/snort/snort.conf
```

Acompanhar alertas gerados:
```bash
tail -f /var/log/snort/alert.fast
```

### 6.2 Suricata e Zeek

- **Suricata**: combina assinatura e anomalia, arquitetura multi-thread — ideal para redes de alta velocidade.
- **Zeek (ex-Bro)**: além de assinatura/anomalia, gera **logs estruturados** (`conn.log`, `dns.log`, `http.log`, `files.log`) muito usados em threat hunting e integração com SIEM.

### 6.3 Anatomia de um Alerta Snort

```
12/10-05:32:16.929144 [**] [1:2014726:123] ET POLICY Outdated Flash Version M1 [**]
[Classification: Potential Corporate Privacy Violation] [Priority: 1]
{TCP} 172.16.2.139:49186 -> 23.218.156.83:80
```

| Campo | Significado |
|---|---|
| `12/10-05:32:16.929144` | Timestamp do evento |
| `[1:2014726:123]` | `1` = Generator ID · `2014726` = SID (Signature ID) · `123` = revisão da assinatura |
| `ET POLICY Outdated Flash Version M1` | Descrição da assinatura (categoria Emerging Threats POLICY) |
| `[Classification: ...]` | Classificação do alerta |
| `[Priority: 1]` | 1 = prioridade máxima |
| `{TCP} 172.16.2.139:49186 -> 23.218.156.83:80` | Protocolo, IP:porta origem → IP:porta destino |

Exemplos de alertas comuns e o que significam:

| Alerta | Interpretação |
|---|---|
| `ATTACK-RESPONSES 403 Forbidden` | Resposta de acesso negado — pode indicar tentativa de acesso não autorizado |
| `Possible Java Applet JNLP applet_ssv_validated in Base64` | Transferência de JNLP em Base64 — técnica usada para rodar applets Java maliciosos |
| `Terse alphanumeric executable downloader` | Downloader malicioso codificado, alta probabilidade de ser hostil |
| `Java EXE Download` / `PE EXE or DLL Windows file download HTTP` | Download de executável — potencial payload malicioso |
| `Outdated Flash Version M1` / `Vulnerable Java Version 1.6.x` | Uso de software desatualizado/vulnerável |

---

## 7. NetFlow-Based Network Forensics

**NetFlow** (protocolo da Cisco) coleta estatísticas de tráfego em roteadores/switches, registrando **fluxos** (flow) — sequências de pacotes entre um par de IP/porta/protocolo de origem e destino — sem armazenar o payload completo. É leve, escalável e ideal para redes grandes onde captura full-packet é inviável.

### 7.1 Campos coletados por Flow

- IP de origem e destino
- Porta de origem e destino (TCP/UDP)
- Protocolo IP
- Detalhes de interface
- Versão do IP
- Início/fim do fluxo, duração, bytes e pacotes transferidos, estado do fluxo

### 7.2 Casos de uso

- Detecção de aumento anômalo de volume de tráfego
- Detecção de vazamento de dados
- Detecção de acesso a sistemas privados
- Detecção de novos IPs na rede
- Detecção de sistemas acessados pela primeira vez

### 7.3 Exemplos práticos de análise

**Anomalia de protocolo/porta**: um gráfico de estatísticas mostrando picos de pacotes acima do baseline (ex.: média ultrapassando o limiar de 10 pacotes às 19h) já é gatilho de investigação. Ao aplicar um filtro DNS sobre esse pico, é possível identificar qual IP interno está gerando o maior volume de consultas — esse host se torna o alvo prioritário para investigação de endpoint.

**Anomalia de horário**: picos fora do horário comercial associados a uso intenso de **SMTP** podem indicar um host infectado enviando spam. Esse achado deve escalar para a fase de **Endpoint Forensics**.

**Resposta a incidentes com NetFlow**:
- *Traffic flow analysis*: entender quando e onde o incidente começou (ex.: identificar SSH tunelado por trás da porta 443 — sinal de evasão de controles de firewall baseados em porta).
- *Impact assessment*: dimensionar sistemas e dados afetados.
- *Attack vector identification*: apontar origem e método do ataque.

**Análise comportamental**:
- *Application usage*: identificar portas/protocolos usados por cada aplicação e sinalizar uso fora do padrão (ex.: FTP sendo usado quando é proibido por política).
- *User activity*: cruzar timestamps de atividade com horário de trabalho, acessos a recursos sensíveis e padrões de acesso anômalos — chave para insider threat também via NetFlow (não só via PCAP).

---

## 8. Análise de TLS/SSL

TLS/SSL são protocolos de criptografia para comunicação segura. Boa parte do tráfego malicioso moderno (C2, exfiltração) passa por canais criptografados — por isso a análise de TLS é essencial mesmo sem decriptar o payload.

### 8.1 Cipher Suites e Versões

- **Cipher suite**: identifica quais algoritmos de criptografia estão em uso. Cipher suites fracas indicam sistemas mal configurados ou software desatualizado.
- **Versão do protocolo**: versões antigas (SSLv2, SSLv3, TLS 1.0 inicial) possuem vulnerabilidades conhecidas.

No Wireshark, o filtro `tls` isola pacotes TLS, permitindo ver a versão negociada e detalhes do handshake nos detalhes do pacote.

### 8.2 Decriptando tráfego HTTPS

Para decriptar HTTPS no Wireshark são necessárias as chaves de sessão TLS, obtidas de duas formas:

**1. Variável de ambiente `SSLKEYLOGFILE`** (navegadores modernos escrevem as chaves de sessão em um arquivo):
```bash
# Linux/macOS
export SSLKEYLOGFILE=~/sslkeylog.log
```
```cmd
:: Windows
set SSLKEYLOGFILE=C:\sslkeylog.log
```
Depois, no Wireshark: **Edit → Preferences → Protocols → TLS → "Pre-Master-Secret log filename"** → apontar para o arquivo gerado.

**2. Chave privada do servidor** — só viável com acesso e privilégio adequados.

> [!danger] Cuidado
> Usar a chave privada do servidor para decriptar tráfego **não é recomendado fora de ambiente de teste** — expõe a chave e quebra a garantia de sigilo que o TLS deveria fornecer para todo o tráfego, não só o do incidente investigado.

Após configurar corretamente, o tráfego capturado passa a ser exibido em texto claro no Wireshark.

### 8.3 Anomalias em tráfego criptografado

- **Padrões de criptografia anômalos**: mudanças inesperadas no comportamento do tráfego cifrado — possível indício de exfiltração ou tráfego C2.
- **Volume anômalo de tráfego criptografado**: aumento repentino pode indicar atividade suspeita.
- **Falhas de handshake TLS**: handshakes frequentemente falhos ou inesperados podem indicar interferência ou atividade maliciosa (ex.: scanning, MITM, malware testando C2 com certificados inválidos).

---

## 9. Tópicos Complementares

> [!info] Sobre esta seção
> Assuntos que não vieram no material original, mas que fecham lacunas importantes para levar essa base do "sei analisar um PCAP" para "sei conduzir uma investigação de network forensics de ponta a ponta dentro de um SOC real" — cadeia de custódia, correlação com SIEM/XDR, threat intel e ATT&CK.

### 9.1 Cadeia de Custódia

Toda evidência de rede (PCAP, exports de NetFlow, logs) deve seguir cadeia de custódia formal para manter validade probatória:
- **Hash da evidência** no momento da coleta (SHA-256 do `.pcap`) e a cada transferência.
- **Registro de quem acessou, quando e por quê** (write-blocker conceitual: nunca analisar o arquivo original, sempre trabalhar em cópia).
- Documentar ferramenta, versão e configuração usadas na análise (reprodutibilidade).

### 9.2 Correlação com SIEM/XDR

Análise de PCAP isolada raramente conta a história completa. Na prática de SOC, o valor real vem de correlacionar:
- **IOCs extraídos do PCAP** (IPs, domínios, hashes de arquivos via NetworkMiner) → enriquecer no SIEM/XDR (ex.: Cortex XSIAM) para checar se o mesmo indicador aparece em outros hosts.
- **Logs de Zeek/Suricata** ingeridos no SIEM permitem threat hunting retroativo com XQL/KQL sem precisar reabrir o PCAP bruto.
- Timeline de rede + timeline de endpoint (EDR) + timeline de identidade (logon/AD) = reconstrução completa do incidente.

### 9.3 Threat Intel Enrichment

Depois de extrair IPs/domínios/hashes suspeitos:
- Consultar reputação em **VirusTotal, AbuseIPDB, Shodan, GreyNoise**.
- Verificar se o IP/domínio consta em feeds de C2 conhecidos (ex.: listas de Emerging Threats, MISP).
- Validar se a assinatura Snort/Suricata que disparou tem CVE ou campanha associada.

### 9.4 Mapeamento MITRE ATT&CK (rede)

Táticas frequentemente identificadas via network forensics:

| Tática ATT&CK | Exemplo de evidência de rede |
|---|---|
| **Command and Control (TA0011)** | Beaconing periódico para IP externo, DNS tunneling |
| **Exfiltration (TA0010)** | Tráfego assimétrico anômalo, upload volumoso fora de horário |
| **Lateral Movement (TA0008)** | SMB/RDP entre hosts internos fora do padrão |
| **Discovery (TA0007)** | Port scan interno, ARP sweep |
| **Initial Access (TA0001)** | Download de payload via HTTP, phishing com callback |

### 9.5 Formatos de arquivo

- **`.pcap`**: formato clássico, amplamente suportado.
- **`.pcapng`**: formato mais moderno (padrão atual do Wireshark), suporta metadados adicionais (comentários, múltiplas interfaces).
- Sempre verificar compatibilidade da ferramenta de análise com o formato antes de converter/perder metadados.

---

## 10. Metodologia de Investigação (Checklist)

> [!todo] Como usar
> Sequência sugerida para conduzir uma investigação de network forensics do zero até o relatório final. Nem todo incidente vai precisar de todos os itens — use como referência, não como fluxo rígido.

- [ ] Preservar a evidência original (hash + cópia de trabalho)
- [ ] Levantar contexto do incidente (quando foi detectado, por qual fonte)
- [ ] **Protocol Hierarchy** — visão geral dos protocolos em uso
- [ ] **Conversations/Endpoints** — identificar pares de IP com volume/duração anômalos
- [ ] Aplicar filtros direcionados por IP/porta/protocolo suspeito
- [ ] **Follow TCP/UDP Stream** nos fluxos suspeitos
- [ ] Checar tráfego DNS (consultas repetidas, domínios recém-gerados/DGA-like)
- [ ] Verificar handshakes TLS e cipher suites (decriptar se houver chave disponível)
- [ ] Rodar Snort/Suricata contra o PCAP para checagem rápida de assinaturas conhecidas
- [ ] Cruzar achados com NetFlow/logs de Zeek se disponíveis
- [ ] Extrair IOCs (IP, domínio, hash) e enriquecer com threat intel
- [ ] Mapear achados no MITRE ATT&CK
- [ ] Correlacionar com endpoint (EDR) e identidade (AD/logon)
- [ ] Documentar timeline e compilar relatório final

---

## 11. Cheatsheet de Comandos e Filtros

**Wireshark — Display Filters úteis:**
```
ip.addr == x.x.x.x
tcp.port == x || udp.port == x
tls
dns and dns.qry.name == "dominio.com"
http.request
tcp.analysis.retransmission
tcp.flags.syn == 1 && tcp.flags.ack == 0
frame contains "string_suspeita"
```

**TCPdump:**
```bash
sudo tcpdump -i <iface> -w captura.pcap
tcpdump -i <iface> host <ip>
tcpdump -i <iface> port <porta>
tcpdump -i <iface> net <cidr>
```

**Snort:**
```bash
snort -r arquivo.pcap -c snort.conf
tail -f /var/log/snort/alert.fast
```

---

## Ver também
- [Email Forensics](Email%20Forensics.md)
- [Forense Digital em Windows](../Windows/Forense%20Digital%20em%20Windows.md)
- [DFIR em Linux](../Linux/DFIR%20em%20Linux.md)
- [Forense de Memória em Windows](../Windows/Forense%20de%20Memória%20em%20Windows.md)
- [Forense de Memória em Linux](../Linux/Forense%20de%20Memória%20em%20Linux.md)
- [Anti-Forense e Ofuscação de Dados](../Anti-Forense/Anti-Forense%20e%20Ofuscação%20de%20Dados.md)
