---
tags: [forense-digital, dfir, windows, aquisicao-dados, memoria-forense, disk-imaging, sysinternals]
area: Blue Team / DFIR
status: estudo-ativo
---

# Forense Digital em Windows: Aquisição e Duplicação de Dados

> [!info] Sobre esta nota
> Consolida os conceitos, ferramentas e procedimentos práticos para **coleta e preservação de evidências digitais** em sistemas Windows. É a base de qualquer processo de DFIR (Digital Forensics and Incident Response) — sem uma aquisição correta, toda a análise posterior (Volatility3, MemProcFS, Sleuth Kit, etc.) fica comprometida.

---

## 1. Fundamentos antes de tocar em qualquer evidência

### 1.1 A Ordem de Volatilidade (RFC 3227)

Antes de decidir *o que* coletar primeiro, é preciso entender que nem todo dado "dura" o mesmo tempo. A RFC 3227 define uma ordem de prioridade — do mais volátil (desaparece primeiro) ao menos volátil:

| Ordem | Fonte de dado | Tempo de vida aproximado |
|---|---|---|
| 1 | Registradores da CPU e cache | Nanossegundos |
| 2 | Tabela de roteamento, cache ARP, tabela de processos, RAM | Segundos a minutos |
| 3 | Estado do sistema (arquivos temporários, swap/pagefile) | Minutos |
| 4 | Disco rígido (dados em repouso) | Relativamente estável |
| 5 | Mídias de backup remotas/impressas | Dias a anos |

> [!tip] Regra prática
> Sempre colete **da RAM para o disco**, nunca o contrário. Se você desligar a máquina antes de tirar a memória, perde para sempre processos em execução, conexões de rede ativas, chaves de criptografia e até malware fileless que só existe em memória.

### 1.2 Cadeia de Custódia (Chain of Custody)

Toda evidência coletada precisa de rastreabilidade documentada, ou ela perde valor probatório (inclusive em contexto corporativo/jurídico). Um registro mínimo de cadeia de custódia deve conter:

- **O quê**: descrição do item (ex: "imagem de memória RAM — HOST01")
- **Quem**: nome/matrícula de quem coletou
- **Quando**: data e hora exata (com timezone) da coleta
- **Onde**: local físico/lógico da coleta
- **Como**: ferramenta e método utilizados
- **Hash**: valor SHA256 no momento da coleta
- **Transferências**: cada vez que a evidência muda de mãos ou de storage, registrar novamente

> [!warning] Regra de ouro da forense
> **NUNCA analise a evidência original.** Toda análise é feita em cópias. Qualquer escrita acidental no original (mesmo montar um disco sem write blocker) pode invalidar a evidência.

---

## 2. Live Data Acquisition (Aquisição em Tempo Real)

Objetivo: capturar dados **voláteis** de um sistema ainda ligado, sem gerar downtime desnecessário em sistemas críticos.

### 2.1 O que coletar

| Alvo | Por que importa | Localização típica |
|---|---|---|
| Memória RAM | Processos ativos, senhas em claro, chaves de criptografia, malware fileless | N/A (é a própria RAM) |
| Conexões de rede ativas | Identifica comunicação com C2 | `netstat -ano`, TCPView |
| Event Logs | Trilha de autenticação, execução, erros | `%SystemRoot%\System32\winevt\Logs\` |
| Logs de serviço fora do Event Viewer | DNS, DHCP, IIS gravam fora do padrão .evtx | `%SystemRoot%\System32\Dns\Dns.log`, `%SystemRoot%\System32\dhcp\DhcpSrv.log` |
| Arquivos temporários | Payloads descompactados por malware | `%SystemRoot%\Temp`, `%UserProfile%\AppData\Local\Temp` |
| Registro do Windows | Persistência, histórico de execução, dispositivos conectados | Hives em `%SystemRoot%\System32\config\` e `NTUSER.DAT` por usuário |
| Prefetch | Evidência de execução de binários (mesmo já deletados) | `%SystemRoot%\Prefetch\*.pf` |
| Arquivos abertos/handles | O que o processo suspeito está tocando agora | Process Explorer |

### 2.2 Captura de Memória RAM — Ferramentas

| Ferramenta | Tipo | Observação |
|---|---|---|
| **WinPmem** | CLI, open-source | Leve, não exige instalação, ideal para não "sujar" o disco com artefatos |
| **FTK Imager** | GUI | `File > Capture Memory`, gera relatório junto |
| **Magnet RAM Capture** | GUI, gratuita | Interface simples, boa para quem está começando |
| **Belkasoft RAM Capturer** | CLI/GUI | Foco em contornar proteções anti-dump de alguns processos |
| **DumpIt (Comae)** | CLI, um clique | Gera `.dmp` compatível com WinDbg e Volatility |

#### Exemplo prático — WinPmem

```powershell
# Executar o PowerShell como Administrador na pasta da ferramenta
.\Winpmem_mini_x64_rc2.exe memdump.raw
```

Isso gera `memdump.raw` com o dump completo da RAM. Passo seguinte (fora do escopo desta nota, mas para referência futura): esse arquivo é o input direto para análise com **Volatility3** (`vol.py -f memdump.raw windows.pslist`) ou **MemProcFS** (que monta a memória como um sistema de arquivos virtual).

> [!example] Checklist rápido de aquisição de RAM
> 1. Identificar espaço em disco suficiente no destino (idealmente disco externo, não o disco do sistema investigado)
> 2. Rodar a ferramenta de captura com privilégio de Administrador
> 3. Gerar hash SHA256 do arquivo IMEDIATAMENTE após a captura
> 4. Documentar hora exata de início e fim da captura
> 5. Copiar o arquivo para local seguro e recalcular hash para confirmar integridade

### 2.3 Captura de Tráfego de Rede Ativo

Antes de isolar a máquina, capturar o estado das conexões:

```powershell
netstat -ano > conexoes_ativas.txt
```

O `-a` lista todas as conexões, `-n` evita resolução de DNS (mais rápido e não gera ruído na rede), e `-o` mostra o PID do processo dono da conexão — essencial para depois cruzar com o Process Explorer e achar o processo malicioso.

Para captura de pacotes em tempo real (quando há tempo/necessidade), `tshark` ou Wireshark:

```powershell
tshark -i "Ethernet" -w captura_incidente.pcap
```

### 2.4 Event Logs — Aprofundando

Os logs mais relevantes para uma investigação forense em Windows:

| Log | Caminho | Eventos-chave |
|---|---|---|
| Security | `Security.evtx` | 4624 (logon), 4625 (logon falho), 4688 (criação de processo), 4720 (criação de usuário) |
| System | `System.evtx` | Inicialização/desligamento, instalação de serviços, drivers |
| Application | `Application.evtx` | Erros de aplicações, crashes |
| PowerShell Operational | `Microsoft-Windows-PowerShell%4Operational.evtx` | 4104 (script block logging — captura o conteúdo de scripts executados) |
| Sysmon (se instalado) | `Microsoft-Windows-Sysmon%4Operational.evtx` | Criação de processo com hash, conexões de rede, criação de arquivo, alterações de registro |

Exportar rapidamente um log via linha de comando (útil quando o Event Viewer gráfico não está disponível ou se quer automatizar):

```powershell
wevtutil epl Security C:\Evidencias\Security.evtx
```

> [!warning] Por que copiar rápido?
> O Windows sobrescreve entradas antigas quando o log atinge o tamanho máximo configurado (log circular). Em máquinas com muita atividade, um log de Security pode "girar" em poucas horas — copie antes de qualquer outra ação.

### 2.5 Registro do Windows (Registry) — Artefatos Forenses Relevantes

O Registro guarda muito mais que configurações — é uma das fontes mais ricas de evidência de atividade do usuário e de persistência de malware.

| Hive | Localização no disco | O que revela |
|---|---|---|
| `SYSTEM` | `%SystemRoot%\System32\config\SYSTEM` | Configuração de serviços, drivers, ControlSet |
| `SOFTWARE` | `%SystemRoot%\System32\config\SOFTWARE` | Programas instalados, versão do SO |
| `SAM` | `%SystemRoot%\System32\config\SAM` | Contas de usuário locais (hashes de senha) |
| `SECURITY` | `%SystemRoot%\System32\config\SECURITY` | Políticas de segurança, LSA secrets |
| `NTUSER.DAT` | `%UserProfile%\NTUSER.DAT` | Perfil individual do usuário (por conta) |

Artefatos clássicos dentro dessas hives que todo investigador deve conhecer:

- **UserAssist** (`NTUSER.DAT\...\UserAssist`): registra programas executados via Explorer, com contagem e timestamp — ótimo para provar "o usuário clicou nisso".
- **ShimCache / AppCompatCache** (`SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`): lista executáveis que rodaram no sistema, mesmo que já tenham sido apagados.
- **Amcache.hve** (`%SystemRoot%\AppCompat\Programs\Amcache.hve`): similar ao ShimCache, mas guarda também hash SHA1 do binário — excelente para correlacionar com VirusTotal.
- **RunMRU / TypedPaths**: comandos digitados na caixa "Executar" e caminhos digitados no Explorer.
- **Run / RunOnce keys**: locais clássicos de persistência (`HKLM\...\Run`, `HKCU\...\Run`).

Exportar manualmente uma chave específica:

```powershell
reg export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" run_key_export.reg
```

---

## 3. Dynamic Acquisition (Aquisição Dinâmica) — Monitorando Comportamento

Enquanto a Live Acquisition "tira uma foto", a Aquisição Dinâmica observa o sistema **em movimento** — essencial quando o comportamento suspeito ainda está ocorrendo.

### 3.1 Suite Sysinternals — o canivete suíço do investigador

| Ferramenta                    | Função forense                                                                                                                                                                                                                                                                                       |
| ----------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Process Explorer**          | Substitui o Gerenciador de Tarefas. Botão direito → *Properties* mostra aba **TCP/IP** (para onde o processo se conecta), aba **Strings** (extrai texto legível da memória do processo — útil para achar scripts ou IOCs escondidos), aba **Image** (caminho do binário + hash direto no VirusTotal) |
| **Process Monitor (procmon)** | Grava em tempo real todo acesso a arquivo, registro e rede feito por processos — permite reconstruir exatamente o que um malware fez, passo a passo                                                                                                                                                  |
| **Autoruns**                  | Vasculha TODOS os pontos de persistência: Registro, pastas de inicialização, tarefas agendadas, serviços, drivers, extensões de navegador. `File > Save` preserva o estado para análise posterior/comparação                                                                                         |
| **TCPView**                   | Visão gráfica em tempo real de conexões TCP/UDP, similar ao netstat mas com atualização ao vivo                                                                                                                                                                                                      |
| **Sysmon**                    | Não é reativo — precisa estar instalado ANTES do incidente. Gera logs detalhados de criação de processo (com hash), conexão de rede, criação/alteração de arquivo e registro. Se já estiver rodando no ambiente, é uma das melhores fontes de timeline                                               |

> [!example] Cenário prático — caçando persistência
> 1. Abrir o Autoruns como Administrador
> 2. Filtrar por `Options > Hide Microsoft Entries` para reduzir ruído
> 3. Procurar entradas sem assinatura digital (coluna *Publisher* em branco ou "Not verified")
> 4. Clicar com o botão direito na entrada suspeita → *Check VirusTotal* (o Autoruns calcula o hash e consulta automaticamente)
> 5. `File > Save` para documentar o estado encontrado antes de qualquer remediação

### 3.2 Regedit para exportação pontual

Quando já se sabe exatamente qual chave investigar (por exemplo, indicada pelo Autoruns):

```
regedit.exe → File → Export → salvar como .reg
```

Isso preserva a chave (e subchaves) como evidência antes de qualquer alteração/remoção.

---

## 4. Copy and Duplicate (Cópia e Duplicação Forense)

> [!danger] Regra de ouro (repetindo porque é a mais importante da forense)
> **NUNCA realize análises nos dados originais.** Qualquer alteração — mesmo um simples "abrir o arquivo" em alguns casos — pode invalidar a evidência. Trabalhe sempre com cópias forenses validadas por hash.

### 4.1 Write Blockers

Antes de conectar um disco físico original a uma estação de análise, use um **write blocker** (hardware ou software) — ele impede fisicamente/logicamente qualquer escrita no disco de origem, garantindo que a mera conexão não altere timestamps ou metadados.

### 4.2 Métodos de Cópia

| Método | O que faz | Quando usar |
|---|---|---|
| **Bit-Level Copy** (imagem física) | Clona byte a byte, incluindo espaço não alocado e partições ocultas | Investigações completas, recuperação de arquivos deletados |
| **Selective/Logical Copy** | Copia apenas arquivos/pastas específicas | Triagem rápida, coleta remota, quando não há tempo/espaço para imagem completa |

### 4.3 Formatos de Imagem Forense

| Formato | Descrição | Uso prático |
|---|---|---|
| **RAW (dd)** | Cópia bruta, sem compressão nem metadados (`.img`/`.bin`) | Máxima compatibilidade — lido por qualquer ferramenta forense |
| **SMART** | Formato proprietário | Guarda a imagem junto com metadados da investigação |
| **E01 (EnCase)** | Padrão de indústria | Suporta compressão, hash embutido (verificação de integridade nativa) e proteção por senha |
| **AFF** (Advanced Forensic Format) | Open source, muito flexível | Suporta compressão extrema e criptografia |

#### Exemplo — FTK Imager (GUI)

1. `File > Create Disk Image`
2. Selecionar a fonte (disco físico ou lógico)
3. Escolher o formato de destino (geralmente E01 para casos formais, RAW para máxima portabilidade)
4. Preencher os campos de metadados do caso (examinador, número do caso, notas)
5. FTK Imager calcula automaticamente MD5 e SHA1 da imagem gerada e verifica ao final

#### Exemplo — `dd` em ambiente Linux de boot forense (ex: live USB)

```bash
# Origem: disco físico identificado como /dev/sdb
# Destino: imagem RAW em disco de evidências montado em /mnt/evidencias
dd if=/dev/sdb of=/mnt/evidencias/caso01_disco.img bs=4M conv=noerror,sync status=progress
```

- `bs=4M`: tamanho do bloco (afeta velocidade)
- `conv=noerror,sync`: continua mesmo se encontrar setores com erro de leitura, preenchendo com zeros para manter o alinhamento da imagem

---

## 5. Garantia de Integridade (Hashing)

Depois de qualquer aquisição — RAM, disco, logs — o passo final é sempre o mesmo: **gerar o hash e documentar**.

```powershell
certutil -hashfile C:\Evidencias\memdump.raw SHA256
```

| Algoritmo | Uso recomendado |
|---|---|
| MD5 | Rápido, ainda usado para comparação legada, mas vulnerável a colisões — não usar sozinho em casos críticos |
| SHA1 | Melhor que MD5, mas também com colisões conhecidas |
| **SHA256** | Padrão atual recomendado para evidência forense |

> [!tip] Verificação de integridade
> Sempre que a evidência for movida (troca de disco, upload para storage do caso, etc.), recalcule o hash. Se o valor mudar, a cadeia de custódia foi quebrada — e isso precisa ser documentado, não escondido.

---

## 6. Próximos Passos (fora do escopo de aquisição, mas conectados)

A aquisição é só o começo. Uma vez com a evidência coletada e íntegra, o fluxo natural de investigação segue para:

- **Análise de memória**: Volatility3 (`pslist`, `netscan`, `malfind`), MemProcFS (monta o dump como filesystem navegável)
- **Análise de disco**: Sleuth Kit / Autopsy para reconstrução de timeline e recuperação de arquivos
- **Timeline forense**: plaso/log2timeline para correlacionar todos os artefatos coletados em uma linha do tempo única
- **Análise de metadados específicos**: exiftool para artefatos como imagens (GPS, dispositivo de origem)

---

## 7. Checklist Geral de Aquisição (ordem recomendada)

1. [ ] Documentar hora de chegada e estado inicial do sistema (ligado/desligado, tela, processos visíveis)
2. [ ] Capturar memória RAM (WinPmem/FTK Imager)
3. [ ] Capturar conexões de rede ativas (`netstat -ano`, TCPView)
4. [ ] Copiar Event Logs relevantes (Security, System, PowerShell Operational, Sysmon)
5. [ ] Copiar hives de Registro (SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER.DAT)
6. [ ] Copiar Prefetch e arquivos temporários
7. [ ] Rodar Autoruns e salvar estado de persistência
8. [ ] Gerar hash SHA256 de cada item coletado, documentar na cadeia de custódia
9. [ ] Se necessário, realizar imagem de disco completa com write blocker
10. [ ] Transferir tudo para storage de evidências e revalidar hashes

---

## 8. Referências para Aprofundamento

- RFC 3227 — *Guidelines for Evidence Collection and Archiving*
- SANS FOR500 (Windows Forensic Analysis) e FOR508 (Advanced Incident Response)
- Documentação oficial do Sysinternals Suite (Microsoft)
- Volatility3 Docs / MemProcFS Docs
- Plataformas de prática: BTLO, CyberDefenders

---

## Ver também
- [Forense de Memória em Windows](Forense%20de%20Memória%20em%20Windows.md)
- [DFIR em Linux](../Linux/DFIR%20em%20Linux.md)
- [Arquitetura de Computadores para Forense Digital](../Fundamentos/Arquitetura%20de%20Computadores%20para%20Forense%20Digital.md)
- [Anti-Forense e Ofuscação de Dados](../Anti-Forense/Anti-Forense%20e%20Ofuscação%20de%20Dados.md)
- [DFIR com EDR](../Deteccao-e-Resposta/DFIR%20com%20EDR.md)
- [Cyber Kill Chain](../Threat-Intel/Cyber%20Kill%20Chain.md)
- [MITRE ATT&CK](../Threat-Intel/MITRE%20ATT&CK.md)
