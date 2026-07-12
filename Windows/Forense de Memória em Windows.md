---
tags: [dfir, windows, memory-forensics, volatility3, ftk-imager, blue-team]
area: Blue Team / DFIR
status: estudo-ativo
---

# Forense de Memória em Windows (FTK Imager + Volatility3)

> [!info] Sobre esta nota
> Par da nota [Forense de Memória em Linux](../Linux/Forense%20de%20Memória%20em%20Linux.md) — mesma lógica de investigação (Volatility3), artefatos e ferramentas completamente diferentes por conta do próprio SO. Cobre captura com **FTK Imager** e análise com **Volatility3**, do zero até um fluxo de investigação completo em Windows.

---

## 1. Por que Forense de Memória em Windows Importa

A memória RAM guarda o estado vivo de um sistema Windows: processos em execução, DLLs carregadas, chaves de registro em cache, conexões de rede ativas, hashes de senha em cache, e muitas vezes malware que **nunca grava nada em disco** (fileless malware, técnicas de process injection).

**Casos de uso principais:**

- Extração de chaves de criptografia da memória
- Coleta de informações de sessões e transações do usuário
- Detecção de malware residente apenas em memória
- Análise de causa raiz de crashes de sistema
- Resposta a incidentes — reconstruir exatamente o que rodou durante o comprometimento

> [!warning] Janela de oportunidade
> Assim como no Linux, a memória é o dado mais volátil (ver ordem de volatilidade na nota de aquisição Windows). Reiniciar o sistema antes da captura destrói tudo isso permanentemente.

---

## 2. Ferramentas do Ecossistema

### 2.1 Captura (dump da memória)

| Ferramenta | Observação |
|---|---|
| **FTK Imager** | Padrão de indústria — `File > Capture Memory`, verifica integridade via MD5/SHA1 nativamente |
| **WinDbg** | Debugger da Microsoft — foco em análise de crash dumps, mas também abre memória de sistemas vivos |
| **Magnet RAM Capture** | Interface simples, captura rápida — boa opção para quem está começando |
| **Belkasoft Evidence Center** | Plataforma completa de forense digital, também cobre memória |
| **Rekall** | Fork avançado do Volatility, conhecido por análises mais sofisticadas |
| **MemDump** | Ferramenta de linha de comando simples, dump raw direto |

### 2.2 Análise

| Ferramenta | Observação |
|---|---|
| **Volatility3** | Framework open-source mais usado — mesma base conceitual do lado Linux, plugins específicos para Windows |
| **Rekall** | Alternativa avançada ao Volatility |
| **Belkasoft Evidence Center** | Além de captura, também analisa histórico de internet, atividade em redes sociais e outros artefatos digitais junto com o dump |

---

## 3. Capturando a Memória com FTK Imager

### 3.1 Passo a passo

1. Abrir o FTK Imager
2. `File > Capture Memory`
3. Especificar caminho e nome do arquivo de imagem de memória
4. Clicar em **Capture Memory**

### 3.2 Opção "Include Pagefile"

Quando a RAM física não é suficiente, o Windows usa um arquivo em disco (`C:\pagefile.sys`) como memória virtual. Se você marcar **Include Pagefile**, o FTK Imager inclui essa área na captura também.

> [!tip] Quando incluir o pagefile
> Inclua sempre que possível — dados que foram "descartados" da RAM física por falta de espaço podem ter sido movidos para o pagefile, e isso pode conter informação relevante (inclusive fragmentos de processos que já não estão mais ativos na RAM em si).

### 3.3 Verificação de integridade

O FTK Imager já calcula MD5/SHA1 nativamente durante a captura. Se quiser conferir manualmente depois:

```powershell
CertUtil -hashfile .\memdump.mem MD5
CertUtil -hashfile .\memdump.mem SHA256
```

---

## 4. Instalando o Volatility3 no Windows

Requer Python 3+.

```powershell
# Confirmar versão do Python instalada
python --version

# Instalar o módulo "snappy" (dependência de compressão)
pip install .\python_snappy-0.7.1-py3-none-any.whl

# Baixar o Volatility3 (repositório oficial)
# https://github.com/volatilityfoundation/volatility3

# Instalar as dependências listadas no requirements.txt do Volatility
pip install -r .\requirements.txt

# Confirmar que a instalação funcionou
python.exe .\vol.py -h
```

---

## 5. Arquitetura do Volatility3 (revisão rápida)

Os mesmos três conceitos centrais da versão Linux se aplicam aqui — Volatility3 é o mesmo framework, apenas com plugins diferentes por SO:

| Componente | O que é |
|---|---|
| **Memory Layers** | Abstrações das diferentes camadas de memória (física, virtual, sistema de arquivos) |
| **Templates & Objects** | Templates definem estruturas de dados em memória; Objects são instâncias concretas encontradas na análise |
| **Symbol Tables** | Endereços e layouts de estruturas do kernel e componentes do sistema, permitindo interpretar corretamente o que está na memória |

> [!tip] Diferença prática Windows vs Linux no Volatility3
> No Windows, os símbolos (equivalente ao ISF do Linux) já vêm embutidos/baixados automaticamente pelo Volatility3 na maioria dos casos, sem o processo manual de `dwarf2json` que vimos na nota de Linux — a Microsoft publica os PDBs de símbolos publicamente e o Volatility já sabe buscá-los.

---

## 6. Fluxo Completo de Análise de Memória

```mermaid
flowchart LR
    A[1. Identificação da Imagem] --> B[2. Processos e Threads]
    B --> C[3. Conexões de Rede]
    C --> D[4. Análise de Registro]
    D --> E[5. Análise de Arquivos]
    E --> F[6. Análise de Malware]
    F --> G[7. Análise de Serviços]
    G --> H[8. Conclusões e Relatório]
```

### 6.1 Identificação da Imagem

```powershell
# Informações de SO, versão e build a partir do dump
python.exe .\vol.py -f memdump.mem windows.info

# Hash do dump antes de qualquer análise
CertUtil -hashfile .\memdump.mem MD5

# Ver plugins Windows disponíveis na sua instalação
python vol.py --help | findstr windows.

# Ver ajuda detalhada de um plugin específico
python vol.py windows.pslist.PsList -h
```

### 6.2 Processos e Threads

```powershell
# Lista de processos ativos
python.exe .\vol.py -f memdump.mem windows.pslist

# Árvore de processos (relação pai/filho)
python.exe .\vol.py -f memdump.mem windows.pstree

# Varredura profunda — pega processos escondidos/terminados mas com rastro em memória
python.exe .\vol.py -f memdump.mem windows.psscan

# Argumentos de linha de comando usados para iniciar cada processo
python.exe .\vol.py -f memdump.mem windows.cmdline

# DLLs carregadas por cada processo
python.exe .\vol.py -f memdump.mem windows.dlllist
```

**Campos-chave do `windows.pslist`:**

| Campo | Significado |
|---|---|
| PID | Identificador único do processo |
| PPID | PID do processo pai |
| ImageFileName | Nome do processo |
| Offset(V) | Endereço virtual do processo na memória |
| Threads | Número de threads do processo |
| Handles | Referências a recursos do sistema (arquivos abertos, chaves de registro, conexões) |
| Session | Número da sessão à qual o processo pertence |
| Wow64 | Indica se é um processo 32-bit rodando em subsistema WoW64 de um SO 64-bit |
| CreatedTime / ExitTime | Quando o processo foi criado / finalizado (`N/A` se ainda ativo) |

> [!example] `pslist` vs `psscan` — igual ao Linux
> `pslist`/`pstree` seguem as listas ligadas do kernel — um rootkit ou técnica de DKOM (Direct Kernel Object Manipulation) pode desvincular um processo dessas listas para escondê-lo. `psscan` varre a memória física procurando estruturas de processo diretamente, então **encontra processos escondidos** que não aparecem no `pslist`. Sempre rode os dois e compare as diferenças.

### 6.3 Conexões de Rede

```powershell
python.exe .\vol.py -f memdump.mem windows.netscan

# Filtrar por IP específico
python.exe .\vol.py -f memdump.mem windows.netscan | findstr "172.16.8.132"
```

**Campos-chave:**

| Campo | Significado |
|---|---|
| Offset | Endereço hexadecimal do objeto de conexão na memória |
| Protocol | Protocolo em uso (TCPv4, UDPv4, etc.) |
| LocalAddr / LocalPort | Endereço/porta local |
| ForeignAddr / ForeignPort | Endereço/porta remoto |
| State | Estado da conexão (`ESTABLISHED`, `LISTENING`, etc.) |
| PID / Owner | Processo (PID e nome) dono da conexão |
| Created | Data/hora de criação da conexão |

> [!tip] Cruzamento com processos
> Ache o PID de uma conexão suspeita em `netscan` e cruze com `pslist`/`cmdline` para saber exatamente qual binário (e com quais argumentos) está se comunicando com aquele IP/porta.

### 6.4 Análise de Registro

O registro é uma das fontes mais ricas de artefatos em memória — malware e atividade do usuário deixam trilhas extensas aqui.

```powershell
# Lista as hives de registro carregadas em memória
python.exe .\vol.py -f memdump.mem windows.registry.hivelist

# Varredura da estrutura de registro em memória — encontra hives ocultas/não listadas
python.exe .\vol.py -f memdump.mem windows.registry.hivescan
```

> [!warning] Por que `hivescan` importa
> Se malware ou o próprio usuário tentar apagar seus rastros, isso pode deixar hives parcialmente apagadas ou não visíveis pelas técnicas padrão de listagem — `hivescan` encontra o que `hivelist` sozinho não pegaria. Isso conecta diretamente com a nota [Anti-Forense e Ofuscação de Dados](../Anti-Forense/Anti-Forense%20e%20Ofuscação%20de%20Dados.md), especificamente a seção de artifact wiping.

**Chaves de registro que merecem checagem prioritária:**

| Chave | O que revela |
|---|---|
| `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` / `HKCU\...\Run` | Programas que iniciam automaticamente no logon/boot — clássico ponto de persistência |
| `HKLM\System\CurrentControlSet\Services` | Serviços e drivers do sistema — serviços maliciosos costumam se esconder aqui |
| `HKLM\Software\Microsoft\Windows\CurrentVersion\Shell Extensions` | Extensões adicionadas ao shell do Windows |
| `HKLM\System\MountedDevices` | Dispositivos montados no sistema |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist` | Programas executados pelo usuário — útil para reconstruir atividade |

### 6.5 Análise de Arquivos

```powershell
python.exe .\vol.py -f memdump.mem windows.filescan
```

Lista objetos de arquivo gerenciados pelo SO com endereço em memória, nome, e metadados associados — inclusive arquivos **deletados ou ocultos** que ainda têm rastro em memória, com informação de criação/modificação/acesso e localização.

### 6.6 Análise de Malware

```powershell
# Procura regiões de memória com características de código malicioso injetado
python.exe .\vol.py -f memdump.mem windows.malfind

# Varredura com regras YARA customizadas
python.exe .\vol.py -f memdump.mem yarascan.YaraScan --yara-file .\yara\search_mimikatz.yar
```

`windows.malfind` procura por padrões característicos de **process injection** (regiões de memória executáveis sem um arquivo mapeado correspondente em disco — sinal clássico de código injetado).

> [!example] Exemplo de regra YARA (busca por Mimikatz)
> Uma regra customizada como `search_mimikatz.yar` procura strings/padrões característicos da ferramenta Mimikatz (extração de credenciais) na memória — útil quando há suspeita de dumping de credenciais no sistema.

### 6.7 Análise de Serviços

Serviços Windows rodam em background e são um alvo clássico de disfarce — malware pode se passar por um serviço legítimo ou modificar um existente.

```powershell
python.exe .\vol.py -f memdump.mem windows.svcscan
```

**Campos-chave:**

| Campo | Significado |
|---|---|
| Offset | Endereço do serviço no registro/memória |
| Order | Ordem de inicialização do serviço |
| PID | PID do serviço (`N/A` se sem processo próprio ou rodando como parte de um processo de sistema) |
| Start | Tipo de início — `SERVICE_DEMAND_START` (manual) ou `SERVICE_SYSTEM_START` (automático no boot) |
| State | Estado atual — `SERVICE_STOPPED` ou `SERVICE_RUNNING` |
| Type | Categoria — `SERVICE_KERNEL_DRIVER`, `SERVICE_FILE_SYSTEM_DRIVER`, `SERVICE_WIN32_SHARE_PROCESS` |
| Name / Display | Nome interno / nome apresentado nas interfaces de gerenciamento |
| Binary | Caminho do executável do serviço |

**Sinais de serviço anômalo — checklist de anomalias:**

1. [ ] Serviço que deveria ser `SERVICE_SYSTEM_START` aparecendo como `SERVICE_DEMAND_START` (ou vice-versa) sem explicação
2. [ ] Serviço de segurança parado inesperadamente (`SERVICE_STOPPED`)
3. [ ] Tipo de serviço crítico (`SERVICE_KERNEL_DRIVER`, `SERVICE_FILE_SYSTEM_DRIVER`) com nome ou configuração fora do padrão
4. [ ] Nome de serviço parecido mas sutilmente diferente de um legítimo (ex: `Netmaan` em vez de `Netman`) — técnica clássica de disfarce
5. [ ] Caminho do binário fora dos diretórios padrão do sistema (ex: em `%TEMP%` em vez de `C:\Windows\System32`)
6. [ ] Comparação contra uma baseline de serviços esperados após instalação limpa do SO — sem essa referência, "anômalo" fica subjetivo

### 6.8 Outros Plugins Úteis

| Plugin | Função |
|---|---|
| `windows.hashdump` | Extrai hashes de senha da base SAM presente em memória |
| `windows.driverscan` | Varre e lista drivers do sistema |
| `windows.drivermodule` | Lista módulos de driver instalados |
| `windows.modules` | Lista módulos de kernel carregados |

> [!danger] Cuidado com `hashdump`
> Os hashes extraídos por esse plugin são dados extremamente sensíveis (equivalentes a senha em outro formato). Trate como qualquer outra evidência crítica — acesso restrito, nunca comitar em repositório, nunca compartilhar fora do contexto formal da investigação.

---

## 7. Exemplo Prático — Fluxo Investigativo Completo

Cenário: suspeita de processo se comunicando com IP externo e possível dumping de credenciais.

```powershell
# 1. Identificar o dump
python.exe .\vol.py -f memdump.mem windows.info

# 2. Listar processos e comparar pslist vs psscan
python.exe .\vol.py -f memdump.mem windows.pslist
python.exe .\vol.py -f memdump.mem windows.psscan

# 3. Ver argumentos de execução do processo suspeito
python.exe .\vol.py -f memdump.mem windows.cmdline

# 4. Investigar conexões de rede, filtrando por IP suspeito
python.exe .\vol.py -f memdump.mem windows.netscan | findstr "172.16.8.132"

# 5. Checar persistência via Run keys e serviços
python.exe .\vol.py -f memdump.mem windows.registry.hivelist
python.exe .\vol.py -f memdump.mem windows.svcscan

# 6. Procurar por injeção de código
python.exe .\vol.py -f memdump.mem windows.malfind

# 7. Varredura YARA para IOCs conhecidos (ex: Mimikatz)
python.exe .\vol.py -f memdump.mem yarascan.YaraScan --yara-file .\yara\search_mimikatz.yar
```

Esse encadeamento — processo → rede → persistência (registro/serviços) → injeção → assinaturas — é o esqueleto padrão de investigação de memória Windows, equivalente ao fluxo já documentado para Linux.

---

## 8. Checklist — Análise de Memória em Windows

1. [ ] Capturar com FTK Imager, considerando incluir o pagefile
2. [ ] Confirmar hash (MD5/SHA1 ou SHA256) imediatamente após a captura
3. [ ] Rodar `windows.info` para confirmar SO/build do dump
4. [ ] Revalidar o hash no ambiente de análise antes de prosseguir
5. [ ] Rodar `pslist`/`pstree` **e** `psscan` — comparar para achar processos escondidos
6. [ ] Investigar conexões de rede de processos suspeitos (`netscan`)
7. [ ] Checar `cmdline` e `dlllist` dos processos suspeitos
8. [ ] Rodar `hivelist` e `hivescan` — comparar para achar hives ocultas
9. [ ] Checar chaves de persistência clássicas (Run keys, Services, UserAssist)
10. [ ] Rodar `filescan` para achar arquivos deletados/ocultos com rastro em memória
11. [ ] Rodar `malfind` para detectar injeção de código
12. [ ] Rodar `svcscan` e aplicar o checklist de anomalias de serviço
13. [ ] Varredura YARA contra IOCs/regras conhecidas
14. [ ] Se necessário, `hashdump` (tratar resultado como dado crítico)
15. [ ] Documentar tudo e escrever o relatório com timeline, sistemas afetados, ameaças identificadas e ações recomendadas

---

## 9. Referências para Aprofundamento

- Documentação oficial do Volatility3: https://volatility3.readthedocs.io/en/latest/basics.html
- AccessData FTK Imager — documentação oficial
- Documentação de regras YARA — para escrever assinaturas customizadas de detecção
- SANS FOR500/FOR508 — cobrem memory forensics Windows em profundidade

---

## Ver também
- [Forense Digital em Windows](Forense%20Digital%20em%20Windows.md)
- [Forense de Memória em Linux](../Linux/Forense%20de%20Memória%20em%20Linux.md)
- [Ring0 — Escalonamento de Privilégio e EDR](../Anti-Forense/Ring0%20-%20Escalonamento%20de%20Privilégio%20e%20EDR.md)
- [Anti-Forense e Ofuscação de Dados](../Anti-Forense/Anti-Forense%20e%20Ofuscação%20de%20Dados.md)
- [Arquitetura de Computadores para Forense Digital](../Fundamentos/Arquitetura%20de%20Computadores%20para%20Forense%20Digital.md)
- [Malware](../Threat-Intel/Malware.md)
- [MITRE ATT&CK](../Threat-Intel/MITRE%20ATT%26CK.md)
