---
tags: [DFIR, EDR, XDR, CortexXSIAM, SOC, BlueTeam]
status: estudo em andamento
---

# DFIR com EDR

> [!info] Sobre esta nota
> Esta nota usa SentinelOne e Sysmon como referência (o material-base é vendor-neutro/genérico), mas a seção 7 traduz cada conceito para o vocabulário do **Cortex XDR/XSIAM** — a plataforma do seu dia a dia. A ideia é que você consiga ler qualquer material genérico de EDR (curso, certificação, vendor diferente) e já saber automaticamente "isso aqui, no Cortex, é X". Os exemplos de root cause analysis desta nota (mimikatz, certutil) reaparecem em [Malware](../Threat-Intel/Malware.md); os passos de resposta se conectam diretamente com as etapas de Installation/C2/Actions on Objectives do [Cyber Kill Chain](../Threat-Intel/Cyber%20Kill%20Chain.md); e as regras de detecção customizadas são a mesma lógica por trás do seu trabalho de automação de playbooks no XSIAM.

## Sumário
1. [Introdução ao DFIR com EDR](#1-introdução-ao-dfir-com-edr)
2. [EDR nos Planos de DFIR](#2-edr-nos-planos-de-dfir)
3. [Configurando EDR para Detecção Efetiva](#3-configurando-edr-para-detecção-efetiva)
4. [Detecção e Resposta a Incidentes com EDR](#4-detecção-e-resposta-a-incidentes-com-edr)
5. [Técnicas Avançadas de Análise com EDR](#5-técnicas-avançadas-de-análise-com-edr)
6. [Estudos de Caso](#6-estudos-de-caso)
7. [Correlação com Cortex XDR/XSIAM](#7-correlação-com-cortex-xdrxsiam)
8. [Tópicos Complementares](#8-tópicos-complementares)
9. [Metodologia de Investigação (Checklist)](#9-metodologia-de-investigação-checklist)
10. [Cheatsheet de Referência Rápida](#10-cheatsheet-de-referência-rápida)

---

## 1. Introdução ao DFIR com EDR

**EDR (Endpoint Detection and Response)** monitora continuamente endpoints e detecta ameaças avançadas em tempo real. **EPP (Endpoint Protection Platform)** é a camada mais tradicional — proteção antimalware e aplicação de políticas de segurança. Na prática de mercado atual, a maioria das soluções (incluindo Cortex) já entrega as duas camadas combinadas.

EDR é crítico em quatro operações do processo de DFIR:

| Operação | O que o EDR entrega |
|---|---|
| **Detecção de ameaças** | Monitora comportamento suspeito e assinaturas conhecidas para identificar violações rapidamente |
| **Coleta de informação forense** | Recolhe dados dos endpoints afetados — insumo direto para análise pós-incidente |
| **Resposta a incidentes** | Isola ameaças e limpa malware de forma rápida e efetiva |
| **Análise de longo prazo** | Dados coletados alimentam threat hunting contínuo e melhoria da postura de segurança |

> [!tip] Duas ferramentas, dois níveis de abstração
> **Sysmon** é gratuito, roda em Windows/Linux, e gera logs extremamente detalhados — mas não tem resposta automática nem console central (precisa de um SIEM, ex.: Wazuh). **SentinelOne** é uma plataforma EDR completa — detecção, resposta automática e console central já embutidos. Entender os dois ajuda a entender EDR corporativo em qualquer vendor, porque cada solução comercial (incluindo Cortex) resolve o mesmo problema que Sysmon expõe de forma crua.

---

## 2. EDR nos Planos de DFIR

Incorporar EDR a um plano de DFIR aumenta a capacidade de detectar e responder a ameaças rapidamente — em três frentes:

### 2.1 Detecção e Avaliação de Incidentes
- **Monitoramento e análise contínuos**: EDR observa comportamento do sistema constantemente para detectar atividade anômala e violações potenciais.
- **Detecção precoce e threat intelligence**: algoritmos avançados de detecção alertam a equipe de DFIR antes que o dano se espalhe.

### 2.2 Resposta e Mitigação de Incidentes
- **Resposta automática e imediata**: ao detectar uma ameaça, o EDR pode agir sozinho — matar processo malicioso, isolar malware, encerrar conexões perigosas.
- **Coordenação e interação**: o plano de DFIR trabalha de forma integrada com as informações que o EDR fornece, garantindo que a resposta seja coordenada.

### 2.3 Recuperação e Remediação
- **Recuperação rápida**: logs detalhados de evento mostram exatamente como sistemas e aplicações foram afetados, acelerando o retorno seguro à operação.
- **Reinício de processos com segurança**: os dados do EDR orientam decisões estratégicas sobre quais recursos priorizar na recuperação.

---

## 3. Configurando EDR para Detecção Efetiva

### 3.1 Monitoramento e Registro

A decisão mais crítica de configuração de EDR é **o que registrar**. No SentinelOne, isso é definido via política. No Sysmon, via arquivo de configuração XML, que habilita eventos específicos por ID.

**Tabela completa de Event IDs do Sysmon:**

| ID | Evento | Relevância forense |
|---|---|---|
| 1 | Process Creation | Detectar processo não autorizado/suspeito |
| 2 | File Creation Time Changed | Detectar timestomping |
| 3 | Network Connection | Detectar vazamento de dado ou tráfego malicioso |
| 4 | Sysmon Service State Changed | Proteção da própria ferramenta de monitoramento contra sabotagem |
| 5 | Process Terminated | Investigar processos encerrados prematuramente/afetados por malware |
| 6 | Driver Loaded | Detectar carregamento de driver não autorizado/malicioso |
| 7 | Image Loaded | Detectar rastros deixados por malware (DLL loading) |
| 8 | CreateRemoteThread | Detectar injeção de processo maliciosa |
| 9 | RawAccessRead | Monitorar roubo de dado/atividade de malware via leitura raw de disco |
| 10 | ProcessAccess | Detectar interferência de malware em outro processo |
| 11 | File Create | Monitorar criação/manipulação não autorizada de arquivo |
| 12 | Registry Event | Detectar mudança de registro não autorizada/configuração maliciosa |
| 13 | Registry — Value Set | Monitorar escrita em chave/valor de registro (comum em malware) |
| 14 | Registry — Object Renamed | Renomear chave de registro é técnica de evasão |
| 15 | File Create Stream Hash | Verificar integridade de arquivo via hash do stream |
| 16 | Sysmon Configuration Change | Detectar se o próprio monitoramento foi adulterado |
| 17 | Pipe Created | Detectar comunicação inter-processo de malware |
| 18 | Pipe Connected | Identificar canais de comunicação maliciosos |
| 19 | WmiEventFilter | Detectar uso malicioso de filtro WMI |
| 20 | WmiEventConsumer | Monitorar interação de script malicioso com WMI |
| 21 | WmiEventConsumerToFilter | Detectar relação filtro↔consumidor WMI — atividade complexa |
| 22 | DNSEvent (DNS query) | Detectar consultas a domínios maliciosos |
| 23 | FileDelete | Detectar deleção maliciosa de arquivo/tentativa de apagar rastro |
| 24 | ClipboardChange | Detectar vazamento de informação via clipboard |
| 25 | ProcessTampering | Monitorar manipulação/adulteração de processo |
| 26 | FileDeleteDetected | Detectar rastros de malware persistente/dumps deletados |
| 27 | FileBlockExecutable | Sysmon bloqueou criação de executável (PE) |
| 28 | FileBlockShredding | Sysmon bloqueou shredding de arquivo (ex.: SDelete) |
| 29 | FileExecutableDetected | Detecção de criação de novo executável (PE) |

> [!tip] Não precisa habilitar tudo
> Cada ID adicional é mais volume de log e mais custo de armazenamento/processamento. A prática real é habilitar o que se conecta a hipóteses concretas de ameaça no seu ambiente — não "tudo, por via das dúvidas".

### 3.2 Regras de Detecção de Ameaças

Regras customizadas podem ser escritas contra vetores de ataque e comportamentos de ameaça conhecidos — incluindo assinaturas de malware, comportamento anômalo e mudanças não autorizadas no sistema. Durante um DFIR, IoCs e IoAs obtidos sobre um ator de ameaça específico podem virar regra customizada e ser buscados **retrospectivamente**, ampliando o escopo da investigação.

**Fluxo prático — regra customizada no SentinelOne** (exemplo: detectar `Log Clear` via `wevtutil.exe`):
1. `Console SentinelOne → Sentinels → Start Custom Rules`
2. Definir **Rule Name**, **Rule Severity**, **Rule Type**
3. Escrever a **query** na seção **Condition**
4. Definir a **Response** desejada (ex.: marcar como Threat, ou quarentena de rede direta)
5. Revisar no **Summary** e marcar "Activate rule immediately after saving"

**Configuração via Sysmon (XML)** — elementos centrais:

```xml
<Sysmon schemaversion="4.82">
  <HashAlgorithms>*</HashAlgorithms>
  <EventFiltering>
    <DriverLoad onmatch="exclude">
      <Signature condition="contains">microsoft</Signature>
      <Signature condition="contains">windows</Signature>
    </DriverLoad>
    <ProcessTerminate onmatch="include" />
    <NetworkConnect onmatch="include">
      <DestinationPort condition="is">443</DestinationPort>
      <DestinationPort condition="is">80</DestinationPort>
    </NetworkConnect>
    <NetworkConnect onmatch="exclude">
      <Image condition="endsWith">iexplore.exe</Image>
    </NetworkConnect>
  </EventFiltering>
</Sysmon>
```

**Operadores disponíveis no Sysmon:** `contains`, `equals`, `startsWith`, `endsWith`, `is`, `greaterThan`, `lessThan`, `image` (compara caminho/nome de arquivo).

### 3.3 Gestão de Alertas

O objetivo é filtrar o excesso de falsos positivos para que threat hunters e IR foquem em ameaças reais:
- Atribuir **rating de criticidade** a cada alerta, priorizando por nível de risco
- Analisar continuamente os dados de alerta, fortalecendo o processo de threat hunting
- Integrar com threat intelligence atualizada para reduzir taxa de falso positivo

> [!warning] Sysmon sozinho não centraliza nada
> Sysmon não tem console central para coletar/gerenciar eventos de múltiplos endpoints — por isso soluções SIEM (ex.: Wazuh) são normalmente usadas para consolidar logs Sysmon de toda a frota.

### 3.4 Integração e Automação

Integrar EDR com SIEM/SOAR permite troca de threat intelligence e resposta automatizada:
- **Uso de API**: padroniza e simplifica comunicação entre ferramentas
- **Resposta automatizada a incidente**: protocolos pré-definidos ativados automaticamente ao detectar ameaça (ex.: isolar arquivo suspeito)
- **Compartilhamento de threat intelligence**: informação sobre ameaças detectadas é compartilhada entre sistemas, ampliando a perspectiva de avaliação
- **Visão consolidada do incidente**: reunir informação de múltiplas fontes em um único sistema

---

## 4. Detecção e Resposta a Incidentes com EDR

### 4.1 Métodos de Detecção

| Método | Como funciona | Ponto forte |
|---|---|---|
| **Baseado em assinatura** | Compara contra base de assinaturas conhecidas (definições de vírus) | Rápido contra ameaças já catalogadas |
| **Comportamental** | Analisa perfis de comportamento de usuário/sistema para achar atividade anômala | Melhor contra ameaças novas/em evolução |
| **Baseado em anomalia** | Detecta desvio em tráfego de rede, atividade de usuário, performance de sistema | Essencial contra 0-day |

### 4.2 Motores de Detecção (exemplo SentinelOne)

| Motor | O que detecta |
|---|---|
| **Reputation** | Avalia reputação de arquivos/apps via bases de reputação e fontes de segurança |
| **Static AI** | Analisa estrutura/conteúdo de executáveis para achar características maliciosas |
| **Static AI — Suspicious** | Arquivos com características estáticas altamente suspeitas (nem sempre maliciosos, mas suspeitos) |
| **Behavioral AI — Executables** | Monitora comportamento de executáveis em tempo real |
| **Documents, scripts** | Detecta código malicioso escondido em documento/script (ex.: macro) |
| **Lateral movement** | Detecta movimentação horizontal dentro da rede |
| **Anti-Exploitation/Fileless** | Detecta ataques em memória e malware fileless |
| **Potentially Unwanted Applications (PUA)** | Identifica software sem benefício claro ou com comportamento indesejado |
| **Detect Interactive Threats** | Detecta ameaças que exigem interação/comando manual do atacante |

### 4.3 Passos de Resposta a Incidentes

1. **Isolation** — isolar rapidamente para impedir propagação (remover dispositivo da rede, encerrar processo suspeito)
2. **Containment** — minimizar dano: impedir vazamento de dado, restringir acesso de usuário, proteger dado crítico
3. **Telemetry Data Collection** — coletar toda informação relevante (logs, relatos de usuário, tráfego de rede)
4. **In-depth Analysis** — determinar ponto de entrada, sistemas afetados, como a ameaça se espalhou
5. **Root Cause Analysis** — determinar causa raiz para prevenir recorrência (ver seção 5.3)
6. **Incident Response** — ações necessárias para mitigar impacto e voltar à operação normal
7. **System Optimization** — aplicar updates/patches para fechar brechas de segurança
8. **Prevention** — políticas mais fortes, treinamento, avaliação de risco contínua

### 4.4 Ações de Resposta Disponíveis

No SentinelOne, além de política de resposta automática, é possível aplicar resposta manual: **Kill & Quarantine**, **Add Blacklist**, **Apply Exclusion**, **Isolate from Network**.

### 4.5 Forense Digital

- **Coleta de dados forenses**: EDR coleta atividade de malware, comandos de usuário, mudanças de sistema — técnicas incluem memory dump, captura de tráfego de rede, armazenamento de log.
- **Preservação de evidência forense**: garantir integridade (hash, selagem/assinatura, armazenamento seguro) e documentar cada etapa da análise para viabilizar uso em processo legal.

---

## 5. Técnicas Avançadas de Análise com EDR

### 5.1 Análise Comportamental e Detecção de Anomalia

Comandos isolados como `net users`, `net user /add` ou `net localgroup administrators /add` via PowerShell **não são anomalia por si só** — são comandos administrativos legítimos em muitos contextos.

> [!warning] O contexto é o que torna anômalo
> Se um **Shadow Copy Delete** ocorre logo **após** essa sequência (enumerar usuário → adicionar usuário → adicionar a grupo admin), o EDR passa a classificar isso como atividade anômala — é a **combinação e a ordem temporal** dos eventos que formam o padrão de ataque, não um evento isolado.

### 5.2 Integração com Threat Intelligence

EDR pode ser alimentado com IPs maliciosos conhecidos, URLs, assinaturas de arquivo maliciosas vindas de fontes de CTI de terceiros. Isso enriquece os dados coletados pelo EDR, produzindo resultados mais avançados e com menos falso positivo — incidentes ficam mais precisos e fáceis de analisar quando enriquecidos com CTI.

### 5.3 Root Cause Analysis

**Exemplo 1 — Mimikatz:**
Investigando um incidente com ameaça `mimikatz.zip`, o threat hunting revela a cadeia de processo:
```
powershell.exe → hh.exe → [endereço GitHub relevante]
```
Ou seja: o download de `mimikatz.zip` partiu de uma URL do GitHub, iniciado via `hh.exe`, que por sua vez foi chamado por `powershell.exe`.

**Exemplo 2 — Certutil.exe:**
Malware foi baixado via `certutil.exe` e depois detectado. Examinando mais a fundo quem executou `certutil.exe`:
```
httpd.exe (processo do Apache) → certutil.exe
```
Conclusão do Incident Responder: **existe uma vulnerabilidade na aplicação web**, e explorando-a é possível executar comandos no servidor através do próprio processo da aplicação web — a causa raiz da atividade suspeita no endpoint é uma vulnerabilidade de segurança web, não o endpoint em si.

> [!tip] O padrão por trás dos dois exemplos
> Em ambos os casos, a pergunta que resolve o caso é a mesma: **"quem é o processo pai deste processo suspeito?"** — subir a cadeia de causalidade (parent → child) é a técnica central de root cause analysis em EDR, e é exatamente o que a seção 7.5 mostra sendo automatizado no Cortex.

---

## 6. Estudos de Caso

### 6.1 Ransomware Attack Detection and Response

**Indicadores de detecção:**
- Surgimento repentino de arquivos criptografados
- Mudanças inesperadas em nome/extensão de arquivo
- Lentidão anormal do sistema ou aplicações travando

**Resposta:**
- Isolar a rede imediatamente para impedir propagação
- Restaurar dados a partir de backup
- Não pagar o resgate — notificar autoridades
- Aplicar patches de segurança regularmente, manter firewall atualizado
- Usar ações de **Kill, Quarantine**, **Remediate** e **Rollback** do EDR para restaurar arquivos ao estado original

### 6.2 Credential Dumping Detection and Response

**Indicadores de detecção:**
- Atividade de memory dump observada
- Tentativas incomuns de escalonar acesso/privilégio
- Autenticação bem-sucedida ou falha inesperada nos logs

No cenário do material: atacante explora vulnerabilidade de aplicação web para executar comando remoto, baixa a ferramenta mimikatz, extrai do zip e roda com os parâmetros necessários para dump de senha.

**Resposta:**
- Isolar e investigar os sistemas afetados
- Trocar imediatamente as senhas das contas afetadas
- Fortalecer controles de acesso e monitoramento
- Estabelecer time de resposta a incidente dedicado

### 6.3 Detected Persistence Activity

**Indicadores de detecção:**
- Aplicações suspeitas adicionadas a pastas de inicialização
- Mudanças inesperadas em registro ou tarefas agendadas
- Mudanças não autorizadas em arquivo de configuração do sistema

No cenário do material: adição de usuário + adição desse usuário ao grupo Administrators — clássico padrão de persistência.

**Resposta:**
- Isolar imediatamente sistemas com mudanças suspeitas/não autorizadas
- Limpar configurações maliciosas via restore de sistema ou reinstalação limpa
- Revisar e fortalecer firewall e monitoramento de rede
- Habilitar monitoramento/alerta para detectar tentativas similares rapidamente
- Examinar eventos da conta envolvida e deletá-la **após** tirar imagem do sistema (preservar evidência antes de remediar)

---

## 7. Correlação com Cortex XDR/XSIAM

> [!info] Por que esta seção existe
> Todo o material acima usa SentinelOne/Sysmon como referência didática — mas seu trabalho do dia a dia é em Cortex. Esta seção é o "tradutor": cada conceito genérico de EDR mapeado para o equivalente real na plataforma que você usa.

### 7.1 Tabela de equivalência de conceitos

| Conceito genérico (SentinelOne/Sysmon) | Equivalente no Cortex XDR/XSIAM |
|---|---|
| Coleta de telemetria (Sysmon Event IDs / policy do SentinelOne) | Agente Cortex XDR coleta automaticamente para o dataset `xdr_data` — processo, rede, arquivo, registro, já normalizados |
| Regra customizada (SentinelOne Custom Rule / Sysmon XML) | **BIOC** (comportamental/TTP), **IOC** (indicador estático conhecido) ou **Correlation Rule** (múltiplos eventos/tempo) — a lógica de decisão é: comportamental → BIOC; artefato estático conhecido-mau → IOC; precisa de correlação temporal/múltiplos eventos → Correlation Rule |
| Motores de detecção (Reputation, Static AI, Behavioral AI...) | Módulos nativos do agente Cortex XDR: **Local Analysis** (ML pré-execução, equivalente a Static AI), **Behavioral Threat Protection (BTP)** (módulos para ransomware, webshell, credential gathering, exploit — equivalente a Behavioral AI/Anti-Exploitation), integração **WildFire** (reputação/sandbox em nuvem) |
| Ações de resposta (Kill & Quarantine, Isolate from Network, Blacklist, Exclusion) | **Terminate Process**, **Quarantine File**, **Isolate Endpoint** (contenção de rede), bloqueio via **IOC (hash)**, **Exception/Exclusion** |
| Console de Incidentes (SentinelOne) | Tela de **Incidents** do Cortex — com diferencial importante: o Cortex já **agrupa automaticamente alertas relacionados em um único incidente** via stitching de causalidade, reduzindo ruído antes mesmo de o analista abrir o caso |
| Integração SIEM/SOAR (Wazuh, API, resposta automatizada) | **XSIAM já é SIEM + SOAR + XDR na mesma plataforma** — a automação descrita na seção 3.4 (resposta automática, protocolos pré-definidos) é literalmente o mesmo conceito por trás de **Playbooks** no XSIAM |
| Root cause analysis manual (subir a árvore de processo pai/filho) | **Causality Chain View / Causality View** — o Cortex já renderiza visualmente a cadeia completa de causalidade de qualquer alerta automaticamente, sem precisar reconstruir manualmente processo por processo |

> [!tip] Ligação direta com seu trabalho
> A automação descrita na seção 3.4 (protocolo pré-definido ativado automaticamente ao detectar ameaça, integração via API, visão consolidada do incidente) é exatamente o problema que sua arquitetura de **Playbook Triggers para o ciclo de vida de incidente no XSIAM** já resolve na prática — captura de dados de resolução, sincronização automática com ServiceNow, alertas de SLA/MTTR. O material genérico está descrevendo em teoria o que você já implementou em produção.

### 7.2 Sysmon Event IDs → campos de `xdr_data`

A tabela abaixo é ilustrativa — **sempre validar contra o schema real do tenant** (mesma disciplina de `[VALIDAR CAMPO NO TENANT]` já usada nas suas notas de XQL):

| Evento Sysmon | Campo/filtro aproximado em `xdr_data` |
|---|---|
| ID 1 — Process Creation | `event_type = PROCESS`, `event_sub_type = PROCESS_START` |
| ID 3 — Network Connection | `event_type = NETWORK` |
| ID 11 — File Create | `event_type = FILE`, `event_sub_type = FILE_CREATE_NEW` |
| ID 12/13/14 — Registry Event | `event_type = REGISTRY` |
| ID 22 — DNS Query | `event_type = DNS` (dataset pode variar conforme onboarding) |

### 7.3 Exemplo de BIOC — "Log Clear" via wevtutil (mesmo caso do material)

A regra customizada do SentinelOne para detectar `wevtutil.exe` limpando log de evento é, em essência, um **BIOC** — comportamento (TTP: *Indicator Removal*, T1070.001 no [MITRE ATT&CK](../Threat-Intel/MITRE%20ATT&CK.md)), não um artefato estático:

```xql
dataset = xdr_data
| filter event_type = PROCESS and event_sub_type = PROCESS_START
| filter actor_process_image_name = "wevtutil.exe"
| filter actor_process_command_line contains "cl " or actor_process_command_line contains "clear-log"
| fields agent_hostname, actor_process_command_line, actor_effective_username, _time
```
*(Campos exatos — `actor_process_command_line`, `actor_effective_username` — [VALIDAR CAMPO NO TENANT] antes de promover a produção.)*

### 7.4 Exemplos de hunting XQL para os estudos de caso da seção 6

**Ransomware — volume anômalo de renomeação/criação de arquivo em curto intervalo:**
```xql
dataset = xdr_data
| filter event_type = FILE and event_sub_type in (FILE_RENAMED, FILE_CREATE_NEW)
| comp count() as file_event_count by agent_hostname, actor_process_image_name
| filter file_event_count > 100
```

**Credential Dumping — processo suspeito com linhagem de causalidade a partir de processo web:**
```xql
dataset = xdr_data
| filter event_type = PROCESS and event_sub_type = PROCESS_START
| filter actor_process_image_name in ("certutil.exe", "mimikatz.exe", "procdump.exe")
| filter causality_actor_process_image_name in ("httpd.exe", "w3wp.exe", "nginx.exe")
| fields agent_hostname, actor_process_image_name, causality_actor_process_image_name, _time
```

**Persistence — sequência user add + admin group em janela curta (equivalente ao exemplo da seção 5.1):**
```xql
dataset = xdr_data
| filter event_type = PROCESS and event_sub_type = PROCESS_START
| filter actor_process_command_line contains "net user" or actor_process_command_line contains "net localgroup administrators"
| comp count() as seq_count by agent_hostname
| filter seq_count >= 2
```

> [!warning] Estes exemplos são ponto de partida, não regra de produção
> Seguindo o critério do próprio material de referência de Cortex: **nunca** trate uma query de hunting como detecção de produção sem validar taxa de falso positivo e passar por modo alert-only antes de promover para prevenção — mesma lógica do ciclo de vida de detection engineering (Hunt → Validate → Codify → Alert-only → Medir FP → Tune → Promover).

### 7.5 Causality Chain View — root cause automatizado

Os dois exemplos da seção 5.3 (mimikatz e certutil) foram reconstruídos **manualmente**, olhando processo por processo. No Cortex, essa reconstrução já vem pronta: a visualização de causalidade mostra a árvore completa `processo pai → processo filho → ação` de qualquer alerta, poupando exatamente o trabalho manual que o material descreve — o checklist de pivôs de investigação (linhagem de processo, hash prevalence, reuso de domínio/IP, atividade do usuário) é o roteiro para explorar essa árvore de forma sistemática.

---

## 8. Tópicos Complementares

> [!info] Sobre esta seção
> Falta amarrar EDR com o restante da hierarquia de siglas do mercado (EPP/EDR/XDR/SIEM/SOAR) e conectar os estudos de caso da seção 6 ao vocabulário do [MITRE ATT&CK](../Threat-Intel/MITRE%20ATT&CK.md) e do [Cyber Kill Chain](../Threat-Intel/Cyber%20Kill%20Chain.md).

### 8.1 EPP → EDR → XDR → SIEM/SOAR/XSIAM — a evolução em uma tabela

| Camada | Escopo | Pergunta que responde |
|---|---|---|
| **EPP** | Um endpoint | "Este arquivo é malware conhecido?" |
| **EDR** | Um endpoint, com profundidade comportamental | "O que este endpoint fez, passo a passo, e consigo responder a isso?" |
| **XDR** | Múltiplas fontes correlacionadas (endpoint + rede + identidade + cloud) | "Esse comportamento em um endpoint se conecta com algo em outro lugar do ambiente?" |
| **SIEM** | Toda a organização, foco em log/correlação | "O que aconteceu, cruzando todas as fontes de log?" |
| **SOAR** | Automação de resposta entre ferramentas | "Como automatizo a resposta assim que algo é detectado?" |
| **XSIAM** | XDR + SIEM + SOAR na mesma plataforma | Junta as quatro perguntas acima em um único produto |

### 8.2 Mapeamento ATT&CK dos estudos de caso da seção 6

| Estudo de caso | Tática/Técnica ATT&CK aproximada |
|---|---|
| Ransomware | Impact (TA0040) — Data Encrypted for Impact (T1486) |
| Credential Dumping | Credential Access (TA0006) — OS Credential Dumping (T1003) |
| Persistence (user add + admin group) | Persistence (TA0003) — Create Account: Local Account (T1136.001) |

### 8.3 Relação com o Cyber Kill Chain

Cada estudo de caso da seção 6 já chegou na etapa **Actions on Objectives** (ransomware) ou está a caminho dela (credential dumping como preparação para Lateral Movement, persistence garantindo sobrevivência antes de C2). A resposta do EDR — isolar, matar processo, restaurar via rollback — é, na prática, a aplicação real do princípio "**break the kill chain**" já discutido em [Cyber Kill Chain](../Threat-Intel/Cyber%20Kill%20Chain.md) seção 12.2: quebrar a cadeia o mais cedo possível reduz drasticamente o custo do incidente.

---

## 9. Metodologia de Investigação (Checklist)

> [!todo] Como usar
> Sequência sugerida ao investigar um alerta de EDR, do primeiro sinal até o relatório final.

- [ ] Confirmar se o alerta é assinatura, comportamental ou anomalia — isso já orienta a urgência
- [ ] Subir a cadeia de causalidade (processo pai → filho) até a origem real do comportamento
- [ ] Isolar o endpoint afetado antes de aprofundar a análise, se houver risco de propagação
- [ ] Coletar telemetria completa (logs, tráfego, memory dump se aplicável) antes de qualquer remediação
- [ ] Rodar root cause analysis — a causa é o endpoint em si, ou um sistema upstream (ex.: aplicação web vulnerável)?
- [ ] Verificar se o padrão observado bate com um dos estudos de caso da seção 6 (ransomware, credential dumping, persistence)
- [ ] Mapear o comportamento para [MITRE ATT&CK](../Threat-Intel/MITRE%20ATT&CK.md) e, se aplicável, para a etapa correspondente do [Cyber Kill Chain](../Threat-Intel/Cyber%20Kill%20Chain.md)
- [ ] Se estiver no Cortex, verificar a Causality Chain View antes de reconstruir manualmente
- [ ] Extrair IOCs/IoAs do incidente e considerar promovê-los a regra customizada (BIOC/IOC/Correlation Rule) para busca retrospectiva
- [ ] Documentar cadeia de custódia da evidência coletada, preservando integridade (hash) para uso legal se necessário
- [ ] Aplicar lição aprendida — patch, hardening, ajuste de política — antes de encerrar o incidente

---

## 10. Cheatsheet de Referência Rápida

**Ações de resposta EDR (equivalência rápida):**
```
Kill & Quarantine       → Terminate Process + Quarantine File (Cortex)
Isolate from Network    → Isolate Endpoint (Cortex)
Add Blacklist           → IOC de hash bloqueado (Cortex)
Apply Exclusion         → Exception/Exclusion (Cortex)
```

**Decisão de tipo de regra (Cortex):**
```
Comportamental (TTP)?             → BIOC
Artefato estático conhecido-mau?  → IOC
Precisa correlação multi-evento?  → Correlation Rule
```

**Ciclo de detection engineering:**
```
Hunt → Validate → Codify (BIOC/IOC/Correlation) → Alert-only → Medir FP → Tune → Promover
```

**Passos de resposta a incidente (ordem):**
```
Isolation → Containment → Telemetry Collection → In-depth Analysis →
Root Cause Analysis → Incident Response → System Optimization → Prevention
```

**Pergunta-chave de root cause analysis:**
```
"Quem é o processo pai deste processo suspeito?"
```

---

## Ver também
- [MITRE ATT&CK](../Threat-Intel/MITRE%20ATT&CK.md)
- [Cyber Kill Chain](../Threat-Intel/Cyber%20Kill%20Chain.md)
- [Malware](../Threat-Intel/Malware.md)
- [Network Forensics](../Rede-e-Email/Network%20Forensics.md)
- [Forense Digital em Windows](../Windows/Forense%20Digital%20em%20Windows.md)
- [Ring0 — Escalonamento de Privilégio e EDR](../Anti-Forense/Ring0%20-%20Escalonamento%20de%20Privilégio%20e%20EDR.md)
