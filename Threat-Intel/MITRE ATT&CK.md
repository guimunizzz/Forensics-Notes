---
tags: [DFIR, MITREATTACK, SOC, ThreatIntel, BlueTeam]
status: estudo em andamento
---

# MITRE ATT&CK

> [!info] Sobre esta nota
> O MITRE ATT&CK é a "linguagem comum" que amarra todas as outras notas deste vault — quando [Network Forensics](../Rede-e-Email/Network%20Forensics.md) fala em mapear achados para táticas como Command and Control ou Exfiltration, ou quando [Email Forensics](../Rede-e-Email/Email%20Forensics.md) e [Android Forensics](../Mobile/Android%20Forensics.md) tratam de análise de malware, é o ATT&CK que dá o vocabulário padronizado para descrever *o que* o atacante fez em cada etapa. Esta nota cobre a estrutura do framework (Matrizes → Táticas → Técnicas/Sub-técnicas → Procedimentos → Mitigações → Grupos → Software) e como usá-lo na prática de um SOC.

## Sumário
1. [O que é o MITRE](#1-o-que-é-o-mitre)
2. [O que é o MITRE ATT&CK Framework](#2-o-que-é-o-mitre-attck-framework)
3. [Por que importa para o Analista SOC](#3-por-que-importa-para-o-analista-soc)
4. [Matrizes](#4-matrizes)
5. [Táticas (Tactics)](#5-táticas-tactics)
6. [Técnicas e Sub-técnicas](#6-técnicas-e-sub-técnicas)
7. [Mitigações](#7-mitigações)
8. [Grupos (APT Groups)](#8-grupos-apt-groups)
9. [Software](#9-software)
10. [Tópicos Complementares](#10-tópicos-complementares)
11. [Metodologia de Uso no SOC (Checklist)](#11-metodologia-de-uso-no-soc-checklist)
12. [Cheatsheet de Referência Rápida](#12-cheatsheet-de-referência-rápida)

---

## 1. O que é o MITRE

**MITRE** é uma organização sem fins lucrativos fundada em 1958 nos EUA, que atua como conselheira independente para avançar a segurança nacional e o interesse público. Atua em várias frentes além de cibersegurança: aeroespacial, IA/machine learning, aviação e transporte, defesa e inteligência, inovação governamental, saúde, segurança interna e telecom.

> [!tip] Por que isso importa
> O ATT&CK não é produto de uma empresa vendendo solução de segurança — é mantido por uma organização sem fins lucrativos com décadas de trabalho em pesquisa aplicada. Isso é parte do motivo pelo qual o framework virou **padrão de fato da indústria**, adotado por fornecedores de EDR/SIEM (incluindo Cortex XDR/XSIAM) e por times de SOC no mundo inteiro.

## 2. O que é o MITRE ATT&CK Framework

**ATT&CK** = **Adversarial Tactics, Techniques, and Common Knowledge**. É uma base de conhecimento introduzida pelo MITRE em **2013**, atualizada continuamente, que permite analisar ataques cibernéticos de forma sistemática — dividindo o ataque em estágios (táticas) e detalhando os métodos usados em cada estágio (técnicas).

Diferente de uma lista solta de indicadores, o ATT&CK descreve **comportamento observado em ataques reais** — por isso continua útil mesmo quando malware, infraestrutura e ferramentas específicas do atacante mudam: o comportamento subjacente (ex.: "escalar privilégio via token manipulation") tende a se repetir.

## 3. Por que importa para o Analista SOC

Como cada estágio do ataque é detalhado no framework, o analista SOC consegue:

- Ver claramente **quais ações tomar em cada estágio** de um ataque, usando o ATT&CK como referência.
- **Mapear** o ataque observado para um vocabulário padronizado, compartilhável entre times e ferramentas.
- Escrever relatórios aprofundados e **arquivar detalhes do ataque** para uso/consulta futura.
- Pesquisar sobre ataques que ainda não ocorreram no seu ambiente, desenvolvendo detecção **proativa** com base em técnicas conhecidas mas não vistas localmente ainda.

> [!info] Na prática de SOC/Cortex XSIAM
> Regras de correlação, BIOCs e Analytics no Cortex XSIAM costumam já vir **pré-mapeados para IDs de técnica ATT&CK** — quando um alerta dispara, o analista já enxerga "isso é T1059.001 (PowerShell)" direto no incidente, sem precisar adivinhar. Saber a estrutura do framework é o que permite interpretar esse mapeamento corretamente e decidir os próximos passos da investigação.

---

## 4. Matrizes

A **Matrix (Matriz)** é o método de visualização do ATT&CK — organiza táticas (colunas) e técnicas (células abaixo de cada tática) em uma grade, permitindo enxergar rapidamente o "mapa" de comportamentos possíveis de um atacante.

Existem **3 matrizes**, uma para cada tipo de plataforma:

| Matriz | Foco | Link |
|---|---|---|
| **Enterprise** | Ataques contra organizações — redes corporativas, cloud, containers | https://attack.mitre.org/matrices/enterprise/ |
| **Mobile** | Segurança de dispositivos móveis (individuais e corporativos) | https://attack.mitre.org/matrices/mobile/ |
| **ICS** | Sistemas de controle industrial (Industrial Control Systems) | https://attack.mitre.org/matrices/ics/ |

### 4.1 Matriz Enterprise

A primeira e maior matriz criada pelo MITRE — cobre mais sistemas digitais e por isso concentra muito mais informação que as outras. É a matriz usada para entender ataques contra organizações de médio/grande porte.

Possui **7 sub-matrizes**, cada uma focada em uma superfície de ataque específica:

- PRE (pré-ataque, reconhecimento/preparação)
- Windows
- macOS
- Linux
- Cloud
- Network
- Containers

### 4.2 Matriz Mobile

Preparada para dispositivos móveis — segurança individual e corporativa. Contém menos informação que a Enterprise. Possui **2 sub-matrizes**:

- Android
- iOS

> [!tip] Ligação com este vault
> A sub-matriz Android complementa diretamente a nota de [Android Forensics](../Mobile/Android%20Forensics.md) — técnicas como instalação de app malicioso ou abuso de permissão têm IDs próprios nessa matriz, diferentes dos IDs da matriz Enterprise.

### 4.3 Matriz ICS

Cobre a segurança cibernética de dispositivos em sistemas de controle industrial (SCADA, PLCs, etc.) — usada para segurança e análise desse tipo de ambiente, bem diferente de TI corporativa tradicional.

---

## 5. Táticas (Tactics)

**Tática** é o **objetivo** do atacante — o "porquê" da ação, não o "como". É um dos componentes mais importantes do ATT&CK porque agrupa comportamentos do atacante e mostra os estágios do ataque. Táticas ficam na **linha superior** da matriz, como colunas.

Como táticas expressam propósito (algo mais genérico), elas são bastante parecidas entre as três matrizes.

### 5.1 Táticas Enterprise

| ID     | Tática                               |
| ------ | ------------------------------------ |
| TA0043 | Reconnaissance                       |
| TA0042 | Resource Development                 |
| TA0001 | Initial Access                       |
| TA0002 | Execution                            |
| TA0003 | Persistence                          |
| TA0004 | Privilege Escalation                 |
| TA0005 | Defense Evasion *(ver aviso abaixo)* |
| TA0006 | Credential Access                    |
| TA0007 | Discovery                            |
| TA0008 | Lateral Movement                     |
| TA0009 | Collection                           |
| TA0011 | Command and Control                  |
| TA0010 | Exfiltration                         |
| TA0040 | Impact                               |

Link: https://attack.mitre.org/tactics/enterprise/

> [!warning] Mudança estrutural recente (ATT&CK v19, abril de 2026)
> A tática **Defense Evasion (TA0005)** foi dividida em duas: **Stealth (TA0005 — mantém o ID)**, cobrindo técnicas de "se esconder" (ofuscação, guardrails de execução, remoção de indicadores), e **Defense Impairment (TA0112)**, cobrindo técnicas de "quebrar ativamente as defesas" (desabilitar firewall, matar EDR). É a mudança estrutural mais significativa do framework em anos — a Matriz Enterprise passou de **14 para 15 táticas**. Se você estudou por um material mais antigo (como o desta nota, originalmente baseado em conteúdo de 2023), tenha isso em mente e sempre confira a lista atual em attack.mitre.org antes de reportar algo formalmente.

### 5.2 Táticas Mobile

Historicamente 14 táticas foram ensinadas em materiais de treinamento (incluindo *Network Effects* e *Remote Service Effects*, específicas do contexto mobile). O número atual publicado pelo MITRE é **12 táticas** — a lista muda com menos frequência que a Enterprise, mas ainda assim **sempre confira a versão vigente**:

Link: https://attack.mitre.org/tactics/mobile/

### 5.3 Táticas ICS

**12 táticas**, incluindo duas exclusivas desse domínio que não existem nas outras matrizes: *Inhibit Response Function* e *Impair Process Control* — refletem o objetivo típico de um ataque a ambiente industrial (não é roubar dados, é **interromper ou manipular um processo físico**).

Link: https://attack.mitre.org/tactics/ics/

---

## 6. Técnicas e Sub-técnicas

Enquanto a tática mostra **o objetivo**, a técnica mostra **o método específico** usado para alcançá-lo — como o atacante de fato executou aquele estágio do ataque. Cada técnica/sub-técnica pertence a uma tática específica na matriz.

No visual da matriz, uma área cinza ao lado do nome da técnica indica que ela **possui sub-técnicas** — variações mais específicas do mesmo método. Por exemplo, a técnica "Phishing" (T1566) tem sub-técnicas como *Spearphishing Attachment* (T1566.001), *Spearphishing Link* (T1566.002) e *Spearphishing via Service* (T1566.003).

> [!tip] Convenção de ID
> Técnica = `T####` (ex.: `T1566`). Sub-técnica = `T####.###` (ex.: `T1566.001`). Essa convenção é universal em toda ferramenta/relatório que referencia ATT&CK — inclusive em regras de detecção no Cortex XSIAM.

### 6.1 Escala do framework (e como ela cresce)

| Matriz | Snapshot original (mai/2023) | Snapshot atual (abr/2026 — v19) |
|---|---|---|
| **Enterprise** | 193 técnicas / 401 sub-técnicas | 222 técnicas / 475 sub-técnicas |
| **Mobile** | 66 técnicas / 41 sub-técnicas | 77 técnicas / 47 sub-técnicas |
| **ICS** | 79 técnicas / 0 sub-técnicas | 79 técnicas / **18 sub-técnicas** (novidade da v19 — antes o ICS não tinha sub-técnicas) |

Links para os números sempre atualizados:
- Enterprise: https://attack.mitre.org/techniques/enterprise/
- Mobile: https://attack.mitre.org/techniques/mobile/
- ICS: https://attack.mitre.org/techniques/ics/

> [!warning] Números mudam o tempo todo
> O ATT&CK é atualizado em releases regulares (esquema de versão major.minor). **Nunca memorize um número absoluto** — o valor real serve para dar noção de escala; para citar em relatório formal, sempre confira a versão vigente no site oficial.

### 6.2 Procedimento (Procedure)

**Procedimento** é o exemplo concreto de uso de uma técnica/sub-técnica — mostra qual ferramenta/software específico foi utilizado na implementação real daquela técnica. É a ponte entre a teoria (técnica) e a prática observada (o que um grupo/malware específico realmente fez).

**Exemplo prático:** para a técnica "OS Credential Dumping" (T1003), um procedimento documentado mostra que o grupo APT usou a ferramenta *Mimikatz* especificamente para realizar aquele dump de credenciais — o procedimento é o "como, na prática, com qual ferramenta", não apenas "o quê, em teoria".

---

## 7. Mitigações

**Mitigação** é a medida/ação que pode ser tomada em resposta a uma técnica do ATT&CK. Cada mitigação tem **ID único, nome e descrição** próprios, assim como as técnicas.

| Matriz | Snapshot original (2023) | Snapshot atual (v19) |
|---|---|---|
| Enterprise | 43 mitigações | 44 mitigações |
| Mobile | 11 mitigações | 13 mitigações |
| ICS | 51 mitigações | 52 mitigações |

Links:
- Enterprise: https://attack.mitre.org/mitigations/enterprise/
- Mobile: https://attack.mitre.org/mitigations/mobile/
- ICS: https://attack.mitre.org/mitigations/ics/

**Exemplo prático:** a mitigação "Multi-factor Authentication" (M1032) é referenciada em dezenas de técnicas de Credential Access e Lateral Movement — ela por si só reduz drasticamente a eficácia de técnicas que dependem apenas de uma credencial roubada/reutilizada.

---

## 8. Grupos (APT Groups)

**APT (Advanced Persistent Threat) Groups** são grupos de hackers — muitas vezes com apoio governamental — que realizam ataques cibernéticos de forma direcionada e sistemática, com motivações variadas: missão específica, financeira, ou alinhada a interesses de um governo estrangeiro.

O ATT&CK coleta informação sobre esses grupos para ajudar a identificar **qual grupo mira quais sistemas** e **quais técnicas ele emprega** — cruzando isso com a matriz, é possível reconstruir o "mapa de ataque" característico daquele grupo.

Cada grupo tem **Group ID, Nome e Descrição** únicos, além de uma listagem das técnicas e do software que o grupo é conhecido por usar.

**Exemplo prático:** o grupo **Lazarus Group** tem página própria no ATT&CK listando as técnicas empregadas historicamente e o software associado a ele — útil quando uma investigação encontra indicadores que "batem" com esse grupo, permitindo prever prováveis próximos passos do atacante com base no padrão histórico documentado.

Link: https://attack.mitre.org/groups/ — a contagem de grupos catalogados também cresce a cada release (o material original de 2023 registrava 135; o total já passou de 170 em releases recentes — confira o número vigente no link).

---

## 9. Software

**Software** no ATT&CK são os programas — malware, ferramentas de pentest, utilitários duplo-uso — usados pelos grupos APT para executar técnicas. Cada entrada tem **ID, nome e descrição** únicos.

A página de cada software detalha **quais técnicas** ele implementa e **quais grupos** o utilizam — é a peça que fecha o triângulo Grupo ↔ Software ↔ Técnica.

**Exemplo prático:** a página do software **"3PARA RAT"** mostra exatamente quais técnicas esse RAT (Remote Access Trojan) implementa e quais grupos APT são conhecidos por utilizá-lo — se esse RAT aparecer em uma análise de malware (ver [Email Forensics](../Rede-e-Email/Email%20Forensics.md) seção de anexos, ou [Android Forensics](../Mobile/Android%20Forensics.md) seção de APK malicioso), a página do ATT&CK já entrega de graça uma lista de técnicas esperadas para correlacionar com os achados.

Link: https://attack.mitre.org/software/ — o catálogo já ultrapassa 700 entradas de software e continua crescendo.

---

## 10. Tópicos Complementares

> [!info] Sobre esta seção
> O material original para na estrutura estática do framework (Matrizes, Táticas, Técnicas, Mitigações, Grupos, Software). Faltam duas coisas: objetos mais recentes do próprio ATT&CK que já fazem parte da versão atual, e — mais importante para o dia a dia — **como efetivamente usar isso** em uma investigação real.

### 10.1 Campaigns (Campanhas) — objeto mais recente

Além de Grupos e Software, o ATT&CK passou a catalogar **Campaigns**: uma campanha é um conjunto de atividades de intrusão realizadas ao longo de um período específico, com objetivos e vítimas em comum — diferente de um Grupo (entidade duradoura) ou Software (ferramenta reutilizável), uma Campaign é um **evento delimitado no tempo**. Na v19 (abril de 2026) o framework já cataloga dezenas de campanhas documentadas entre os três domínios.

### 10.2 Detection Strategies, Analytics e Data Components

Releases recentes do ATT&CK vêm expandindo além de "o que o atacante faz" para "como detectar isso":

- **Data Components**: fontes/tipos de dado necessários para detectar uma técnica (ex.: "Process Creation", "Network Traffic Flow").
- **Analytics**: lógicas de detecção específicas construídas em cima desses Data Components.
- **Detection Strategies**: agrupamento de Analytics em uma estratégia coerente de detecção para uma técnica.

Esse é o motivo pelo qual ferramentas de SIEM/XDR (incluindo Cortex XSIAM) conseguem hoje sugerir *quais fontes de log* são necessárias para detectar uma técnica específica — a resposta já vem modelada dentro do próprio ATT&CK.

### 10.3 ATT&CK Navigator — a ferramenta prática do dia a dia

O **ATT&CK Navigator** é uma ferramenta web que permite anotar e visualizar a matriz — colorindo/marcando células conforme critérios definidos pelo analista.

**Exemplo prático de uso em SOC:**
1. Durante/após uma investigação, o analista marca no Navigator todas as técnicas observadas no incidente (ex.: T1566.001, T1059.001, T1547.001).
2. Exporta essa seleção como uma **layer** (arquivo JSON) — um "mapa de calor" do ataque.
3. Compartilha a layer com o time — cada pessoa abre o mesmo JSON no Navigator e enxerga visualmente a cobertura do ataque na matriz.
4. Comparando layers de vários incidentes ao longo do tempo, dá pra identificar **quais táticas/técnicas se repetem** no seu ambiente — dado valioso para priorizar detecção e hardening.

### 10.4 Exemplo prático — mapeando um incidente completo

Cenário: um usuário recebe um e-mail de phishing com anexo malicioso (ver [Email Forensics](../Rede-e-Email/Email%20Forensics.md)), abre o documento, uma macro executa PowerShell, o atacante ganha persistência, faz dump de credenciais, se move lateralmente via RDP e exfiltra dados via HTTPS.

| Etapa observada | Tática | Técnica (exemplo de ID) |
|---|---|---|
| E-mail com anexo malicioso | Initial Access (TA0001) | Phishing: Spearphishing Attachment (T1566.001) |
| Macro executa comando | Execution (TA0002) | Command and Scripting Interpreter: PowerShell (T1059.001) |
| Chave de registro criada para reiniciar o malware no boot | Persistence (TA0003) | Boot or Logon Autostart Execution: Registry Run Keys (T1547.001) |
| Dump de credenciais do LSASS | Credential Access (TA0006) | OS Credential Dumping (T1003) |
| Uso das credenciais para acessar outro host via RDP | Lateral Movement (TA0008) | Remote Services: Remote Desktop Protocol (T1021.001) |
| Dados enviados para fora via canal HTTPS | Exfiltration (TA0010) | Exfiltration Over C2 Channel (T1041) |

> [!tip] Por que mapear assim ajuda
> Uma vez que o incidente vira uma sequência de IDs ATT&CK, ele passa a ser **comparável** com outros incidentes (seus e da indústria), **pesquisável** (você consegue procurar "quem mais usou T1547.001 + T1021.001 juntos") e **acionável** (cada técnica tem mitigações e detecções já catalogadas — seções 7 e 10.2).

### 10.5 D3FEND — o "espelho defensivo" do ATT&CK

O **MITRE D3FEND** é um framework irmão, focado em **técnicas defensivas** (ex.: "Process Spawn Analysis", "File Analysis") mapeadas explicitamente contra as técnicas ofensivas do ATT&CK. Enquanto o ATT&CK responde "o que o atacante faz", o D3FEND responde "o que o defensor pode implementar tecnicamente para lidar com isso" — útil quando a mitigação do ATT&CK (seção 7) é genérica demais e você precisa de algo mais próximo de uma especificação técnica de controle.

### 10.6 ATT&CK x Cyber Kill Chain — não são a mesma coisa

| | Cyber Kill Chain (Lockheed Martin) | MITRE ATT&CK |
|---|---|---|
| Estrutura | Linear, 7 fases fixas, sequenciais | Matriz, táticas não-lineares (atacante pode pular etapas ou repetir) |
| Nível de detalhe | Alto nível, conceitual | Extremamente granular (centenas de técnicas/sub-técnicas) |
| Base | Modelo teórico | Comportamento documentado em ataques reais observados |
| Uso típico | Comunicação executiva, visão geral do ciclo de ataque | Detecção, threat hunting, red/purple team, mapeamento técnico |

Não são concorrentes — muitos times usam a Kill Chain para contar a história do incidente em alto nível para stakeholders, e o ATT&CK para o trabalho técnico de detecção e resposta.

### 10.7 Versionamento do ATT&CK

O catálogo usa esquema **major.minor** (ex.: v18.1, v19.0). Releases major (como a v19 discutida na seção 5.1) podem trazer mudanças estruturais — novas táticas, técnicas revogadas/renomeadas (`revoked by`). Antes de reportar formalmente um mapeamento ATT&CK, vale checar o changelog oficial para garantir que os IDs usados ainda são válidos na versão vigente: https://attack.mitre.org/resources/changelog.html

---

## 11. Metodologia de Uso no SOC (Checklist)

> [!todo] Como usar
> Sequência sugerida para incorporar o ATT&CK no fluxo de trabalho de detecção/resposta a incidentes.

- [ ] Ao investigar um incidente, mapear cada ação observada do atacante para Tática + Técnica (e sub-técnica, quando o nível de detalhe do log permitir)
- [ ] Registrar os IDs (não só o nome) — IDs são estáveis para busca/comparação futura
- [ ] Verificar se a técnica tem sub-técnica mais específica antes de mapear no nível genérico
- [ ] Consultar a página da técnica para mitigações e detecções já catalogadas
- [ ] Se houver indicadores de um grupo/software conhecido, checar a página correspondente para antecipar próximos passos prováveis
- [ ] Exportar o mapeamento como layer no ATT&CK Navigator para documentação e compartilhamento
- [ ] Comparar com layers de incidentes anteriores para identificar padrões recorrentes no ambiente
- [ ] Ao propor uma nova regra de detecção, verificar se a técnica-alvo já tem Detection Strategy/Analytics publicados (seção 10.2) como ponto de partida
- [ ] Sempre confirmar IDs/contagens contra a versão vigente do site oficial antes de formalizar em relatório

---

## 12. Cheatsheet de Referência Rápida

**Convenção de IDs:**
```
TA####      → Tática               (ex.: TA0001 = Initial Access)
T####       → Técnica               (ex.: T1566 = Phishing)
T####.###   → Sub-técnica           (ex.: T1566.001 = Spearphishing Attachment)
M####       → Mitigação             (ex.: M1032 = Multi-factor Authentication)
G####       → Grupo                 (ex.: página de grupo APT)
S####       → Software              (ex.: página de malware/ferramenta)
```

**Táticas Enterprise (ordem da matriz, pré/pós-v19 — ver seção 5.1 para o split de TA0005):**
```
Reconnaissance → Resource Development → Initial Access → Execution →
Persistence → Privilege Escalation → Defense Evasion (Stealth / Defense Impairment) →
Credential Access → Discovery → Lateral Movement → Collection →
Command and Control → Exfiltration → Impact
```

**Links essenciais:**
```
Matrizes:     attack.mitre.org/matrices/{enterprise|mobile|ics}/
Táticas:      attack.mitre.org/tactics/{enterprise|mobile|ics}/
Técnicas:     attack.mitre.org/techniques/{enterprise|mobile|ics}/
Mitigações:   attack.mitre.org/mitigations/{enterprise|mobile|ics}/
Grupos:       attack.mitre.org/groups/
Software:     attack.mitre.org/software/
Navigator:    mitre-attack.github.io/attack-navigator/
Changelog:    attack.mitre.org/resources/changelog.html
```

---

## Ver também
- [DFIR com EDR](../Deteccao-e-Resposta/DFIR%20com%20EDR.md)
- [Cyber Kill Chain](Cyber%20Kill%20Chain.md)
- [Malware](Malware.md)
- [Network Forensics](../Rede-e-Email/Network%20Forensics.md)
- [Email Forensics](../Rede-e-Email/Email%20Forensics.md)
- [Android Forensics](../Mobile/Android%20Forensics.md)
- [Forense Digital em Windows](../Windows/Forense%20Digital%20em%20Windows.md)
- [DFIR em Linux](../Linux/DFIR%20em%20Linux.md)
