---
tags: [DFIR, CyberKillChain, SOC, ThreatIntel, BlueTeam]
status: estudo em andamento
---

# Cyber Kill Chain

> [!info] Sobre esta nota
> Cyber Kill Chain e [MITRE ATT&CK](MITRE%20ATT%26CK.md) respondem à mesma pergunta — "em que fase do ataque estamos?" — em dois níveis de resolução diferentes. A Kill Chain é a versão em 7 fases lineares, boa para contar a história do incidente para um stakeholder não-técnico ou para estruturar uma resposta rápida. O ATT&CK é a versão granular, com centenas de técnicas mapeadas por ID. Esta nota cobre as 7 fases da Kill Chain com ações típicas de ataque e defesa em cada uma, e na seção de tópicos complementares mostra como as duas abordagens se encaixam (e onde a Kill Chain quebra).

## Sumário
1. [O que é a Lockheed Martin](#1-o-que-é-a-lockheed-martin)
2. [O que é o Cyber Kill Chain](#2-o-que-é-o-cyber-kill-chain)
3. [Importância para o Analista SOC](#3-importância-para-o-analista-soc)
4. [As 7 Etapas — Visão Geral](#4-as-7-etapas--visão-geral)
5. [Etapa 1: Reconnaissance](#5-etapa-1-reconnaissance)
6. [Etapa 2: Weaponization](#6-etapa-2-weaponization)
7. [Etapa 3: Delivery](#7-etapa-3-delivery)
8. [Etapa 4: Exploitation](#8-etapa-4-exploitation)
9. [Etapa 5: Installation](#9-etapa-5-installation)
10. [Etapa 6: Command and Control (C2)](#10-etapa-6-command-and-control-c2)
11. [Etapa 7: Actions on Objectives](#11-etapa-7-actions-on-objectives)
12. [Tópicos Complementares](#12-tópicos-complementares)
13. [Metodologia de Uso no SOC (Checklist)](#13-metodologia-de-uso-no-soc-checklist)
14. [Cheatsheet de Referência Rápida](#14-cheatsheet-de-referência-rápida)

---

## 1. O que é a Lockheed Martin

**Lockheed Martin**, fundada em 1995, é uma corporação de segurança e aeroespacial que pesquisa, desenvolve, projeta e produz sistemas tecnológicos avançados — foi dentro dessa empresa que o modelo Cyber Kill Chain nasceu, adaptando o conceito militar de "kill chain" (a sequência de etapas para identificar e neutralizar um alvo) para o contexto de ataques cibernéticos.

## 2. O que é o Cyber Kill Chain

O **Cyber Kill Chain** é um framework criado pela Lockheed Martin em **2011** para modelar o comportamento de atacantes. Divide todo o processo de um ataque cibernético em **7 etapas sequenciais**.

Página oficial: https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html

> [!tip] O conceito central
> As etapas são **sequenciais e dependentes** — se o atacante falha em uma etapa, ele não consegue avançar para a próxima. É exatamente esse encadeamento que dá nome ao framework: **quebrar um único elo da corrente já é suficiente para impedir o ataque** (ver seção 12.2).

## 3. Importância para o Analista SOC

O Cyber Kill Chain ajuda o analista SOC a:

- Entender melhor **em que estágio** um ataque observado se encontra.
- Determinar **com qual ação o ataque começou** e quais ações provavelmente vêm a seguir.
- Analisar onde, na cadeia, as ações do atacante notadas nos sistemas efetivamente ocorrem.
- Ajudar a organização a identificar **onde e quão graves** são as falhas de segurança expostas.
- Dar ao Blue Team uma estrutura para identificar **áreas com controles insuficientes** e agir sobre elas.

---

## 4. As 7 Etapas — Visão Geral

| # | Etapa | Pergunta que responde |
|---|---|---|
| 1 | **Reconnaissance** | O que o atacante sabe sobre o alvo? |
| 2 | **Weaponization** | Como o atacante preparou a arma do ataque? |
| 3 | **Delivery** | Como a arma chega até a vítima? |
| 4 | **Exploitation** | Como a arma é ativada no sistema alvo? |
| 5 | **Installation** | Como o atacante garante persistência? |
| 6 | **Command & Control (C2)** | Como o atacante controla remotamente o sistema comprometido? |
| 7 | **Actions on Objectives** | O que o atacante realmente veio fazer? |

---

## 5. Etapa 1: Reconnaissance

O atacante tenta obter informação sobre o sistema alvo. Quanto mais conhecimento sobre o alvo, maior a superfície de ataque percebida — é aqui que os vetores de ataque possíveis são descobertos.

Duas subcategorias de técnica:

- **Reconhecimento Passivo**: coleta de informação de fontes externas **sem interagir diretamente** com o sistema alvo. Ex.: consultar sites de arquivo web (Wayback Machine) para ver conteúdo que já saiu do site oficial do alvo.
- **Reconhecimento Ativo**: obtenção de informação **interagindo diretamente** com o sistema alvo. Ex.: enviar uma requisição a um servidor web e extrair a versão do software a partir da resposta (banner grabbing).

### Adversário
- Obter versão de servidores e softwares do alvo
- Obter informação de fontes abertas já publicadas sobre o alvo
- Obter e-mails de funcionários da organização
- Obter informação pessoal/interna de funcionários via redes sociais
- Detectar dispositivos conectados à internet pertencentes ao alvo
- Detectar vulnerabilidades em servidores expostos à internet
- Identificar o bloco de IP da organização
- Identificar fornecedores com os quais a organização coopera

### Defensor
- Detectar áreas de exposição de informação via pentest externo
- Obter informação de vazamento da organização via fontes de Threat Intelligence
- Não manter documentos com informação organizacional disponíveis publicamente na internet
- Monitorar tráfego instalando soluções de segurança (firewall) nas áreas expostas à internet
- Atualizar sistemas prontamente para evitar exploração de vulnerabilidades novas

**Exemplo prático — reconhecimento passivo e ativo básico:**
```bash
# Passivo — OSINT sem tocar no alvo
whois exemplo.com
theHarvester -d exemplo.com -b google,linkedin      # e-mails e subdomínios públicos

# Ativo — interage diretamente com o alvo
curl -I https://exemplo.com                          # banner grabbing via headers HTTP
nmap -sV alvo.exemplo.com                             # versão de serviços expostos
```

> [!warning] Onde o defensor entra em jogo
> Boa parte do reconhecimento ativo (scans de porta, requisições incomuns) **gera tráfego detectável**. É por isso que monitoramento de borda (firewall, IDS/IPS — ver [Network Forensics](../Rede-e-Email/Network%20Forensics.md)) e alertas de scanning são o primeiro ponto de detecção possível — muito antes do ataque de fato começar.

---

## 6. Etapa 2: Weaponization

O atacante usa a informação obtida na etapa anterior para **acessar ou desenvolver a ferramenta** necessária para o ataque. A preparação varia conforme o tipo de ataque planejado — para phishing, pode ser um exploit construído para uma vulnerabilidade conhecida, ou conteúdo malicioso de e-mail. Se as ferramentas já estão prontas, essa etapa é rápida.

> [!info] Ponto-chave
> Nessa etapa **o ataque ainda não começou** e a vítima normalmente não tem qualquer conhecimento do atacante — tudo acontece do lado do atacante, fora da vista da organização-alvo.

### Adversário
- Criar malware
- Desenvolver exploits
- Criar conteúdo malicioso para uso em phishing (template de e-mail, documento malicioso)
- Identificar o melhor instrumento para o ataque planejado

### Defensor
- Verificar regularmente se vulnerabilidades conhecidas existem nos próprios sistemas
- Instalar atualizações de segurança o quanto antes
- Analisar o impacto de ferramentas de ataque conhecidas/novas, acompanhando sua evolução, para detectar quando forem utilizadas

> [!danger] Limitação estrutural desta etapa
> Diferente das outras seis, o Blue Team **não tem visibilidade direta** sobre a Weaponization — ela acontece na infraestrutura do atacante. As únicas alavancas são indiretas: reduzir a superfície explorável (patching) e acompanhar threat intel sobre ferramentas/exploits em circulação para os quais sua organização pode ser um alvo.

---

## 7. Etapa 3: Delivery

O atacante executa o ataque preparado nas fases anteriores — é a etapa da **primeira interação real com a vítima**. Por exemplo, o malware é hospedado em algum ambiente e a vítima o baixa; ou o conteúdo malicioso é entregue diretamente por e-mail.

### Adversário
- Entregar URL maliciosa via e-mail
- Entregar malware como anexo de e-mail
- Entregar malware via site
- Entregar URL maliciosa via rede social
- Entregar malware via rede social
- Enviar o malware diretamente ao servidor alvo (se houver acesso direto)
- Instalar/habilitar malware fisicamente via dispositivo USB

### Defensor
- Adotar postura cética com URLs em e-mails, visualizando-as em ambiente sandbox
- Escanear anexos de e-mail com antivírus
- Usar soluções de segurança de e-mail corporativas
- Treinar usuários/colaboradores em segurança da informação
- Monitorar constantemente acesso a servidores e registrar logs
- Usar e gerenciar efetivamente soluções como firewall
- Realizar análise detalhada de atividades suspeitas quando necessário
- Detectar anomalias e determinar a causa raiz

> [!tip] Ligação com este vault
> Todo o fluxo de análise de anexo/link malicioso já coberto em [Email Forensics](../Rede-e-Email/Email%20Forensics.md) (seções de header, corpo e anexo) é exatamente o trabalho de investigar **esta etapa específica** da Kill Chain — é o ponto onde a maioria dos incidentes corporativos realmente começa a virar caso.

---

## 8. Etapa 4: Exploitation

O atacante garante que o conteúdo malicioso entregue na etapa anterior **seja ativado**. É aqui que o malware entregue à vítima é efetivamente executado — a primeira operação do atacante dentro do sistema. Se o exploit falhar aqui, as fases seguintes não acontecem.

### Adversário
- Executar exploit que abusa de vulnerabilidade de hardware
- Executar exploit que abusa de vulnerabilidade de software/SO
- Rodar o malware

### Defensor
- Treinar colaboradores sobre quando é/não é seguro abrir um arquivo recebido
- Monitorar constantemente segurança dos ativos e detectar anomalias
- Rastrear vulnerabilidades publicadas para os ativos da organização, escrever regra de monitoramento e detectar exploração
- Aplicar atualizações de segurança imediatamente
- Monitorar endpoints com EDR
- Treinar desenvolvedores em codificação segura (para prevenir vulnerabilidades em apps internas)
- Realizar pentests regulares nos ativos
- Realizar scans de vulnerabilidade automatizados e monitorar os relatórios
- Organizar autorizações — cada conta com o privilégio mínimo necessário

> [!danger] Por que essa etapa é a mais difícil de defender
> É a etapa com maior chance de envolver **malware ou exploit nunca visto antes** (0-day) — a defesa baseada em assinatura (Snort/Suricata, ver [Network Forensics](../Rede-e-Email/Network%20Forensics.md)) simplesmente não tem o que comparar. É por isso que controles de **redução de superfície** (patching, privilégio mínimo, EDR comportamental) pesam mais aqui do que detecção baseada em assinatura.

---

## 9. Etapa 5: Installation

O atacante tenta **garantir persistência** no sistema explorado. Como a vulnerabilidade explorada será eventualmente corrigida, o atacante precisa de um caminho de acesso independente dela — geralmente via backdoor. O malware final também pode ser colocado com a ajuda de um **dropper**. Nesta fase o atacante também pode buscar escalar privilégio para uma conta de alta autoridade, de forma a garantir a persistência.

### Adversário
- Instalar malware no dispositivo da vítima
- Colocar um backdoor no sistema
- Instalar web shell no servidor web (se aplicável)
- Adicionar serviço, regra de firewall ou tarefa agendada para garantir persistência

> [!info] O atacante quer ser invisível aqui
> Nesta etapa o atacante tenta deixar **o mínimo de rastro possível** e evitar interferência de produtos de segurança — o objetivo é permanecer despercebido pelo maior tempo possível para ter tempo de executar o ataque completo.

### Defensor
As ações do Blue Team aqui são essencialmente as de **Threat Hunting**. Se o atacante chegou até esta fase, por definição ele não foi detectado ainda — por isso a postura recomendada é **assumir presença de atacante (assume breach)** e operar a segurança com essa premissa, independentemente de haver ou não indício confirmado.

- Realizar Network Security Monitoring em todos os ativos
- Usar EDR para estar ciente de mudanças de configuração em cada endpoint
- Restringir e monitorar acesso a arquivos críticos
- Restringir e monitorar acesso a caminhos críticos do sistema
- Permitir uso de privilégio admin apenas quando estritamente necessário
- Detectar atividade maliciosa de processo monitorando processos em execução
- Permitir execução apenas de executáveis com assinatura válida
- Detectar anomalias em toda atividade monitorada e investigar a causa raiz

**Exemplo prático — persistência clássica via chave de registro (Windows):**
```
Registry Run Key:
HKCU\Software\Microsoft\Windows\CurrentVersion\Run\UpdaterService = "C:\Users\Public\svchost_update.exe"
```
No ATT&CK, isso mapeia diretamente para **T1547.001 (Boot or Logon Autostart Execution: Registry Run Keys)** — ver [MITRE ATT&CK](MITRE%20ATT%26CK.md) seção 10.4 para o mapeamento completo de um incidente.

---

## 10. Etapa 6: Command and Control (C2)

O atacante já completou etapas críticas do ataque e prepara o **servidor C2** para enviar comandos ao sistema comprometido. A partir daqui, é possível enviar comandos remotos e executá-los.

### Adversário
Nesta etapa, o que o atacante faz é **estabelecer o contato** entre o C2 e o sistema alvo — ainda não executa as ações-fim planejadas (isso vem na etapa 7):

- Configurar o servidor C2 para se comunicar com a vítima
- Implementar as ações necessárias no dispositivo da vítima para viabilizar esse contato

### Defensor
Não há uma ação exclusiva de Blue Team só para esta etapa — o que se aplica é monitoramento e detecção geral no contexto de comunicação C2:

- Verificar se ferramentas de C2 conhecidas estão presentes nos sistemas
- Bloquear IPs de servidores C2 conhecidos (via Cyber Threat Intelligence) em firewall
- Detectar tráfego de rede que possa ser comunicação C2 via Network Security Monitoring

> [!tip] Ligação com este vault
> A detecção de **beaconing** (comunicação periódica e regular com um IP externo) já coberta em [Network Forensics](../Rede-e-Email/Network%20Forensics.md) (seção de NetFlow/anomalias de protocolo) é exatamente a técnica de detecção mais usada nesta etapa — um host "conversando" com o mesmo IP externo em intervalos regulares e previsíveis é a assinatura clássica de C2.

---

## 11. Etapa 7: Actions on Objectives

A etapa final — o atacante executa as ações planejadas desde o início do ataque. Chegar até aqui significa que **todas as seis etapas anteriores foram bem-sucedidas**.

### Adversário
As ações variam conforme o objetivo/motivação do atacante:

- Criptografar arquivos com ransomware
- Exfiltrar informação/documentos críticos
- Danificar o sistema deletando informação crítica
- Escalar privilégio para expandir o ataque a outras máquinas da rede
- Coletar credenciais de usuário para acessar outro dispositivo
- Coletar informação dentro do sistema
- Alterar ou manipular informação no sistema

### Defensor
As ações aqui variam bastante conforme o processo específico, mas o ponto mais fundamental é **impedir a exfiltração de dados** — vazamento de dados é um dos desfechos mais comuns de ataques hoje.

- Detectar anomalias no tráfego de rede
- Restringir e monitorar continuamente o acesso de saída à internet
- Restringir e controlar regularmente acesso a arquivos/pastas com informação crítica
- Restringir autorização de acesso a bancos de dados críticos e monitorar continuamente
- Usar produtos DLP para prevenir vazamento de dados
- Detectar acesso não autorizado de usuários

> [!danger] Esta é a etapa mais cara de conter
> Quanto mais tarde na cadeia o ataque é detectado, mais caro e complexo é o dano — na etapa 7 você já está lidando com **ransomware ativo ou dados já em rota de exfiltração**, não mais prevenção. É exatamente por isso que a filosofia da Kill Chain empurra o investimento defensivo para **as etapas mais cedo possível** (seção 12.2).

---

## 12. Tópicos Complementares

> [!info] Sobre esta seção
> O material original explica muito bem cada etapa isoladamente. O que falta é amarrar tudo: um exemplo de ponta a ponta, a lógica estratégica por trás do modelo, e uma visão crítica — porque a Kill Chain, apesar de extremamente didática, tem limitações reais que todo analista deveria conhecer antes de usá-la como única ferramenta.

### 12.1 Exemplo prático completo — ataque de ransomware mapeado nas 7 etapas

| Etapa | O que acontece no cenário |
|---|---|
| **1. Reconnaissance** | Atacante identifica, via LinkedIn e um scan superficial, que a empresa usa um VPN gateway desatualizado e tem um funcionário do financeiro ativo publicamente |
| **2. Weaponization** | Atacante prepara um documento Excel com macro maliciosa, referenciando um exploit conhecido para o VPN gateway como plano B |
| **3. Delivery** | E-mail de phishing direcionado ("spear phishing") é enviado ao funcionário do financeiro, com o Excel malicioso anexado |
| **4. Exploitation** | Funcionário abre o anexo, habilita a macro, o VBA executa um comando PowerShell ofuscado |
| **5. Installation** | PowerShell cria uma chave de registro Run Key e instala um backdoor leve para sobreviver a reboot |
| **6. Command & Control** | O backdoor estabelece beaconing periódico (a cada 60s) para um domínio de C2 recém-registrado |
| **7. Actions on Objectives** | Atacante usa o C2 para mapear a rede interna, escalar privilégio, mover lateralmente até o file server e finalmente implantar ransomware, criptografando os compartilhamentos críticos |

> [!tip] Onde quebrar essa cadeia teria sido mais barato
> Bloquear a macro na etapa 4 (política de macro desabilitada por padrão) ou detectar o beaconing na etapa 6 (Network Security Monitoring) custam uma fração do esforço — em tempo, dinheiro e dano reputacional — de responder a um ransomware já ativo na etapa 7.

### 12.2 "Break the Kill Chain" — a lógica estratégica do modelo

O princípio central por trás do framework: **como as 7 etapas são sequenciais e dependentes, basta quebrar UMA delas para neutralizar todo o ataque.** Isso muda como o Blue Team prioriza investimento defensivo — em vez de tentar ser perfeito em todas as camadas, o objetivo é ter **pelo menos um controle eficaz em cada etapa**, formando redundância defensiva (defense in depth).

| Princípio | O que significa na prática |
|---|---|
| **Detect** | Consigo perceber que essa etapa está acontecendo? |
| **Deny** | Consigo impedir que essa etapa aconteça? |
| **Disrupt** | Consigo interromper a comunicação/fluxo de dados dessa etapa? |
| **Degrade** | Consigo limitar o quanto essa etapa avança/quanto dano causa? |
| **Deceive** | Consigo enganar o atacante (honeypot, dados falsos) nessa etapa? |
| **Contain** | Se tudo mais falhar, consigo limitar o raio de impacto? |

> [!info] Origem desses 6 verbos
> Esse modelo de 6 ações (**"Course of Action Matrix"**) é o complemento tático que a própria Lockheed Martin publicou junto com a Kill Chain original — cruzando as 7 etapas com essas 6 ações, você obtém uma matriz de 42 células que ajuda a mapear exatamente **onde há lacuna de controle** em cada etapa do ataque.

### 12.3 Cyber Kill Chain x MITRE ATT&CK — recapitulando

Já coberto em detalhe em [MITRE ATT&CK](MITRE%20ATT%26CK.md) (seção 10.6), mas o resumo essencial: a Kill Chain é **linear e de alto nível** (boa para storytelling executivo), o ATT&CK é uma **matriz granular e não-linear** (boa para detecção técnica). Muitos times mapeiam um incidente nas duas — a Kill Chain para o resumo do relatório, o ATT&CK para o detalhamento técnico linha a linha.

### 12.4 Unified Kill Chain — a tentativa de unir os dois modelos

O **Unified Kill Chain**, proposto por Paul Pols em 2017, tenta resolver a maior crítica à Kill Chain original (ver 12.5) combinando-a com elementos do ATT&CK em uma cadeia de **18 fases**, agrupadas em três blocos:

- **In (invasão inicial)**: reconhecimento, entrega, exploração — similar às primeiras etapas da Kill Chain clássica.
- **Through (atravessar o ambiente)**: persistência, escalonamento de privilégio, movimentação lateral, coleta — fases que a Kill Chain original comprime demais dentro de "Installation" e "C2".
- **Out (atingir o objetivo)**: exfiltração, impacto — equivalente a "Actions on Objectives", mas detalhado.

> [!tip] Quando vale a pena conhecer isso
> Se sua organização já mapeia incidentes no ATT&CK e sente que a Kill Chain de 7 etapas "simplifica demais" o meio do ataque (especialmente movimentação lateral em rede corporativa), o Unified Kill Chain é o ponto intermediário — mais granular que a Kill Chain, mais narrativo/sequencial que o ATT&CK puro.

### 12.5 Críticas ao modelo — o que a Kill Chain não cobre bem

| Limitação | Por quê importa |
|---|---|
| **Modelo linear** | Ataques reais frequentemente pulam etapas, repetem etapas (múltiplas tentativas de exploitation) ou seguem ordem diferente — a linearidade é uma simplificação didática, não uma regra física do ataque |
| **Foco em malware/perímetro** | Foi originalmente pensado para ataques externos entregando malware — cobre mal cenários de **insider threat** (o "atacante" já está dentro, sem precisar de Delivery/Exploitation) |
| **Fraco em ambientes cloud/SaaS** | Ataques que abusam de credenciais válidas em serviços cloud (sem malware algum) não se encaixam bem nas 7 etapas originais |
| **Não modela bem supply chain attacks** | Comprometer um fornecedor de software para atingir o alvo final foge do modelo linear de "um atacante, uma vítima" |

> [!warning] Como usar isso com bom senso
> A crítica não invalida o modelo — ele continua excelente como ferramenta didática e de comunicação. O ponto é **não tratá-lo como framework único**: para cobrir os cenários onde a Kill Chain é fraca (insider threat, cloud, supply chain), complemente com ATT&CK (mais granular) e, se necessário, com o Diamond Model (seção 12.6).

### 12.6 Diamond Model — outro framework complementar

O **Diamond Model of Intrusion Analysis** modela cada evento de intrusão como um diamante com 4 vértices conectados: **Adversário**, **Capacidade** (a ferramenta/técnica usada), **Infraestrutura** (de onde o ataque parte) e **Vítima**. Diferente da Kill Chain (foco temporal/sequencial) e do ATT&CK (foco comportamental/técnico), o Diamond Model foca em **relacionamentos** — é especialmente útil em threat intelligence para conectar campanhas diferentes ao mesmo ator, mesmo quando a infraestrutura ou a ferramenta mudou.

---

## 13. Metodologia de Uso no SOC (Checklist)

> [!todo] Como usar
> Sequência sugerida para aplicar a Kill Chain tanto na investigação de um incidente real quanto em um exercício de purple team preventivo.

- [ ] Ao investigar um incidente, identificar em qual das 7 etapas o comportamento observado se encaixa
- [ ] Reconstruir, etapa por etapa, o que já aconteceu e o que provavelmente vem a seguir
- [ ] Para cada etapa identificada, aplicar a matriz Detect/Deny/Disrupt/Degrade/Deceive/Contain e verificar qual ação já existia (ou faltou)
- [ ] Complementar o mapeamento de alto nível da Kill Chain com IDs específicos do [MITRE ATT&CK](MITRE%20ATT%26CK.md) para o relatório técnico
- [ ] Se o cenário envolve insider threat, cloud ou supply chain, não forçar o encaixe na Kill Chain clássica — considerar Unified Kill Chain ou ATT&CK puro
- [ ] Em exercícios de purple team, simular cada uma das 7 etapas isoladamente e validar se existe controle de detecção/prevenção correspondente
- [ ] Priorizar investimento defensivo nas etapas mais cedo na cadeia (Reconnaissance/Delivery/Exploitation) — quebrar ali é mais barato que conter na etapa 7
- [ ] Documentar lacunas encontradas e revisitar a matriz Course of Action periodicamente

---

## 14. Cheatsheet de Referência Rápida

**As 7 etapas, em ordem:**
```
1. Reconnaissance        → coleta de informação sobre o alvo
2. Weaponization          → preparo da arma/ferramenta de ataque
3. Delivery                → entrega da arma até a vítima
4. Exploitation            → ativação/execução da arma no sistema
5. Installation            → garantia de persistência
6. Command & Control (C2)  → canal de controle remoto estabelecido
7. Actions on Objectives   → execução do objetivo final do atacante
```

**Course of Action Matrix (6 verbos, aplicáveis a cada etapa):**
```
Detect · Deny · Disrupt · Degrade · Deceive · Contain
```

**Frameworks relacionados:**
```
MITRE ATT&CK        → granular, matriz não-linear (ver nota própria)
Unified Kill Chain  → 18 fases, une Kill Chain + ATT&CK (Pols, 2017)
Diamond Model        → foco em relacionamento Adversário-Capacidade-Infraestrutura-Vítima
```

**Link oficial:**
```
lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html
```

---

## Ver também
- [DFIR com EDR](../Deteccao-e-Resposta/DFIR%20com%20EDR.md)
- [MITRE ATT&CK](MITRE%20ATT%26CK.md)
- [Malware](Malware.md)
- [Network Forensics](../Rede-e-Email/Network%20Forensics.md)
- [Email Forensics](../Rede-e-Email/Email%20Forensics.md)
- [Android Forensics](../Mobile/Android%20Forensics.md)
- [Forense Digital em Windows](../Windows/Forense%20Digital%20em%20Windows.md)
- [DFIR em Linux](../Linux/DFIR%20em%20Linux.md)
