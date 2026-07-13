# Forense Digital — Anotações de Estudo

Anotações pessoais de estudo em **Forense Digital / DFIR (Digital Forensics and Incident Response)**, organizadas por tema. Parte da trilha [SOC-Carreira](../).

> [!info] Sobre este repositório
> As notas foram escritas originalmente no Obsidian (callouts `> [!tip]`, `> [!warning]`, etc. e frontmatter YAML). No GitHub, os callouts aparecem como blockquotes normais — o conteúdo continua 100% legível, só perde a cor/ícone que o Obsidian adiciona.

---

## Estrutura

```
Forense/
├── Fundamentos/
│   └── Arquitetura de Computadores para Forense Digital.md
├── Anti-Forense/
│   ├── Anti-Forense e Ofuscação de Dados.md
│   └── Ring0 - Escalonamento de Privilégio e EDR.md
├── Rede-e-Email/
│   ├── Network Forensics.md
│   └── Email Forensics.md
├── Deteccao-e-Resposta/
│   └── DFIR com EDR.md
├── Windows/
│   ├── Forense Digital em Windows.md
│   └── Forense de Memória em Windows.md
├── Linux/
│   ├── DFIR em Linux.md
│   └── Forense de Memória em Linux.md
├── Mobile/
│   ├── Android Forensics.md
│   └── iOS Forensics.md
├── Threat-Intel/
│   ├── Cyber Kill Chain.md
│   ├── MITRE ATT&CK.md
│   └── Malware.md
└── README.md
```

---

## Mapa de conteúdo

### 📐 Fundamentos
| Nota | Conteúdo |
|---|---|
| [Arquitetura de Computadores para Forense Digital](Fundamentos/Arquitetura%20de%20Computadores%20para%20Forense%20Digital.md) | Base conceitual de tudo o resto: CPU, registradores, cache, hierarquia de memória, kernel, rings de proteção (Ring 0 x Ring 3), boot process e a ordem de volatilidade (RFC 3227) explicada fisicamente — por que `psscan` acha o que `pslist` não acha, por que SSD com TRIM mata a recuperação de arquivos, por que capturar RAM antes do disco. |

### 🕵️ Anti-Forense
| Nota | Conteúdo |
|---|---|
| [Anti-Forense e Ofuscação de Dados](Anti-Forense/Anti-Forense%20e%20Ofuscação%20de%20Dados.md) | Técnicas usadas para dificultar/impedir investigação: mídia bootável, apps portáteis, esteganografia, criptografia (incl. ransomware), adulteração/destruição de logs, VPN/TOR/Proxy, artifact wiping — sempre com o padrão "como funciona → como é abusado → como detectar". |
| [Ring0 — Escalonamento de Privilégio e EDR](Anti-Forense/Ring0%20-%20Escalonamento%20de%20Privilégio%20e%20EDR.md) | Como malware chega a Ring 0 (exploits de kernel, BYOVD, drivers maliciosos), o que faz de lá (DKOM, syscall hooking, cegar EDR), detecção manual via Volatility, e como um EDR (Cortex XDR como exemplo) monitora esse nível. |

### 🌐 Rede e Email
| Nota | Conteúdo |
|---|---|
| [Network Forensics](Rede-e-Email/Network%20Forensics.md) | Captura (Wireshark/TCPdump), análise de tráfego (malware, insider threat, exfiltração), detecção por assinatura (Snort/Suricata/Zeek), NetFlow, análise de TLS/SSL, correlação com SIEM/XDR e MITRE ATT&CK. |
| [Email Forensics](Rede-e-Email/Email%20Forensics.md) | Protocolos (SMTP/IMAP/POP3), análise de header (Received, SPF/DKIM/DMARC), análise de corpo e anexos (estática, dinâmica/sandbox, assinatura), catálogo de ameaças (phishing, BEC, spoofing, whaling), formatos de arquivo (.eml/.msg/.pst/.mbox). |

### 🛡️ Detecção e Resposta
| Nota | Conteúdo |
|---|---|
| [DFIR com EDR](Deteccao-e-Resposta/DFIR%20com%20EDR.md) | EDR/EPP na prática de DFIR (detecção, coleta forense, resposta, análise contínua), configuração de detecção efetiva (Event IDs do Sysmon, regras customizadas, gestão de alertas), métodos e motores de detecção, passos de resposta a incidente, root cause analysis (subir cadeia de processo pai→filho), estudos de caso (ransomware, credential dumping, persistence), e tradução completa de cada conceito para Cortex XDR/XSIAM (BIOC/IOC/Correlation Rule, Causality Chain View, XQL de hunting). |

### 🪟 Windows
| Nota | Conteúdo |
|---|---|
| [Forense Digital em Windows](Windows/Forense%20Digital%20em%20Windows.md) | Aquisição e duplicação: ordem de volatilidade, cadeia de custódia, live data acquisition (RAM, rede, Event Logs, Registro), Sysinternals (Process Explorer, Autoruns, Sysmon), cópia forense (write blockers, E01/RAW/AFF), hashing. |
| [Forense de Memória em Windows](Windows/Forense%20de%20Memória%20em%20Windows.md) | Captura com FTK Imager e análise com Volatility3: pslist/psscan, netscan, registro (hivelist/hivescan), malfind, svcscan, hashdump — fluxo investigativo completo. |

### 🐧 Linux
| Nota | Conteúdo |
|---|---|
| [DFIR em Linux](Linux/DFIR%20em%20Linux.md) | Live response (processos, usuários, rede, histórico de shell), sistemas de arquivos (EXT2/3/4, XFS, Btrfs), imaging com `dd`/`dc3dd`, recuperação de arquivos deletados, arquivos de configuração (`/etc/passwd`, `sudoers`, `crontab`, `authorized_keys`, systemd). |
| [Forense de Memória em Linux](Linux/Forense%20de%20Memória%20em%20Linux.md) | Captura com LiME e análise com Volatility3: geração de ISF via `dwarf2json`, pslist/psscan, sockstat, `linux.bash` (bash history residente em memória), YARA scanning — fluxo investigativo completo. |

### 📱 Mobile
| Nota | Conteúdo |
|---|---|
| [Android Forensics](Mobile/Android%20Forensics.md) | Sistema de arquivos (EXT4, partições, FDE x FBE), identificação de dispositivo, bypass de bloqueio (ADB, MTP, Andriller), imagem física x lógica, artefatos-chave (SMS, WhatsApp, SQLite + WAL/journal), extração via `adb backup`, anti-forense no Android, análise de APKs maliciosos. |
| [iOS Forensics](Mobile/iOS%20Forensics.md) | Sistema de arquivos (HFS+ → APFS, App Sandbox), os três métodos de aquisição, backups criptografados do iTunes/Finder (brute force via Hashcat), dados do iCloud, estrutura do backup (Manifest.plist/Manifest.db), análise com a biblioteca Python `iOSbackup`, Keychain, timestamp em Mac Absolute Time. |

### 🎯 Threat Intelligence
| Nota | Conteúdo |
|---|---|
| [Cyber Kill Chain](Threat-Intel/Cyber%20Kill%20Chain.md) | As 7 etapas do modelo da Lockheed Martin (Reconnaissance → Actions on Objectives) com ações de ataque/defesa em cada uma, exemplo completo de ransomware mapeado, Course of Action Matrix, Unified Kill Chain, Diamond Model, e onde o modelo quebra (insider threat, cloud, supply chain). |
| [MITRE ATT&CK](Threat-Intel/MITRE%20ATT%26CK.md) | Estrutura do framework (Matrizes → Táticas → Técnicas/Sub-técnicas → Procedimentos → Mitigações → Grupos → Software), ATT&CK Navigator, D3FEND, mapeamento de um incidente completo passo a passo, e a divisão da tática Defense Evasion em Stealth/Defense Impairment na v19 (abril/2026). |
| [Malware](Threat-Intel/Malware.md) | Classificação (vírus, worm, trojan, ransomware, rootkit, RAT, fileless, wiper...), malware notável e threat actor groups (APT29, Lazarus, etc.), arquiteturas de C2 (central, P2P, randomizada), IOCs e regras YARA. |

---

## Trilha de leitura sugerida

1. **Fundamentos** — entender arquitetura antes de decorar comandos
2. **Windows ou Linux** (conforme o SO do seu foco) — aquisição/live response → memória
3. **Mobile** — o mesmo raciocínio de sistema de arquivos e aquisição, aplicado a dispositivos bloqueados/sandboxed
4. **Rede e Email** — a evidência que trafega *entre* hosts
5. **Detecção e Resposta** (DFIR com EDR) — a ferramenta que gera a telemetria usada nas fases 2–4 em tempo real, e como agir sobre um alerta do primeiro sinal até o relatório final
6. **Threat Intelligence** (Kill Chain, MITRE ATT&CK, Malware) — o vocabulário e os modelos que amarram tudo o que foi encontrado nas fases 1–5 em uma narrativa de ataque
7. **Anti-Forense** — como o que você aprendeu nos passos anteriores pode ser escondido de você, e como perceber isso

Cada nota tem uma seção **Ver também** no rodapé linkando as notas relacionadas — segue o fio a partir de qualquer ponto de entrada.

---

## Lacunas identificadas / possíveis próximos temas

Ao revisar o conteúdo, estes tópicos de DFIR ainda não têm nota dedicada no vault — candidatos naturais para expandir a trilha:

- **Timeline Analysis** (log2timeline/plaso, super timelines) — hoje só é citado de passagem como "próximo passo" nas notas de aquisição Windows/Linux
- **Forense em Nuvem** (AWS/Azure/GCP — logs de auditoria, CloudTrail, forense de containers)
- **Relatório e aspectos legais** (laudo pericial, cadeia de custódia formal em processo judicial, comunicação de achados)
- **Registro do Windows aprofundado** (hoje coberto de forma introdutória em duas notas — poderia virar nota própria com mais chaves e cenários)
- **Engenharia reversa de malware** (análise estática/dinâmica aprofundada, desofuscação, unpacking) — a nota [Malware](Threat-Intel/Malware.md) cobre classificação e threat intel, mas fica deliberadamente fora do escopo de reverse engineering profundo

---

## Convenções usadas nas notas

- **Frontmatter YAML**: `tags`, `status` (`estudo-ativo` ou `estudo em andamento`) e, nas notas mais antigas, `area: Blue Team / DFIR`
- **Callouts Obsidian**: `[!info]`, `[!tip]`, `[!warning]`, `[!danger]`, `[!example]`, `[!todo]` — renderizam como blockquote simples no GitHub
- **Links entre notas**: markdown padrão (`[Texto](caminho%20com%20espaços.md)`), não wikilinks `[[...]]` — funcionam tanto no GitHub quanto no Obsidian sem depender de resolução por nome de arquivo
- **Checklists** ao final de cada nota — uso prático em campo/investigação real
- **Ver também** — links cruzados entre notas relacionadas
