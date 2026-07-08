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
├── Windows/
│   ├── Forense Digital em Windows.md
│   └── Forense de Memória em Windows.md
├── Linux/
│   ├── DFIR em Linux.md
│   └── Forense de Memória em Linux.md
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

---

## Trilha de leitura sugerida

1. **Fundamentos** — entender arquitetura antes de decorar comandos
2. **Windows ou Linux** (conforme o SO do seu foco) — aquisição/live response → memória
3. **Rede e Email** — a evidência que trafega *entre* hosts
4. **Anti-Forense** — como o que você aprendeu nos passos 1–3 pode ser escondido de você, e como perceber isso

Cada nota tem uma seção **Ver também** no rodapé linkando as notas relacionadas — segue o fio a partir de qualquer ponto de entrada.

---

## Lacunas identificadas / possíveis próximos temas

Ao revisar o conteúdo, estes tópicos de DFIR ainda não têm nota dedicada no vault — candidatos naturais para expandir a trilha:

- **Timeline Analysis** (log2timeline/plaso, super timelines) — hoje só é citado de passagem como "próximo passo" nas notas de aquisição Windows/Linux
- **Análise de Malware dedicada** (estática/dinâmica, engenharia reversa básica, sandboxing) — hoje o assunto aparece espalhado em Email Forensics (anexos) e Ring0/EDR, mas sem nota própria
- **Forense Mobile** (Android/iOS — extração lógica/física, artefatos de apps)
- **Forense em Nuvem** (AWS/Azure/GCP — logs de auditoria, CloudTrail, forense de containers)
- **Relatório e aspectos legais** (laudo pericial, cadeia de custódia formal em processo judicial, comunicação de achados)
- **Registro do Windows aprofundado** (hoje coberto de forma introdutória em duas notas — poderia virar nota própria com mais chaves e cenários)

---

## Convenções usadas nas notas

- **Frontmatter YAML**: `tags`, `area`, `status` (todas atualmente `estudo-ativo`)
- **Callouts Obsidian**: `[!info]`, `[!tip]`, `[!warning]`, `[!danger]`, `[!example]`, `[!todo]` — renderizam como blockquote simples no GitHub
- **Checklists** ao final de cada nota — uso prático em campo/investigação real
- **Ver também** — links cruzados entre notas relacionadas
