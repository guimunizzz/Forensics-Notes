---
tags: [dfir, linux, live-response, forense-digital, blue-team, filesystem-forensics]
area: Blue Team / DFIR
status: estudo-ativo
---

# DFIR em Linux: Live Response, Sistemas de Arquivos e Forense

> [!info] Sobre esta nota
> Cobre o lado Linux do DFIR — que segue a mesma lógica da nota [Forense Digital em Windows](../Windows/Forense%20Digital%20em%20Windows.md) (ordem de volatilidade, coletar antes de desligar, nunca analisar o original), mas com ferramentas e artefatos completamente diferentes. Estrutura: **Live Response (dados voláteis) → Sistemas de Arquivos → Forense de Disco → Arquivos de Configuração e Sistema**.

---

## 1. O que é Linux Live Response

**Live Response** é a coleta de informação forense em uma máquina Linux **ainda ligada**, logo após um incidente — antes que dados voláteis se percam com um desligamento ou reinicialização.

**Dado volátil** em Linux é qualquer informação que desaparece quando a energia é interrompida: conteúdo da RAM, registradores da CPU, conexões de rede ativas, processos em execução. Essa informação reflete o **estado exato do sistema no momento do incidente** — coisas como um processo de ransomware ainda criptografando arquivos, ou uma conexão ativa com um C2, só existem enquanto a máquina está ligada.

> [!warning] Regra prática
> Dados voláteis mudam constantemente — colete o quanto antes após perceber o incidente. Quanto mais tempo passa, maior a chance de perder processos, conexões e artefatos de memória relevantes.

---

## 2. Live Response — Parte 1: Processos, Tempo e Usuários

### 2.1 Processos em Execução

| Comando | O que mostra |
|---|---|
| `ps` | Por padrão, só os processos da sessão de terminal atual — output limitado (PID, TTY, TIME, CMD) |
| `ps aux` | **Todos** os processos do sistema — usuário, PID, uso de CPU/memória (%CPU, %MEM), tamanho de memória virtual (VSZ) e física (RSS), TTY, status (STAT), horário de início (START), tempo total de CPU (TIME), comando (COMMAND) |
| `top` / `htop` | Monitoramento em tempo real — útil para flagrar processos consumindo CPU/memória de forma anômala (ex: um processo de ransomware cifrando arquivos em massa geralmente aparece com uso de CPU/I/O muito acima do normal) |

```sh
# Ver todos os processos do sistema, independente de terminal/usuário
ps aux

# Ordenar por consumo de CPU para achar rapidamente o processo "barulhento"
ps aux --sort=-%cpu | head -20

# Ver a árvore de processos (útil para ver quem é o processo pai de algo suspeito)
ps auxf
```

> [!example] Sinal de alerta prático
> Um processo desconhecido com nome genérico (`kworker`, `systemd-`, mas rodando de um path fora de `/usr` ou `/lib`) e uso constante e elevado de CPU/I/O é um forte candidato a ransomware, cryptominer ou exfiltração em andamento. Sempre confira o **caminho real do binário**: `ls -la /proc/<PID>/exe`.

### 2.2 Horário do Sistema

Fundamental para montar uma timeline consistente entre logs, timestamps de arquivo e eventos.

```sh
date         # Horário atual do sistema
timedatectl  # Configuração de timezone e sincronização NTP
```

> [!tip] Cuidado com timezone
> Sempre registre o timezone junto com qualquer timestamp coletado. Comparar logs de sistemas em timezones diferentes sem normalizar para UTC é uma das causas mais comuns de erro de timeline em investigações.

### 2.3 Usuários Conectados

| Comando | O que mostra |
|---|---|
| `who` | Usuários logados agora, TTY de origem, data/hora do login |
| `w` | Como `who`, mas também mostra o que cada usuário está executando no momento e a origem (IP, se remoto) |
| `last` | Histórico de logins (bem-sucedidos), lido a partir de `/var/log/wtmp` |
| `lastb` | Histórico de tentativas de login **falhas**, lido a partir de `/var/log/btmp` — ótimo para identificar força bruta |
| `lastlog` | Último login de cada usuário do sistema, mesmo os que nunca logaram |

```sh
who
w
last -a          # inclui o hostname/IP de origem
lastb | head -20 # tentativas de login falhas — força bruta costuma aparecer aqui
```

---

## 3. Live Response — Parte 2: Arquivos Abertos, Rede, Histórico e RAM

### 3.1 Arquivos Abertos (`lsof`)

`lsof` (List Open Files) mostra quais processos têm quais arquivos abertos — essencial para entender o que um processo suspeito está tocando **agora**.

```sh
# Ver quem tem um arquivo/diretório específico aberto
lsof /tmp/.test.txt.swp

# Ver todos os arquivos abertos por um processo específico (via PID)
ps aux | grep nginx
lsof -p 980

# Ver todos os arquivos abertos por um usuário específico
lsof -u vivek

# Ver conexões de rede abertas por um processo (combina lsof + rede)
lsof -i -p 980
```

### 3.2 Conexões de Rede (`netstat` e `ss`)

`netstat` é o clássico; `ss` é o substituto moderno (mais rápido, lê direto do kernel) — ambos valem a pena conhecer, já que `netstat` pode não estar presente em distros mínimas.

| Flag | Significado |
|---|---|
| `-a` | Mostra sockets em escuta e não-escuta |
| `-l` | Só sockets em escuta (listening) |
| `-t` / `-u` | TCP / UDP |
| `-4` / `-6` | IPv4 / IPv6 |
| `-n` | Endereços numéricos (não resolve hostname — mais rápido, não gera ruído de DNS) |
| `-p` | Mostra PID/nome do programa dono do socket (requer root) |

```sh
# Todas as conexões TCP ativas
netstat -at

# Só portas em escuta TCP
netstat -lt

# Equivalente moderno com ss, já trazendo o processo
ss -tulpn

# Configuração de interfaces de rede — útil para detectar interface nova (ex: túnel DNS)
ip addr
```

> [!example] Uso investigativo
> Uma interface de rede nova que você não reconhece (`ip addr`) pode indicar criação de túnel (VPN improvisada, DNS tunneling). Cruze com `ss -tulpn` para ver qual processo está usando essa interface.

### 3.3 Histórico de Comandos

O histórico de comandos do shell é uma das fontes mais diretas de "o que o usuário/atacante digitou".

```sh
history                 # histórico da sessão atual
cat ~/.bash_history     # histórico persistido em disco (usuários bash)
cat ~/.zsh_history       # equivalente para usuários zsh
```

> [!tip] Timestamp no histórico
> Por padrão, `.bash_history` **não guarda timestamp** de cada comando. Se o ambiente tiver `HISTTIMEFORMAT` configurado, o `history` mostra data/hora — verifique com `echo $HISTTIMEFORMAT`. Sem isso, você só sabe a ordem dos comandos, não quando foram executados — outra boa razão para cruzar com logs de auditoria (auditd, se disponível) e com timestamps de arquivos gerados pelos comandos.

> [!warning] Limitação anti-forense
> Um atacante com conhecimento básico apaga ou desabilita o histórico (`unset HISTFILE`, `history -c`, symlink para `/dev/null`). A ausência total de histórico em uma conta que claramente foi usada é, por si só, um indício de atividade deliberada para esconder rastros — ver a nota [Anti-Forense e Ofuscação de Dados](../Anti-Forense/Anti-Forense%20e%20Ofuscação%20de%20Dados.md) para mais sobre isso.

### 3.4 Conteúdo da RAM

A memória guarda aplicações abertas, atividade do usuário e informação sensível — captura crítica para detectar malware fileless, comandos escondidos ou dados sensíveis em uso no momento do incidente.

**LiME (Linux Memory Extractor)** é a ferramenta mais usada para captura de RAM em Linux — carrega como módulo de kernel e salva o estado atual da memória em um arquivo.

```sh
# Exemplo conceitual de uso do LiME (requer módulo compilado para o kernel exato da máquina-alvo)
insmod lime.ko "path=/mnt/evidencias/ram_dump.lime format=lime"
```

A análise do dump gerado é feita com **Volatility** (framework open-source de análise de memória), examinando processos, conexões de rede, arquivos abertos e sessões de usuário no momento da captura.

> [!info] Nota sobre profundidade
> Forense de memória em Linux é um tópico extenso o suficiente para merecer seu próprio material dedicado (Volatility3 com profile Linux, plugins `linux.pslist`, `linux.bash`, `linux.netstat` etc.) — aqui fica registrado como parte do fluxo de Live Response, aprofundamento fica para a nota [Forense de Memória em Linux](Forense%20de%20Memória%20em%20Linux.md)

---

## 4. Sistemas de Arquivos em Linux

Diferente do Windows (NTFS dominante), o Linux suporta múltiplos sistemas de arquivos, cada um com implicações forenses distintas.

| Sistema de Arquivos | Características | Implicação forense |
|---|---|---|
| **EXT2** | Simples e robusto, **sem journaling** | Mais fácil recuperar arquivos deletados (dados não são "confirmados" via journal), mas sem trilha de mudanças recentes |
| **EXT3** | EXT2 + journaling | Journal ajuda a rastrear mudanças e manter integridade após crash — bom para reconstrução de timeline |
| **EXT4** | Evolução do EXT3, suporta discos/arquivos grandes, mais rápido | Journal mais robusto, melhor suporte a recuperação e análise forense moderna |
| **XFS** | Alta performance, feito para sistemas de arquivos grandes | Comum em servidores — útil de conhecer para análise de datasets grandes |
| **Btrfs** | Snapshots nativos, verificação de integridade de dados | Snapshots são ouro para forense — podem preservar estados anteriores do sistema mesmo após alteração |
| **ReiserFS** | Otimizado para muitos arquivos pequenos | Uso em queda, mas ainda aparece em sistemas legados |

```sh
# Ver uso e tipo dos discos montados no sistema
df -hT
```

---

## 5. Forense de Sistema de Arquivos (Imaging, Hash e Recuperação)

### 5.1 Ferramentas de Imaging

#### `dd`

O comando mais fundamental para cópia bit a bit em Linux/Unix.

```sh
dd if=<origem> of=<destino> bs=<tamanho_do_bloco> status=progress
```

- `if=`: **input file** — a origem (ex: uma partição)
- `of=`: **output file** — destino onde a imagem será gravada
- `bs=`: tamanho do bloco de transferência (afeta velocidade)
- `status=progress`: mostra progresso em tempo real

```sh
sudo dd if=/dev/sdb1 of=/path/to/disk_image.img bs=4M status=progress
```

#### Montando a imagem (somente leitura!)

```sh
dd if=/dev/sda1 of=/tmp/sda1.img bs=4M status=progress
mount -o ro /tmp/sda1.img /mnt/image
```

> [!danger] `-o ro` não é opcional
> Montar a imagem sem a flag `ro` (read-only) permite escrita acidental na imagem — que é agora sua **evidência de trabalho**. Isso não afeta o disco original (você já não está mais tocando nele), mas compromete a integridade da cópia que está sendo analisada.

#### `dc3dd`

Versão do `dd` feita especificamente para forense — adiciona indicador de progresso nativo, cálculo automático de hash (MD5/SHA-256) durante a cópia, e suporte a múltiplos arquivos de saída simultâneos.

### 5.2 Cálculo de Hash (Garantia de Integridade)

| Algoritmo | Tamanho | Observação |
|---|---|---|
| MD5 | 128 bits | Rápido, mas vulnerável a colisões — evitar como única prova de integridade em casos sensíveis |
| SHA-1 | 160 bits | Mais forte que MD5, mas também com colisões conhecidas |
| **SHA-256** | 256 bits | Padrão atual recomendado para forense |

```sh
md5sum disk_image.img
sha1sum disk_image.img
sha256sum disk_image.img
```

Assim como no fluxo Windows, o hash deve ser calculado **imediatamente após a captura** e revalidado a cada transferência da evidência.

### 5.3 Recuperação de Arquivos Deletados

Quando um arquivo é "deletado" em Linux, os dados não são apagados fisicamente de imediato — o sistema de arquivos apenas marca o espaço como livre. Até que algo sobrescreva esse espaço, o conteúdo é recuperável.

**Fluxo geral de recuperação:**

1. **Imaging** — sempre trabalhar sobre uma cópia (`dd`/`dc3dd`), nunca no disco original
2. **Escolha de ferramenta** — The Sleuth Kit (TSK), TestDisk, PhotoRec, Foremost, ou ferramentas específicas de sistema de arquivos como `ext3grep`/`ext4magic`
3. **Análise do sistema de arquivos** — as ferramentas varrem tabelas de alocação e metadados em busca de entradas marcadas como deletadas
4. **Recuperação** — os arquivos encontrados são restaurados para um local seguro (nunca de volta no disco original)

#### Exemplo prático — `ext3grep` (sistemas EXT3)

```sh
# Instalar a ferramenta
apt install ext3grep

# Capturar imagem do disco/partição onde os arquivos deletados estão
dd if=/dev/sdb1 of=/root/forensic.dd status=progress bs=8k

# Conferir informações do sistema para contexto do caso
uname -a
df -hT

# Listar todos os arquivos encontrados na imagem (incluindo deletados)
ext3grep --dump-name forensic.dd

# Recuperar todos os arquivos encontrados
ext3grep --restore-all forensic.dd
```

Os arquivos recuperados aparecem no diretório `RESTORED_FILES`.

> [!tip] Para EXT4
> `ext3grep` não é confiável em EXT4 devido a mudanças na estrutura de extents — use `ext4magic` ou ferramentas do The Sleuth Kit (`fls`, `icat`) que lidam melhor com o formato mais recente.

---

## 6. Arquivos de Configuração do Linux (`/etc`)

### 6.1 `/etc/passwd`

Contas de usuário do sistema. Formato de cada linha:

```
username:x:UID:GID:real_name:home_directory:shell
```

**Uso forense**: detectar contas criadas sem autorização, identificar UID 0 (root) em contas que não deveriam ter esse privilégio, entender o shell/home de cada conta para mapear comportamento.

### 6.2 `/etc/shadow`

Guarda os hashes de senha (acessível só por root). Formato:

```
username:password_hash:last_change:min:max:warn:inactive:expire
```

**Uso forense**: analisar política de senha, identificar tentativas de quebra de hash, verificar contas bloqueadas/expiradas — e sobretudo alterações inesperadas no hash, que podem indicar que um atacante trocou a senha para manter persistência.

### 6.3 `/etc/group`

Grupos do sistema e seus membros. Formato:

```
group_name:x:GID:member1,member2,...
```

**Uso forense**: detectar escalonamento de privilégio via inclusão indevida em grupos privilegiados (ex: `sudo`, `wheel`, `docker` — este último é um vetor clássico de escalonamento, já que membros do grupo `docker` podem montar o filesystem raiz via container).

### 6.4 `/etc/sudoers`

Define quais usuários/grupos podem rodar comandos como root via `sudo`.

**Uso forense**: identificar autorizações `sudo` adicionadas ou alteradas de forma não documentada — um dos primeiros lugares a checar quando se suspeita de persistência com privilégio elevado.

```sh
# Forma segura de visualizar sem editar acidentalmente
sudo cat /etc/sudoers
sudo ls -la /etc/sudoers.d/
```

### 6.5 `/etc/crontab` e Persistência via Agendamento

Define tarefas agendadas (cron jobs). Formato:

```
minuto hora dia_mes mês dia_semana usuário comando
```

**Uso forense**: um dos locais mais comuns para persistência de malware/backdoor — atacantes adicionam entradas para reexecutar payloads periodicamente.

> [!warning] Não é só `/etc/crontab`
> Também confira: `/etc/cron.d/`, `/etc/cron.{hourly,daily,weekly,monthly}/`, e o crontab por usuário em `/var/spool/cron/crontabs/<usuario>` (ou `/var/spool/cron/<usuario>`, dependendo da distro). Malware que só planta persistência no crontab de usuário passa despercebido se você só olhar o `/etc/crontab` global.

```sh
# Ver crontab de um usuário específico
crontab -u <usuario> -l

# Listar todos os spools de cron por usuário
ls -la /var/spool/cron/crontabs/
```

---

## 7. Arquivos e Comandos de Sistema

### 7.1 `~/.ssh/authorized_keys`

Guarda as chaves públicas SSH autorizadas para aquele usuário logar sem senha.

**Uso forense**: chave pública desconhecida adicionada aqui é uma das formas mais silenciosas de manter acesso persistente — não aparece em `/etc/shadow`, não gera evento de "troca de senha", e sobrevive até alguém remover a chave manualmente.

```sh
cat ~/.ssh/authorized_keys
# Verificar timestamp de modificação — mudança recente sem explicação é bandeira vermelha
ls -la ~/.ssh/authorized_keys
```

Formato de cada linha: `<tipo_chave> <valor_base64> <comentário>`

### 7.2 `.bashrc` e arquivos de perfil de shell

Executado a cada nova sessão de terminal — local comum para persistência leve (alias maliciosos, comandos automáticos, reverse shells disparados na abertura do terminal).

```sh
cat ~/.bashrc
ls -la ~/.bashrc   # data de modificação ajuda a montar timeline
```

> [!tip] Compare entre contas
> Diferenças entre `.bashrc` de contas diferentes no mesmo sistema (uma tem uma linha extra estranha, as outras não) são fáceis de spotar com um `diff` simples.

### 7.3 `systemd` e Serviços

```sh
systemctl status                       # status geral de serviços e units
systemctl list-units --type=service    # lista todos os serviços em execução
journalctl -u <nome-do-servico>        # logs de um serviço específico
```

**Uso forense**: um serviço `.service` malicioso configurado para iniciar automaticamente é o equivalente Linux das chaves `Run`/`RunOnce` do Registro do Windows — vale a pena revisar unidades habilitadas que não fazem parte da instalação padrão da distro.

```sh
# Listar serviços habilitados para iniciar no boot — comparar com o esperado
systemctl list-unit-files --state=enabled
```

### 7.4 `/tmp` e `/var/tmp` — Território Favorito de Atacante

Diretórios com permissão de escrita ampla — destino clássico para upload de ferramentas, payloads e scripts.

```sh
# Listar arquivos por data de criação/modificação (mais recentes primeiro)
ls -lart /tmp
ls -lart /var/tmp

# Buscar extensões comumente usadas por atacantes
find /tmp -name '*.php'
find /var/tmp -name '*.sh'

# Buscar conteúdo suspeito dentro dos arquivos
grep -R "malicious_code" /tmp
grep -R "192.168.1.1" /var/tmp

# Arquivos modificados/acessados nos últimos 2 dias
find /tmp -mtime -2
find /var/tmp -atime -2

# Arquivos grandes (possível coleta de dados para exfiltração)
find /tmp -size +10M

# Arquivos com permissão perigosa (gravável por qualquer um)
find /tmp -type f -perm -o=w
```

---

## 8. Artefatos Extras que Vale a Pena Conhecer

| Artefato | Localização | Por que importa |
|---|---|---|
| Logs de autenticação | `/var/log/auth.log` (Debian/Ubuntu) ou `/var/log/secure` (RHEL/CentOS) | Registra tentativas de login, uso de `sudo`, autenticação SSH — a fonte nº1 para investigar acesso não autorizado |
| `wtmp` / `utmp` / `btmp` | `/var/log/wtmp`, `/var/run/utmp`, `/var/log/btmp` | Base binária lida por `last`, `who` e `lastb` — pode ser lida diretamente com `utmpdump` se as ferramentas padrão estiverem comprometidas |
| SUID/SGID binaries | Todo o sistema | Binários com bit SUID/SGID mal configurados são vetor clássico de escalonamento de privilégio |
| `/var/log/` em geral | `/var/log/` | Syslog, logs de aplicação, kernel (`dmesg`) — sempre vale um `ls -lat /var/log` para achar o que foi modificado por último |

```sh
# Caçar binários SUID no sistema — revisar contra uma baseline conhecida
find / -perm -4000 -type f 2>/dev/null

# Ver os logs mais recentemente modificados em /var/log
ls -lat /var/log | head -20
```

---

## 9. Checklist — Ordem Prática de Live Response em Linux

1. [ ] Registrar hora de chegada e estado inicial do sistema (ligado, tela, sessões visíveis)
2. [ ] Capturar processos em execução (`ps aux`, `top`/`htop` para overview de recursos)
3. [ ] Registrar horário do sistema e timezone (`date`, `timedatectl`)
4. [ ] Capturar usuários conectados e histórico de login (`who`, `w`, `last -a`, `lastb`)
5. [ ] Capturar arquivos abertos e conexões de rede (`lsof`, `ss -tulpn`, `ip addr`)
6. [ ] Copiar histórico de comandos (`~/.bash_history` de todos os usuários relevantes)
7. [ ] Capturar memória RAM (LiME) **antes** de qualquer ação que possa derrubar o processo suspeito
8. [ ] Copiar arquivos de configuração-chave (`/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/sudoers`, `/etc/crontab` + `/etc/cron.d`, spools de cron por usuário)
9. [ ] Verificar `~/.ssh/authorized_keys` de todos os usuários
10. [ ] Revisar serviços systemd habilitados fora do padrão da distro
11. [ ] Vasculhar `/tmp` e `/var/tmp` por arquivos recentes/suspeitos
12. [ ] Só então (se necessário) proceder para imaging completo de disco com `dd`/`dc3dd`, sempre com hash calculado e documentado

---

## 10. Referências para Aprofundamento

- The Sleuth Kit (TSK) & Autopsy — documentação oficial
- Volatility3 Docs — plugins da família `linux.*`
- SANS FOR577 / FOR508 — cobrem Linux/Unix incident response
- `man` pages de cada comando citado (`man lsof`, `man ss`, `man crontab`) — sempre a fonte mais confiável para a versão exata instalada no sistema investigado

---

## Ver também
- [Forense de Memória em Linux](Forense%20de%20Memória%20em%20Linux.md)
- [Forense Digital em Windows](../Windows/Forense%20Digital%20em%20Windows.md)
- [Arquitetura de Computadores para Forense Digital](../Fundamentos/Arquitetura%20de%20Computadores%20para%20Forense%20Digital.md)
- [Anti-Forense e Ofuscação de Dados](../Anti-Forense/Anti-Forense%20e%20Ofuscação%20de%20Dados.md)
- [Android Forensics](../Mobile/Android%20Forensics.md)
- [MITRE ATT&CK](../Threat-Intel/MITRE%20ATT%26CK.md)
