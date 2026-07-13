---
tags: [DFIR, MobileForensics, AndroidForensics, SOC]
status: estudo em andamento
---

# Android Forensics

> [!info] Sobre esta nota
> Android roda sobre um kernel Linux, então boa parte da intuição de [DFIR em Linux](../Linux/DFIR%20em%20Linux.md) se transfere (EXT4, inodes, permissões Unix) — mas o modelo de sandboxing por aplicativo, a criptografia por arquivo (FBE) e a fragmentação de fabricantes/ROMs criam um universo forense próprio. Esta nota cobre do sistema de arquivos à aquisição de evidência em um dispositivo bloqueado, incluindo os artefatos (bancos SQLite, backups) onde a evidência realmente mora.

## Sumário
1. [Introdução ao Android Forensics (Mobile DFIR)](#1-introdução-ao-android-forensics-mobile-dfir)
2. [Sistema de Arquivos Android](#2-sistema-de-arquivos-android)
3. [Identificação do Dispositivo](#3-identificação-do-dispositivo)
4. [Lidando com Dispositivos Bloqueados](#4-lidando-com-dispositivos-bloqueados)
5. [Aquisição de Evidências (Imaging)](#5-aquisição-de-evidências-imaging)
6. [Ferramentas de Android Forensics](#6-ferramentas-de-android-forensics)
7. [Tópicos Complementares](#7-tópicos-complementares)
8. [Metodologia de Investigação (Checklist)](#8-metodologia-de-investigação-checklist)
9. [Cheatsheet de Comandos ADB](#9-cheatsheet-de-comandos-adb)

---

## 1. Introdução ao Android Forensics (Mobile DFIR)

**Mobile DFIR** é a coleta, análise e preservação de dados digitais de smartphones, tablets e wearables — hoje uma das fontes de evidência mais ricas em qualquer investigação, criminal ou corporativa: registros de chamada, mensagens, e-mails, atividade em redes sociais, localização e uso de apps.

**Android Forensics** é a especialização de Mobile DFIR voltada ao ecossistema Android. O que torna esse ecossistema particularmente desafiador em comparação a iOS:

- **Hardware fragmentado**: dezenas de fabricantes (Samsung, Google, Xiaomi, Motorola...), cada um com seu próprio hardware de segurança.
- **Software fragmentado**: cada fabricante modifica a "Base Android" do Google, adicionando camadas próprias de segurança, ROMs customizadas, bootloaders diferentes.
- **Sem padrão único de aquisição**: o que funciona em um Samsung com Knox pode não funcionar em um Xiaomi ou em um device com bootloader desbloqueado.

> [!tip] Consequência prática
> Diferente de investigar um iPhone (hardware/software controlados pela Apple), em Android **o primeiro passo real da investigação é sempre identificar exatamente o hardware e o software** antes de escolher a técnica de aquisição — ver seção 3.

Achados de Android Forensics ajudam a construir timeline, identificar suspeitos/vítimas, provar intenção e até derrubar álibis falsos — por isso a integridade da cadeia de custódia (documentação de cada ação, minimização de interferência de terceiros) é tão crítica quanto em qualquer outra forense digital.

---

## 2. Sistema de Arquivos Android

### 2.1 EXT4 e metadados

Android usa **EXT4** (baseado em Linux) como formato principal de armazenamento — journaling (preserva integridade em queda de energia), alocação eficiente de blocos, e cada arquivo/diretório tem um **inode** único que rastreia permissões e acesso (mesmo conceito de [DFIR em Linux](../Linux/DFIR%20em%20Linux.md)). Alguns dispositivos ainda suportam EXT2/EXT3/FAT32, e fabricantes específicos podem trazer JFFS2 ou YAFFS2 para partições legadas.

### 2.2 Hierarquia de partições

| Partição | Conteúdo | Relevância forense |
|---|---|---|
| **`/boot`** | Kernel + recovery loader carregados pelo bootloader | Indica versão do kernel; alterações aqui podem indicar root/custom ROM |
| **`/system`** | Arquivos do SO: apps de sistema, frameworks, fontes, configs | Baseline do sistema — comparar contra versão oficial revela modificações maliciosas |
| **`/data`** | Apps instalados pelo usuário e todos os dados (fotos, mensagens, apps) | **A mina de ouro forense** — praticamente toda evidência de usuário vive aqui |
| **`/storage`** | Armazenamento externo (SD card, USB) | Fonte adicional de evidência, muitas vezes esquecida |
| **`/recovery`** | Partição de boot em modo recovery | Reset de fábrica / opções avançadas — relevante para anti-forense (seção 7.5) |

### 2.3 Media Scanner

Mantém o **Media Store**, um banco de dados que indexa conteúdo multimídia do dispositivo (nome do artista, título, duração, tamanho de arquivo etc.), escaneando o armazenamento físico periodicamente. Apps multimídia consultam o Media Scanner em vez de indexar o sistema de arquivos diretamente — isso é, inclusive, um ponto de partida útil para reconstruir uma timeline de mídia sem precisar varrer manualmente cada diretório.

### 2.4 Criptografia: FDE x FBE

| | **FDE** (Full Disk Encryption) | **FBE** (File-Based Encryption) |
|---|---|---|
| Introduzido | Versões antigas do Android | Android 7.0+ |
| Granularidade | Disco inteiro | Arquivo por arquivo |
| Boot | Exige senha para qualquer função | **Direct Boot**: dispositivo liga até a tela de bloqueio sem chave |
| Implicação forense | Sem a senha, imagem inteira é inacessível | Alguns arquivos (CE) só abrem após unlock; outros (DE) exigem verificação de hardware |

Dentro de FBE existem dois tipos de armazenamento:

- **CE (Credential Encrypted)**: criptografado com a credencial de tela (senha/PIN/digital). É onde ficam fotos, mensagens, contatos — só acessível **após** o desbloqueio do dispositivo.
- **DE (Device Encrypted)**: criptografado por hardware seguro (**TEE — Trusted Execution Environment**). Guarda dados críticos de sistema e chaves de app; exige verificação do TEE mesmo com o dispositivo já desbloqueado.

> [!info] TEE por fabricante
> Qualcomm Snapdragon usa um chip **Secure Element (SE)** dedicado; Samsung Exynos usa o **Knox Vault**; MediaTek Helio usa **TrustZone**. Saber qual chip está por trás do TEE do dispositivo apreendido ajuda a avaliar se existe (ou não) um vetor de ataque de hardware conhecido publicamente.

### 2.5 Permissões, VFS/FUSE e Sandbox

- **Permissões**: modelo Unix clássico (read/write/execute para dono/grupo/outros), adaptado com restrições extras específicas do Android.
- **VFS (Virtual File System)**: camada que abstrai diferentes sistemas de arquivo com uma API comum; usa **FUSE (Filesystem in Userspace)** para lidar com armazenamento externo (SD card, MTP) sem exigir drivers de kernel dedicados.
- **Application Sandbox**: cada app roda em seu **próprio processo com UID exclusivo**, isolado dos demais — um app malicioso comprometido não consegue, por padrão, ler os dados de outro app ou do sistema. Esse isolamento é também o motivo pelo qual, na prática, **acesso root é normalmente necessário** para uma aquisição forense completa (seção 5).

---

## 3. Identificação do Dispositivo

Antes de qualquer tentativa de aquisição, documentar:

- [ ] Modelo do dispositivo
- [ ] Número de série
- [ ] IMEI
- [ ] Versão do sistema operacional
- [ ] Nível de patch de segurança
- [ ] Se o dispositivo está rooteado
- [ ] Perfil de usuário (single-user, work profile, múltiplos usuários)
- [ ] Status de bloqueio da tela

**Exemplo prático — coletando essa informação via ADB (se já houver acesso shell):**
```bash
adb shell getprop ro.product.model            # modelo
adb shell getprop ro.build.version.release    # versão do Android
adb shell getprop ro.build.version.security_patch
adb shell service call iphonesubinfo 1        # IMEI (varia por versão/fabricante)
adb shell dumpsys device_policy                # verifica work profile / MDM
adb shell getprop ro.build.tags                # "test-keys" costuma indicar ROM não oficial/rooted
```

> [!tip] Por que isso vem primeiro
> Essas informações determinam **qual técnica de aquisição é sequer possível**: um dispositivo com FBE e bootloader travado exige uma abordagem completamente diferente de um dispositivo antigo com FDE e bootloader desbloqueado.

---

## 4. Lidando com Dispositivos Bloqueados

### 4.1 Preparação e primeiros cuidados

> [!warning] Isolamento de rede é prioridade
> Se o dispositivo é apreendido **ligado**, isole-o de qualquer conectividade (modo avião, Faraday bag, ou remoção do SIM quando seguro) **imediatamente**. O motivo: o **Android Device Manager (ADM)** do Google permite localizar e apagar remotamente um dispositivo — um wipe remoto destrói a evidência antes mesmo de começar a análise.

Outros mecanismos de segurança a ter em mente:
- **Lock Mode**: desativa biometria (digital/face), deixando PIN/padrão como única forma de desbloqueio — reduz drasticamente as chances de bypass biométrico coercitivo.
- **Application Sandbox + SELinux**: reforçam isolamento entre apps mesmo se um deles for comprometido.

Se você tem cooperação do usuário (ex.: vítima de ataque), a coleta de credenciais é trivial. Se o dispositivo pertence a um atacante/suspeito, normalmente não há credenciais disponíveis — nesse caso, segue a cadeia de custódia: documentar tudo, minimizar interferência de terceiros.

### 4.2 ADB (Android Debug Bridge)

ADB é a ferramenta de linha de comando que conecta o computador ao dispositivo, viabilizando instalação/remoção de apps, transferência de arquivos, execução de comandos shell, visualização de logs (`logcat`) e captura de tela.

Pré-requisitos normais para usar ADB: **modo desenvolvedor** ativado, **depuração USB** habilitada, e o computador **autorizado** no dispositivo (prompt de "Device Auth" na tela). Sem esses três, o comando abaixo já revela o problema:

```bash
adb devices
# unauthorized  →  dispositivo pede autorização na tela (sem acesso, você trava aqui)
# device        →  já autorizado, siga para adb shell
```

Se autorizado:
```bash
adb shell
```

> [!tip] "Vale tentar"
> Em alguns dispositivos mais antigos ou com configurações relaxadas, o ADB já vem habilitado ou não exige autenticação — vale sempre rodar `adb devices` antes de assumir que está bloqueado.

### 4.3 MTP (Media Transfer Protocol)

Alternativa quando ADB não está disponível — em muitos dispositivos, conectar via USB já expõe o sistema de arquivos por MTP (com ou sem desbloqueio da tela, dependendo do fabricante).

**Exemplo prático (Linux):**
```bash
mount | grep gvfs                                        # confirma se o MTP foi montado
ls -h /run/user/1000/gvfs                                 # lista o ponto de montagem
ls -al /run/user/1000/gvfs/mtp\:host\=SEUDISPOSITIVO_ID/   # acessa os arquivos
```

> [!danger] Cuidado com integridade da evidência
> Por padrão, MTP monta o dispositivo em **modo leitura/gravação (RW)** para o usuário root — qualquer processo do SO ou antivírus rodando pode gravar/alterar timestamps no dispositivo, quebrando a cadeia de custódia. **Sempre conectar em sessão de usuário normal (não root)**, onde o Linux monta MTP como **somente leitura (RO)** para não-root.

### 4.4 Bypass de bloqueio (quando não há credenciais)

| Técnica | Quando usar | Observação |
|---|---|---|
| Remover `gesture.key` via ADB + reiniciar | Bypass de padrão (pattern lock) | Exige modo desenvolvedor + depuração USB já habilitados — não funciona "de fora" |
| **Andriller** | Brute-force de PIN/padrão em dispositivos vulneráveis | Open-source, Python 3, GUI — ver seção 6.1 |
| **Tenorshare 4uKey** (comercial) | Bypass de tela de bloqueio em marcas populares (Samsung, LG, Motorola, Xiaomi, Google) | Ferramenta de terceiros — validar impacto na cadeia de custódia antes de usar |
| **Android Device Manager** | Reset remoto de PIN | Exige credenciais da conta Google associada ao dispositivo |

Se nenhuma dessas alternativas funcionar, o caminho seguinte é acionar empresas especializadas em forense móvel ou ferramentas comerciais dedicadas (Cellebrite UFED, MSAB XRY etc. — seção 6.3).

---

## 5. Aquisição de Evidências (Imaging)

### 5.1 Imagem Física (Physical Imaging)

Cópia **bit a bit** de toda a memória do dispositivo — o padrão-ouro forense, mais confiável e completo. Dois caminhos possíveis:

1. **Extração de hardware/chip-off** — acesso direto aos chips de memória em laboratório com equipamento especializado. Altíssima confiabilidade, mas exige expertise avançada e **risco real de dano irreparável** ao dispositivo.
2. **Via ADB + root** — obter acesso root no dispositivo (via ADB) e então copiar os dados. Mais rápido e simples, mas **grava/altera dados no dispositivo** durante o processo de rooting, o que é um risco direto para a cadeia de custódia — deve ser documentado detalhadamente se essa for a única opção viável.

### 5.2 Imagem Lógica (Logical Imaging)

Quando a imagem física não é viável: conectar o dispositivo e copiar arquivos do sistema de arquivos, sem acesso a áreas de sistema — só dados do espaço de usuário.

**Via MTP** (interface gráfica ou linha de comando, ver seção 4.3).

**Via `adb pull`** (recursivo, sem parâmetros extras necessários):
```bash
mkdir ./evidencia_dispositivo
adb pull /storage ./evidencia_dispositivo
```

> [!tip] Física x Lógica — trade-off rápido
> Física = mais completa (inclui espaço não alocado, dados deletados recuperáveis) mas mais arriscada/complexa. Lógica = mais segura e rápida, mas só enxerga o que o espaço de usuário expõe — nada de dados deletados ou partições de sistema.

---

## 6. Ferramentas de Android Forensics

### 6.1 Andriller

Ferramenta gratuita e open-source em **Python 3**, com GUI, roda em Ubuntu. Usa força bruta para tentar contornar segurança do Android.

**Instalação:**
```bash
sudo apt-get install android-tools-adb python3-tk
git clone https://github.com/den4uk/andriller.git
cd andriller
pip3 install -r requirements.txt
python3 -m andriller
```

**Fluxo de uso:**
1. Definir o diretório de saída em **Global Output Location → Output**.
2. Conectar o dispositivo via USB e clicar **Check** em **Extraction (USB)** — se conectado com sucesso, aparece o **Serial ID**.
3. Clicar **Extract** — o Andriller tenta extração via **Device Backup**; será necessário autorizar o backup na tela do dispositivo.
4. Ao final, é gerado um diretório `DEVICESERIAL_BACKUPDATE` contendo:
   - `REPORT.html` — resumo da operação
   - `REPORT.xlsx` — lista de arquivos exportados
   - `data/` — dados extraídos das aplicações
5. Usar os campos **Parse (TAR)** e **Parse (AB)** para extrair `DataStore.tar` e `Backup.ab` — gera pastas adicionais com bancos de dados relevantes para a investigação (SMS, contatos, apps de mensageria etc.).

### 6.2 Androidqf (Android Quick Forensic)

Ferramenta em **Go**, mais enxuta que o Andriller — foca em coletar rapidamente o essencial.

```bash
git clone https://github.com/botherder/androidqf.git
cd androidqf/build
./androidqf_linux_amd64
```

Ao rodar, conecta automaticamente ao dispositivo, pergunta se deseja fazer backup do sistema antes de prosseguir, coleta logs do sistema, informações de apps instalados e (opcionalmente) cópias dos APKs.

**Saída gerada:**

| Arquivo | Conteúdo |
|---|---|
| `dumpsys.txt` | Atividades ativas/passadas, janelas, bateria, uso de memória (`adb shell dumpsys`) |
| `getprop.txt` | Serial, modelo, configuração de hardware (`adb shell getprop`) |
| `logcat.txt` | Logs do sistema (`adb shell logcat`) |
| `packages.json` | APKs instalados e seus detalhes |
| `processes.txt` | Processos em execução no momento da coleta |
| `Settings_*` | Dumps de bancos de dados de configurações do sistema |

### 6.3 Ferramentas comerciais

Para casos que exigem robustez, suporte a mais fabricantes ou bypass de segurança mais avançado, o mercado oferece soluções pagas: **X-Ways Forensics, Mobiledit, MSAB (XRY), Magnet (AXIOM)** e **Cellebrite UFED** — geralmente combinando imaging e análise em um único fluxo de trabalho, com decodificação automática de milhares de apps.

---

## 7. Tópicos Complementares

> [!info] Sobre esta seção
> O material original chega até "extrair os dados" — falta o próximo passo: **onde exatamente essa evidência mora dentro do `/data` e como interpretá-la**. Esta seção cobre localização de artefatos, forense de bancos SQLite, formatos de timestamp (pegadinha clássica), extração via `adb backup`, anti-forense no Android e análise de APKs maliciosos.

### 7.1 Onde a evidência realmente mora — artefatos-chave

| Artefato | Caminho típico | Formato |
|---|---|---|
| SMS/MMS | `/data/data/com.android.providers.telephony/databases/mmssms.db` | SQLite |
| Registro de chamadas | `/data/data/com.android.providers.contacts/databases/contacts2.db` | SQLite |
| Contatos | `/data/data/com.android.providers.contacts/databases/contacts2.db` | SQLite |
| WhatsApp | `/data/data/com.whatsapp/databases/msgstore.db` (mensagens) e `wa.db` (contatos) | SQLite (msgstore pode vir criptografado — `.crypt14`/`.crypt15`) |
| Histórico Chrome | `/data/data/com.android.chrome/app_chrome/Default/History` | SQLite |
| Redes Wi-Fi salvas | `/data/misc/wifi/WifiConfigStore.xml` | XML |
| Cache de localização | `/data/data/com.google.android.gms/databases/` | SQLite |
| APKs instalados | `/data/app/` | APK (ZIP) |

> [!tip] Nem sempre a extensão é `.db`
> Vários apps usam extensões próprias ou criptografam o banco antes de gravar em disco (caso do WhatsApp). Sempre confirmar a assinatura real do arquivo (`file <arquivo>`) antes de assumir que não é um SQLite.

### 7.2 Forense de bancos SQLite

A maioria dos dados de usuário no Android vive em **SQLite** — entender sua estrutura é uma habilidade central em Android Forensics.

**Exemplo prático — consultando um banco extraído:**
```bash
sqlite3 mmssms.db
sqlite> .tables
sqlite> SELECT address, date, body FROM sms ORDER BY date DESC LIMIT 20;
```

**Recuperando registros deletados**: o SQLite não sobrescreve imediatamente uma linha `DELETE`d — os bytes podem continuar no arquivo até serem reutilizados. Ferramentas como **`strings`** no arquivo `.db` bruto, ou **SQLite Forensic Explorer**, conseguem recuperar fragmentos de registros apagados diretamente do espaço não alocado do arquivo de banco.

**Arquivos auxiliares a nunca ignorar:**
- **`*-wal`** (Write-Ahead Log): mudanças recentes ainda não gravadas no banco principal — pode conter dados mais atualizados que o próprio `.db`.
- **`*-journal`**: journal de transação, usado para rollback — também pode conter dados residuais úteis.

```bash
file mmssms.db mmssms.db-wal mmssms.db-journal
```

### 7.3 Formatos de timestamp — a pegadinha clássica

Bancos diferentes no mesmo dispositivo podem usar formatos de timestamp diferentes:

| Formato | Exemplo | Onde aparece |
|---|---|---|
| Unix epoch (segundos) | `1751980532` | Diversos bancos de sistema |
| Unix epoch (**milissegundos**) | `1751980532000` | SMS, WhatsApp, muitos apps modernos |
| Java `System.currentTimeMillis()` | Igual ao epoch em ms | Logs de apps Java/Kotlin |

**Exemplo prático de conversão:**
```bash
date -d @1751980532          # epoch em segundos
date -d @$((1751980532000/1000))   # epoch em milissegundos → segundos
```

> [!danger] Erro comum
> Tratar um timestamp em **milissegundos** como se fosse em **segundos** (ou vice-versa) desloca a data em décadas — um erro silencioso que já invalidou linhas do tempo em investigações reais. Sempre validar contra uma data conhecida do caso antes de confiar na conversão.

### 7.4 Extração via `adb backup` e Android Backup Extractor

Além do `adb pull`, o Android oferece um mecanismo de backup nativo que empacota dados de apps em um único arquivo `.ab`:

```bash
adb backup -apk -all -f backup_completo.ab
```
(Requer confirmação manual na tela do dispositivo — mais um motivo para documentar cada interação.)

O `.ab` não é diretamente legível — é preciso convertê-lo com o **Android Backup Extractor (`abe.jar`)**:
```bash
java -jar abe.jar unpack backup_completo.ab backup_completo.tar
tar -xvf backup_completo.tar -C ./backup_extraido
```
A partir daí, os bancos SQLite e arquivos de cada app ficam acessíveis normalmente (seção 7.1).

### 7.5 Anti-forense no Android

| Técnica do investigado | Efeito | Mitigação/contraponto |
|---|---|---|
| **Factory Reset Protection (FRP)** | Após reset de fábrica, exige login da conta Google original para reconfigurar | Reforça a importância de **não deixar o dispositivo resetar** durante a apreensão |
| **Wipe remoto (ADM)** | Apaga o dispositivo remotamente | Mitigado isolando a rede imediatamente (seção 4.1) |
| **Apps ocultos/clonados** (dual apps, app lockers) | Escondem apps de mensageria de uma varredura superficial | Sempre inspecionar `packages.json`/`pm list packages` completo, não só os ícones visíveis na tela |
| **Limpeza de dados de app** | Remove bancos SQLite do app antes da apreensão | Verificar `*-wal`/`*-journal` residuais e possibilidade de recuperação via imagem física |

### 7.6 Google Cloud como fonte complementar

Boa parte do que está no dispositivo também está sincronizada na conta Google associada (contatos, localização via Google Timeline, backups automáticos de apps). Com autorização legal adequada, **Google Takeout** ou solicitação formal ao Google podem preencher lacunas de dados que não sobreviveram no dispositivo físico (ex.: apagados antes da apreensão, mas já sincronizados na nuvem).

### 7.7 Análise de APKs maliciosos

Quando a investigação envolve um app suspeito de ser malware (spyware comercial, trojan bancário):

- **Análise estática**: `apktool d app.apk` desempacota o APK para inspecionar o `AndroidManifest.xml` (permissões solicitadas) e o smali; **jadx** decompila para um pseudo-código Java legível.
- **Análise dinâmica**: **MobSF (Mobile Security Framework)** automatiza análise estática e dinâmica de APKs em um único relatório, incluindo tráfego de rede gerado pelo app — mesmo princípio de sandbox visto em [Email Forensics](../Rede-e-Email/Email%20Forensics.md) para anexos maliciosos, aplicado a apps Android.

```bash
apktool d app_suspeito.apk -o app_decompilado
grep -i "uses-permission" app_decompilado/AndroidManifest.xml
```

---

## 8. Metodologia de Investigação (Checklist)

> [!todo] Como usar
> Sequência sugerida do momento da apreensão até o relatório final. A ordem entre as seções 4 e 5 pode se inverter dependendo se o dispositivo chega bloqueado ou já acessível.

- [ ] Isolar o dispositivo de rede imediatamente (Faraday bag / modo avião / remover SIM)
- [ ] Documentar estado inicial (ligado/desligado, tela, danos físicos)
- [ ] Identificar hardware e software (modelo, serial, IMEI, versão, patch, root?, lock status)
- [ ] Determinar se há credenciais disponíveis (cooperação da vítima vs dispositivo de suspeito)
- [ ] Se bloqueado: tentar ADB → MTP → bypass conhecido → ferramenta comercial (nessa ordem de menor para maior invasividade)
- [ ] Escolher imagem física (se viável e justificável) ou lógica
- [ ] Preservar hash da imagem/backup extraído imediatamente após a coleta
- [ ] Localizar e extrair bancos SQLite relevantes (SMS, apps de mensageria, contatos, browser)
- [ ] Checar arquivos `-wal`/`-journal` para dados não commitados
- [ ] Normalizar todos os timestamps (segundos x milissegundos) antes de montar a timeline
- [ ] Se aplicável, analisar APKs suspeitos (estática + dinâmica)
- [ ] Complementar com dados de nuvem (Google Takeout) quando houver autorização legal
- [ ] Documentar cadeia de custódia de cada interação com o dispositivo
- [ ] Compilar relatório final íntegro e imparcial

---

## 9. Cheatsheet de Comandos ADB

```bash
adb devices                                   # lista dispositivos conectados
adb shell                                     # abre shell no dispositivo
adb shell getprop                             # todas as propriedades do sistema
adb shell dumpsys                             # dump geral de estado do sistema
adb shell pm list packages                    # lista todos os pacotes instalados
adb pull /storage ./saida                     # copia recursivamente (imagem lógica)
adb backup -apk -all -f backup.ab             # backup nativo do sistema
adb install app.apk                           # instala um APK
adb logcat                                    # logs do sistema em tempo real
```

**Conversão de backup:**
```bash
java -jar abe.jar unpack backup.ab backup.tar
```

**SQLite:**
```bash
sqlite3 arquivo.db ".tables"
sqlite3 arquivo.db "SELECT * FROM nome_tabela LIMIT 10;"
```

---

## Ver também
- [iOS Forensics](iOS%20Forensics.md)
- [DFIR em Linux](../Linux/DFIR%20em%20Linux.md)
- [Forense de Memória em Linux](../Linux/Forense%20de%20Memória%20em%20Linux.md)
- [Forense Digital em Windows](../Windows/Forense%20Digital%20em%20Windows.md)
- [Network Forensics](../Rede-e-Email/Network%20Forensics.md)
- [Email Forensics](../Rede-e-Email/Email%20Forensics.md)
- [Anti-Forense e Ofuscação de Dados](../Anti-Forense/Anti-Forense%20e%20Ofuscação%20de%20Dados.md)
- [MITRE ATT&CK](../Threat-Intel/MITRE%20ATT&CK.md)
- [Malware](../Threat-Intel/Malware.md)
