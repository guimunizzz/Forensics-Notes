---
tags: [DFIR, MobileForensics, iOSForensics, SOC]
status: estudo em andamento
---

# iOS Forensics

> [!info] Sobre esta nota
> Se [[Android Forensics]] gira em torno de ADB + root para chegar direto ao `/data`, iOS Forensics gira em torno de **backup** — o sandboxing e a criptografia da Apple tornam a extração direta do sistema de arquivos algo raro fora de laboratório (chip-off) ou de um jailbreak. Por isso a maior parte desta nota trata de como obter, decriptar e analisar um backup do iTunes/Finder ou do iCloud — que na prática é o caminho real de 90% das investigações em dispositivos Apple não-jailbroken.

## Sumário
1. [Introdução ao iOS Forensics](#1-introdução-ao-ios-forensics)
2. [Sistema de Arquivos iOS](#2-sistema-de-arquivos-ios)
3. [Lidando com Backups Bloqueados](#3-lidando-com-backups-bloqueados)
4. [Lidando com Dados do iCloud](#4-lidando-com-dados-do-icloud)
5. [Arquivos Dentro do Backup](#5-arquivos-dentro-do-backup)
6. [Analisando o Backup com Python (iOSbackup)](#6-analisando-o-backup-com-python-iosbackup)
7. [Tópicos Complementares](#7-tópicos-complementares)
8. [Metodologia de Investigação (Checklist)](#8-metodologia-de-investigação-checklist)
9. [Cheatsheet de Referência Rápida](#9-cheatsheet-de-referência-rápida)

---

## 1. Introdução ao iOS Forensics

Forense digital em dispositivos Apple (iPhone/iPad) é um processo complexo. A evidência normalmente vive em memória **NAND flash**, e cópias bit a bit dessa memória podem ser obtidas via métodos de cópia física — mas na prática atual, isso raramente é viável sem hardware especializado ou jailbreak.

iOS entrega um volume enorme de dado útil: dados físicos e lógicos, informação de backup iTunes/iCloud, e dados de conexão/localização Wi-Fi/GPS. Por isso, ter **múltiplas ferramentas** de extração e análise é o que garante uma visão completa do caso.

### 1.1 Os três métodos de aquisição

| Método | Como funciona | Quando é viável |
|---|---|---|
| **Aquisição Lógica** | Explora vulnerabilidades no processo de boot para criar um RAM disk especial e acessar o SO | Depende de exploit/jailbreak específico da versão de iOS |
| **Aquisição Física** | Explora a natureza volátil da memória NAND para transferir uma cópia completa do SO para mídia física | Mais completa, mas exige acesso de baixo nível — raramente viável sem hardware especializado |
| **Aquisição por Sistema de Arquivos (Backup)** | Faz um **backup** do dispositivo e trabalha a partir dele | **O caminho mais comum e realista** — é o foco do restante desta nota |

> [!tip] Por onde começar na prática
> O estudo de iOS forensics começa criando um backup do dispositivo. O **iTunes** (ou Finder, em macOS mais recentes) é o método mais rápido e simples — copia tudo para o computador via protocolo próprio da Apple, sendo uma alternativa mais segura e menos invasiva que a cópia física.

---

## 2. Sistema de Arquivos iOS

### 2.1 Hierarquia e estrutura

O sistema de arquivos iOS é robusto e comprovado — o que, ironicamente, **complica** em vez de facilitar a forense digital. Entender essa estrutura a fundo é pré-requisito para superar os desafios da análise.

- **Root folder** contém subdiretórios divididos em domínios por uso (System, Library, Users, Shared Folders), acessados por caminhos que começam com `/`.
- Cada unidade de armazenamento é dividida em **blocos lógicos de 512 bytes** usados para armazenar metadados; **sparse files** permitem usar blocos vazios em certas circunstâncias, melhorando performance.
- Arquivos são organizados em estrutura de **árvore**, preservando atributos como permissão e propriedade — e rastreando mudanças para evitar deleção acidental.
- A Apple combina diretórios "amigáveis" do macOS (visíveis no Finder) com a hierarquia Unix por trás (`/bin`, `/usr`, `/var`) — nomes user-friendly por cima, estrutura Unix padrão por baixo.
- **APFS B-tree**: um tipo de B-tree derivado do Btrfs. Diferente do Btrfs (que usa um conjunto de códigos de manipulação), o APFS suporta **múltiplas B-trees** para diferentes tipos de metadado, incluindo um arquivo de **"space map overflow"** que rastreia quais blocos de alocação pertencem a quais arquivos.

### 2.2 Evolução: HFS+ → APFS

O sistema de arquivos evoluiu do **HFS+ (Hierarchical File System Plus)** para o **APFS (Apple File System)**, introduzido no **iOS 10.3**. O APFS trouxe melhorias em integridade de dados, velocidade e eficiência de armazenamento — cópia de arquivo mais rápida e confiável, melhor gestão geral de storage.

Outros pilares do sistema de arquivos iOS:
- **Sandboxing por app**: cada app só acessa seus próprios arquivos e recursos limitados do sistema (ver 2.4).
- **Criptografia automática**: iOS criptografa tudo por padrão, trabalhando junto com Touch ID/Face ID como camada extra.
- **Backup contínuo via iCloud**: restauração, sincronização entre dispositivos e armazenamento seguro de fotos/documentos/dados de app (ver seção 4).

### 2.3 Sistema de Arquivos local do macOS

Como o backup normalmente é processado em um Mac, vale entender a estrutura de arquivos do macOS que hospeda esse backup — ela é organizada em **domínios**:

| Domínio | Conteúdo | Quem gerencia |
|---|---|---|
| **User Domain** | Recursos do usuário logado — mostra apenas o diretório home do usuário atual | O próprio usuário |
| **Local Domain** | Apps específicos do computador, compartilhados entre todos os usuários — inclui boot/root | Sistema, mas admins podem adicionar/remover/modificar |
| **Network Domain** | Recursos compartilhados (apps/documentos) em servidores de arquivo de rede | Administrador de rede |
| **System Domain** | Software da própria Apple — recursos essenciais para o sistema funcionar | Ninguém — não é possível adicionar/remover/modificar |

Dentro de `/Users`, cada usuário tem seu diretório com as pastas padrão: `Applications`, `Desktop`, `Documents`, `Downloads`, `Library` (oculta desde macOS 10.7+), `Movies`, `Music`, `Pictures`, `Public`, `Sites`.

> [!tip] Onde o backup do iPhone mora no Mac
> Em versões atuais do macOS, os backups locais ficam em:
> `/Users/<nome_do_usuario>/Library/Application Support/MobileSync/Backup/`

### 2.4 App Sandbox

Mecanismo de segurança usado tanto em iOS quanto em macOS — cada app roda em ambiente isolado, com acesso **limitado e controlado** a recursos do sistema, dados de outros apps e dados do usuário.

O sandbox aplica quatro princípios de segurança:

| Princípio | O que garante |
|---|---|
| **Princípio do Menor Privilégio** | App só tem acesso ao mínimo necessário de recursos para funcionar |
| **Proteção de Dados do Usuário** | Acesso a dados pessoais só com consentimento explícito e quando necessário; compartilhamento entre apps via mecanismos seguros e controlados |
| **Isolamento** | Apps isolados entre si e do sistema — um app comprometido não acessa dados de outro nem componentes críticos do sistema |
| **Firewall** | O sandbox controla troca de dados pela rede, permitindo só conexões seguras e autorizadas |

> [!danger] O mesmo motivo que protege o usuário complica a forense
> O sandbox foi desenhado para privacidade e segurança — mas é exatamente essa arquitetura que torna a extração direta de dados de um iPhone (sem passar por backup) tão mais difícil que em Android. Entenda isso como o pano de fundo para todas as seções seguintes: quase todo caminho de acesso passa, de um jeito ou de outro, pelo mecanismo de backup.

---

## 3. Lidando com Backups Bloqueados

> [!danger] Autorização legal vem antes de tudo
> É essencial obter autorização legal apropriada **antes** de iniciar qualquer tentativa de acesso a um backup criptografado. Sem isso, ao tentar desvendar um incidente cibernético, você corre o risco de **se tornar cúmplice** dele. Leis de privacidade e proteção de dados variam por localização — pesquise a legislação aplicável antes de agir.

### 3.1 As duas senhas envolvidas

Um backup de iOS normalmente envolve **duas senhas diferentes**:

1. A senha do próprio dispositivo (a mesma usada para desbloquear a tela).
2. Uma segunda senha opcional, usada para **criptografar o backup** no momento em que ele é feito (opção "Encrypt local backup").

Backups feitos com essa opção **não podem ser abertos sem a senha** — os dados dentro ficam inacessíveis para análise.

> [!warning] Desde iOS 13, sem "Encrypt local backup" você perde dados críticos
> Se o backup for feito **sem** marcar "Encrypt local backup", os seguintes dados **não são incluídos**:
> - Senhas salvas
> - Configurações de Wi-Fi
> - Histórico de sites
> - Dados de saúde
> - Histórico de chamadas
>
> Ou seja: para uma investigação séria (que provavelmente precisa de Call History e histórico de navegação), a opção de criptografia **precisa** estar marcada — o que, ironicamente, também é o que impede o acesso sem a senha correta.

### 3.2 Brute Force em backups criptografados

Se a senha é desconhecida, a única saída é força bruta — e vale considerar empresas especializadas que oferecem esse serviço antes de tentar sozinho.

A própria documentação da Apple explica: o **backup keybag** é criado quando um backup criptografado é feito pelo iTunes, protegido pela senha definida no iTunes e processado por **10 milhões de iterações de PBKDF2**. Apesar disso, não há vínculo com um dispositivo específico — teoricamente um ataque de força bruta paralelizado em várias máquinas é possível contra o keybag, mitigado apenas por uma senha suficientemente forte.

O ponto prático mais importante: as chaves usadas no backup ficam em um arquivo chamado **`Manifest.plist`**, e a senha do backup criptografa apenas essas chaves — ou seja, **o que precisa ser quebrado não é o backup inteiro (que pode ter gigabytes), e sim um arquivo de poucos kilobytes**.

**Fluxo prático de brute force:**
```bash
# 1. Localizar o Manifest.plist no diretório de backup do Mac
#    /Users/<usuario>/Library/Application Support/MobileSync/Backup/<UDID>/Manifest.plist

# 2. Extrair o hash com o script itunes_backup2hashcat
#    (github.com/philsmd/itunes_backup2hashcat)
./itunes_backup2hashcat.pl Manifest.plist | tee captured_hashes.txt

# 3. O hash gerado começa com algo como "$itunes_backup$9"
#    O número após "$itunes_backup$" indica a versão do iOS do backup —
#    use esse número para confirmar o modo correto na documentação do Hashcat

# 4. Rodar o ataque de força bruta com Hashcat (modo 14700 = iTunes backup)
hashcat -a 3 -m 14700 --increment captured_hashes.txt
```

> [!tip] Performance importa (e muito)
> O tempo de quebra varia muito conforme complexidade da senha e poder de hardware. Máscaras do Hashcat ou wordlists customizadas ajudam a acelerar. Setups desktop padrão costumam ser insuficientes para isso em escala profissional — ambientes com múltiplas GPUs em paralelo são o padrão real de mercado. Sem saber exatamente o que está fazendo, é fácil tornar os dados **permanentemente inacessíveis** — na dúvida, busque ajuda profissional especializada.

---

## 4. Lidando com Dados do iCloud

A Apple usa o **iCloud** para armazenar e sincronizar dados do usuário — mídia, dados de app, backups de dispositivo, dados de saúde — protegido por criptografia robusta e 2FA. Importante: **nem todo dado no iCloud tem criptografia ponta a ponta** — a Apple mantém acesso a certas seções quando necessário.

Com **Advanced Data Protection** ativado, as chaves de criptografia ficam armazenadas em um dispositivo confiável em vez de no iCloud — acesso à conta passa a depender de ter o dispositivo físico ou as credenciais da conta iCloud. Isso reforça privacidade, mas complica análises quando apps não suportam totalmente a integração (ex.: o app Notes não sincroniza se a cota de armazenamento estourar).

A Apple exige certificados assinados e status de desenvolvedor aprovado para acessar serviços do iCloud programaticamente — **não há opção open-source/gratuita viável** por esse caminho. Isso empurra a maioria dos investigadores para **soluções comerciais**:

### 4.1 Ferramentas comerciais

| Ferramenta | Destaques |
|---|---|
| **ElcomSoft Phone Breaker** | Recupera backups do iCloud via credenciais de conta (backups iCloud são automáticos, diários, ao carregar em Wi-Fi — e diferente dos backups locais do iTunes, **não podem ser protegidos por senha**). Permite captura seletiva de dados essenciais (mensagens, anexos, configurações, chamadas, contatos, notas, calendário, e-mail, câmera) em minutos, pulando arquivos pesados como música/vídeo |
| **Magnet AXIOM** | Suporta múltiplas vias legais de aquisição — desde a v3.5 suporta Apple Warrant Returns; desde a v5.9, aquisição de backup iCloud (até iOS 15) via credenciais do usuário. Cobre dados de app, backups do Apple Watch, configurações, organização de tela, iMessage/SMS/MMS, fotos/vídeos, histórico de compra, ringtones, senha de correio de voz visual |

---

## 5. Arquivos Dentro do Backup

Em um diretório de backup iOS, além das áreas de dado, você encontra estes arquivos de controle:

### 5.1 Info.plist
Detalhes do dispositivo em **texto claro**: nome do dispositivo, build version, IMEI, número de telefone, data do último backup, versão do produto, tipo de produto, número de série, configurações de sincronização e nomes dos apps instalados.

### 5.2 Manifest.plist
Informação sobre o próprio backup — normalmente em formato **binário**. Para inspecionar manualmente, converta para XML com `plutil` (macOS):
```bash
plutil -convert xml1 Manifest.plist      # binário → XML (para ler)
plutil -convert binary1 Manifest.plist   # XML → binário (para reverter)
```
Dentro dele:
- Chave **`Applications`**: informação sobre os apps do dispositivo.
- Estrutura **`BackupKeyBag`**: se o backup é protegido por senha e se há PassCode configurado no dispositivo.
- Chave **`Lockdown`**: nome do dispositivo, modelo, versões de software/build e entradas relacionadas a apps instalados.

### 5.3 Status.plist
Também binário — indica se o backup é completo ou parcial, o **número de versão** do backup e o UUID do dispositivo.

> [!info] O número de versão importa para interpretar o resto
> Backups de versões diferentes têm layouts diferentes: na versão "2.4", todos os arquivos ficam no mesmo diretório; na versão "3.2", os arquivos são organizados em subdiretórios que começam com os dois primeiros caracteres do nome do arquivo.

### 5.4 Manifest.db
Banco **SQLite** com duas tabelas:

- **Files**: informação sobre cada arquivo copiado do dispositivo — arquivo de origem, localização dentro do backup, domínio do arquivo, e se o item é arquivo (`flags=1`) ou diretório (`flags=2`).
- **Properties**: propriedades adicionais associadas aos arquivos.

---

## 6. Analisando o Backup com Python (iOSbackup)

A biblioteca **iOSbackup** (Python 3.7+) funciona com backups de iOS 10 a iOS 15.

### 6.1 Instalação e listagem de dispositivos

```bash
pip3 install iOSbackup --user
```

```python
>>> from iOSbackup import iOSbackup
>>> iOSbackup.getDeviceList()
[{'udid': '00000000-00000004DD50CDDE', 'name': 'iPhone-1', 'ios': '17.1.1',
  'serial': 'LETSDEFEND02', 'type': 'iPhone15,3', 'encrypted': False,
  'passcodeSet': True, 'date': datetime.datetime(2024, 1, 31, 11, 8, 58, ...)}]
```

Selecionar o dispositivo pelo UDID:
```python
>>> bck = iOSbackup(udid="00000000-00000004DD50CDDE")
```

> [!tip] Backup fora do diretório padrão
> Se o backup foi movido de local, use os parâmetros `backuproot=` (e `cleartextpassword=` se aplicável):
> ```python
> bck = iOSbackup(udid="00456030-000E4412342802E", cleartextpassword="minhasenha", backuproot='/caminho/para/backup')
> ```

### 6.2 Informações do dispositivo

```python
>>> infoKeys = ['Build Version', 'Device Name', 'IMEI', 'Last Backup Date',
...             'Phone Number', 'Product Type', 'Product Version', 'Serial Number']
>>> for i in infoKeys:
...     print(f'{i}: {bck.info[i]}')
```

Também é possível acessar diretamente via chaves `Lockdown` do manifest:
```python
>>> bck.manifest['Lockdown']['ProductType']
'iPhone15,3'
>>> bck.manifest['Lockdown']['ProductVersion']
'17.1.1'
```

### 6.3 Listando apps instalados

```python
>>> bck.info['Applications'].keys()
dict_keys(['com.apple.Keynote', 'com.burbn.instagram', 'com.google.Maps',
           'com.microsoft.skype.teams', 'us.zoom.videomeetings', ...])
```
Para detalhes completos (caminho, versão, classe de conteúdo), consulte `bck.manifest['Applications']`.

### 6.4 Histórico de Chamadas

```python
>>> file = bck.getFileDecryptedCopy(relativePath="Library/CallHistoryDB/CallHistory.storedata")
>>> calls = sqlite3.connect(file['decryptedFilePath'])
>>> calls.row_factory = sqlite3.Row
>>> calllog = calls.cursor().execute("SELECT * FROM ZCALLRECORD ORDER BY ZDATE DESC").fetchall()
>>> for row in calllog:
...     print(f"Date: {row['ZDATE']}, Status: {row['ZANSWERED']}, Duration: {row['ZDURATION']}")
```

**Campos relevantes da tabela `ZCALLRECORD`:**

| Campo | Significado |
|---|---|
| `Z_ENT` | Tipo de chamada (1=Recebida, 2=Realizada) |
| `ZDATE` | Data/hora da chamada (⚠️ formato Mac Absolute Time — ver seção 7.5) |
| `ZDURATION` | Duração em segundos |
| `ZADDRESS` | Número, e-mail ou FaceTime ID do outro participante |
| `ZNAME` | Nome do contato, se associado na agenda |
| `ZISO_COUNTRY_CODE` | Código do país do número |
| `ZSERVICE_PROVIDER` | Operadora (ex.: Vodafone, T-Mobile) |
| `ZANSWERED` | Se foi atendida (1=Sim, 0=Não) |
| `ZCALLTYPE` | 0=App terceiro, 1=Chamada padrão, 8=FaceTime completo, 6=FaceTime só áudio |
| `ZDISCONNECTED_CAUSE` | Motivo de desconexão (0=Encerrada, 6=Rejeitada) |
| `ZORIGINATED` | Se foi iniciada pelo usuário (1=Saída, 0=Entrada) |
| `ZREAD` | Se foi vista pelo usuário (1=Vista, 0=Não vista) |
| `ZLOCATION` | Localização geográfica aproximada (só se serviços de localização estavam ativos) |

### 6.5 Fotos do dispositivo

```python
>>> bck.getFolderDecryptedCopy(
...     'Media',
...     targetFolder='restored-photos',
...     includeDomains='CameraRollDomain',
...     excludeFiles='%.MOV'
... )
```
Copia tudo do `CameraRollDomain` (excluindo `.MOV` neste exemplo) para `restored-photos/`. As fotos ficam acessíveis em `restored-photos/CameraRollDomain/Media/DCIM/100APPLE`.

### 6.6 Busca por aplicativo específico

```python
>>> [s for s in list(bck.manifest['Applications'].keys()) if "skype" in s]
['com.microsoft.skype.teams', 'com.microsoft.skype.teams.extScreenShare', ...]

>>> for id in [s for s in list(bck.manifest['Applications'].keys()) if "skype" in s]:
...     for prefix in ["AppDomain", "AppDomainGroup", "AppDomainPlugin"]:
...         bck.getFolderDecryptedCopy(targetFolder='skype_data-folder', includeDomains=prefix + '-' + id)
```
Busca todo conteúdo relacionado a "skype" (apps, grupos, plugins) e decripta/copia para `skype_data-folder` — reflexo direto do sandboxing coberto na seção 2.4: cada app tem suas próprias pastas `Library`/`Documents` isoladas dentro do domínio.

### 6.7 SMS

Mensagens SMS ficam em `Library/SMS/sms.db`:
```python
>>> file = bck.getFileDecryptedCopy(relativePath="Library/SMS/sms.db")
>>> smsdatas = sqlite3.connect(file['decryptedFilePath'])
>>> smsdatas.row_factory = sqlite3.Row
>>> smsdata = smsdatas.cursor().execute("SELECT * FROM message;").fetchall()
>>> for row in smsdata:
...     print(f"Date: {row['date']}, Read_Date: {row['date_read']}, Message: {row['text']}")
```

> [!warning] Cuidado com a mesma restrição da seção 3.1
> Se o backup analisado não foi feito com "Encrypt local backup" marcado, é bem provável que a tabela venha **vazia** — não porque não há mensagens no dispositivo, mas porque o iOS 13+ simplesmente não inclui esses dados em backup não criptografado. Sempre confirme qual tipo de backup você está analisando antes de concluir "não há evidência".

---

## 7. Tópicos Complementares

> [!info] Sobre esta seção
> O material original termina prometendo uma tabela de "Analyzable iOS Backup Files" que não chegou a ser detalhada. Esta seção preenche essa lacuna e adiciona o que mais falta: aquisição em dispositivo jailbroken, o Keychain (o cofre de credenciais do iOS), e a pegadinha de timestamp mais comum nessa plataforma.

### 7.1 Tabela de artefatos analisáveis (preenchendo a lacuna do material)

| Domínio | Caminho relativo | Conteúdo |
|---|---|---|
| HomeDomain | `Library/SMS/sms.db` | SMS/iMessage |
| HomeDomain | `Library/CallHistoryDB/CallHistory.storedata` | Histórico de chamadas |
| HomeDomain | `Library/AddressBook/AddressBook.sqlitedb` | Contatos |
| HomeDomain | `Library/Calendar/Calendar.sqlitedb` | Calendário |
| HomeDomain | `Library/Notes/NoteStore.sqlite` | Notas |
| HomeDomain | `Library/Safari/History.db` | Histórico de navegação Safari |
| HomeDomain | `Library/Safari/Bookmarks.db` | Favoritos do Safari |
| HomeDomain | `Library/Voicemail/voicemail.db` | Correio de voz |
| CameraRollDomain | `Media/DCIM/` | Fotos e vídeos |
| WirelessDomain | `Library/Preferences/com.apple.wifi.plist` | Redes Wi-Fi conhecidas |
| KeychainDomain | `Keychain-backup.plist` | Credenciais armazenadas (ver 7.4) |
| AppDomain(Group)-\<bundle id\> | Varia por app | Dados isolados por app (ex.: WhatsApp → `ChatStorage.sqlite`) |

### 7.2 Física x Lógica x Sistema de Arquivos — comparação rápida

| | Física | Lógica | Sistema de Arquivos (Backup) |
|---|---|---|---|
| Completude | Máxima (inclui espaço não alocado) | Média | Alta para dados de usuário, zero para dados de sistema |
| Dificuldade | Altíssima — exige exploit/hardware | Alta — depende de vulnerabilidade de boot | Baixa — ferramentas padrão da Apple já fazem isso |
| Risco ao dispositivo | Alto | Médio | Baixo |
| Uso real em campo | Raro, quase sempre em laboratório especializado | Raro fora de pesquisa | **O padrão de facto** |

### 7.3 Jailbreak e forense

Um dispositivo **jailbroken** (via ferramentas como checkra1n ou unc0ver, dependendo da versão de iOS/chipset) remove as restrições de sandboxing do SO, permitindo acesso root ao sistema de arquivos completo — algo próximo do que ADB+root oferece em [[Android Forensics]].

> [!warning] Jailbreak como técnica forense é uma faca de dois gumes
> Jailbreak em um dispositivo apreendido **modifica o sistema** — o mesmo tipo de preocupação de cadeia de custódia já discutido para root em Android. Só deve ser considerado quando backup e aquisição comercial não são suficientes, e com documentação extremamente detalhada de cada passo.

### 7.4 Keychain — o cofre de credenciais do iOS

O **Keychain** é o armazenamento seguro de credenciais do iOS — senhas de Wi-Fi, senhas de app, tokens. Já mencionado na seção 3 no contexto do `BackupKeyBag`: itens do Keychain **não-migratórios** permanecem protegidos por uma chave derivada do UID do dispositivo, o que significa que só podem ser restaurados no **mesmo dispositivo** de origem — outro motivo pelo qual, sem senha de backup definida, itens de Keychain não migram para um dispositivo diferente.

Para o investigador, isso significa: mesmo com um backup decriptado em mãos, alguns segredos do Keychain podem continuar inacessíveis fora do hardware original — uma limitação estrutural, não uma falha da ferramenta de análise.

### 7.5 Pegadinha de timestamp: Mac Absolute Time

Diferente do Unix epoch (segundos desde 01/01/1970) usado na maioria dos bancos SQLite em [[Android Forensics]], campos como `ZDATE` em bancos do iOS (Core Data / Cocoa) usam **Mac Absolute Time**: segundos desde **01/01/2001 00:00:00 UTC**.

**Conversão prática:**
```bash
# offset entre 1970 e 2001 em segundos = 978307200
date -d @$((ZDATE_VALOR + 978307200))
```
```python
from datetime import datetime, timedelta
mac_epoch = datetime(2001, 1, 1)
data_real = mac_epoch + timedelta(seconds=ZDATE_VALOR)
```

> [!danger] Erro clássico em investigação de iOS
> Tratar um valor de `ZDATE` como Unix epoch puro desloca a data em **31 anos** — um erro fácil de cometer e que já comprometeu timelines em casos reais. Sempre confirme qual epoch está em uso antes de reportar uma data extraída de banco iOS.

### 7.6 Ferramentas comerciais adicionais

Além de ElcomSoft e Magnet AXIOM (seção 4.1), duas ferramentas dominam o mercado de aquisição avançada em iOS quando backup não é suficiente: **Cellebrite Premium** (bypass físico avançado, inclusive em dispositivos bloqueados) e **GrayKey** (da Grayshift, focado especificamente em bypass de tela de bloqueio iOS). Ambas exigem licenciamento e uso por entidade autorizada — não são ferramentas de acesso público.

---

## 8. Metodologia de Investigação (Checklist)

> [!todo] Como usar
> Sequência sugerida da apreensão do dispositivo até o relatório final.

- [ ] Confirmar autorização legal antes de qualquer tentativa de acesso (seção 3)
- [ ] Determinar se há backup existente (Mac/iTunes) ou se será necessário criar um
- [ ] Se for criar backup, garantir que "Encrypt local backup" está marcado (senão perde Call History, Wi-Fi, Health, senhas, histórico web)
- [ ] Se o backup está criptografado e a senha é desconhecida, avaliar viabilidade de brute force (`itunes_backup2hashcat` + Hashcat modo 14700) ou acionar especialista
- [ ] Localizar `Info.plist`, `Manifest.plist`, `Status.plist` e `Manifest.db` para entender a versão e estrutura do backup antes de extrair dados
- [ ] Usar a biblioteca `iOSbackup` (ou ferramenta equivalente) para listar dispositivo, apps e extrair artefatos-alvo
- [ ] Cruzar contra a tabela de domínios/artefatos da seção 7.1 para não deixar fonte de evidência esquecida
- [ ] Converter corretamente todo timestamp Mac Absolute Time antes de montar a timeline (seção 7.5)
- [ ] Se dados relevantes não estiverem no backup local, avaliar aquisição via iCloud (ElcomSoft/Magnet AXIOM)
- [ ] Documentar cada ferramenta e comando usado, com timestamps de cada ação, para a cadeia de custódia
- [ ] Compilar relatório final íntegro e imparcial

---

## 9. Cheatsheet de Referência Rápida

**Conversão de plist:**
```bash
plutil -convert xml1 Manifest.plist
plutil -convert binary1 Manifest.plist
```

**Brute force de backup:**
```bash
./itunes_backup2hashcat.pl Manifest.plist | tee captured_hashes.txt
hashcat -a 3 -m 14700 --increment captured_hashes.txt
```

**Python — iOSbackup:**
```python
from iOSbackup import iOSbackup
iOSbackup.getDeviceList()
bck = iOSbackup(udid="UDID_DO_DISPOSITIVO")
bck.getFileDecryptedCopy(relativePath="Library/SMS/sms.db")
bck.getFolderDecryptedCopy('Media', targetFolder='saida', includeDomains='CameraRollDomain')
```

**Conversão de Mac Absolute Time:**
```bash
date -d @$((VALOR_ZDATE + 978307200))
```

**Caminho padrão de backup local (macOS):**
```
/Users/<usuario>/Library/Application Support/MobileSync/Backup/
```

---

## Ver também
- [[Android Forensics]]
- [[Windows Forensics]]
- [[Linux Forensics]]
- [[Email Forensics]]
- [[Network Forensics]]
