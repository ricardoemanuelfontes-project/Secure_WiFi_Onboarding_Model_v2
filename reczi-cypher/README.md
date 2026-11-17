# Reczi cypher

App Android para encriptar e desencriptar mensagens com OpenPGP, compatível com o GnuPG
(e com o `cofre` / Cofre PGP do Debian).

- **Chaves**: criar (Curve25519: ed25519 + cv25519, ou RSA 4096 se precisares; válida 2 anos), importar a tua chave privada
  do computador, partilhar a chave pública, backup da privada, prolongar a validade.
- **Contactos**: importar chaves públicas (colar, ficheiro ou partilhar a partir de outra app) e
  verificar a impressão digital. Só se pode encriptar para contactos verificados.
- **Encriptar**: para um ou vários destinatários, sempre também para ti, assinado por omissão.
  Também podes escolher só a tua própria chave (uma nota para ti).
- **Desencriptar**: mostra o texto só depois de confirmar a integridade, e diz quem assinou.
  O botão "Responder" abre o Encriptar já com o remetente escolhido.
- **Avisos de validade**: ao abrir, a app avisa das chaves que expiram nos próximos 30 dias.
- **Assinar e verificar** (sem encriptar): texto assinado em claro, pronto a enviar por email
  (por exemplo a um CERT), e ficheiros com a assinatura à parte (`nome.asc`, que o GnuPG verifica
  com `gpg --verify nome.asc nome`). Verifica textos assinados e ficheiros com `.asc` ou `.sig`.
- **Revogar e mudar a palavra-passe**: revogar uma chave (para sempre: deixa de assinar, e os
  contactos deixam de encriptar para ela quando importarem a pública revogada; as mensagens
  antigas continuam a abrir), guardar antes um certificado de revogação, e mudar a palavra-passe.
- **Sem "Version:"**: as mensagens, assinaturas e chaves exportadas não dizem que programa as fez.
- **Ficheiros e fotografias**: "Encriptar um ficheiro…" usa os destinatários escolhidos e guarda
  um `.pgp` normal (abre também no GnuPG); "Desencriptar um ficheiro…" faz o inverso. Se a
  desencriptação falhar, o ficheiro incompleto é apagado.
- **Notas**: bloco de notas encriptado para as tuas chaves. Guardar não pede nada; ler pede a
  palavra-passe. O título de cada nota fica visível na lista e não é protegido pela palavra-passe.
- **QR**: "Mostrar QR" mostra a tua chave pública; "Ler QR" em Contactos importa a de outra pessoa
  com a câmara (ou de uma fotografia). A verificação da impressão digital continua a ser pedida.
- **Chaves grandes (RSA)**: não cabem num só QR, por isso vão em vários códigos (3 para uma
  pública RSA 4096, 5 para a privada), mostrados ou impressos em sequência e lidos um a um, por
  qualquer ordem; a app diz quais faltam.
- **Backup em papel**: imprime a chave privada (protegida pela palavra-passe) em QR e em texto;
  restaura-se em Chaves > Importar > Ler QR.

## Organização da app

Uma barra em cima com **☰** (menu), o nome do ecrã e **? Ajuda**. O menu lateral está agrupado:

- **Mensagens**: Escrever (encriptar), Ler (desencriptar), Colar e detetar.
- **Assinaturas**: Assinar e verificar.
- **Pessoas e chaves**: Contactos, As minhas chaves.
- **Outros**: Notas, Definições (bloqueio e backup completo), Como funciona.

Em cada chave, as ações menos usadas estão em dois submenus: **Backup…** (ficheiro, papel,
certificado de revogação) e **Mais opções…** (copiar/enviar a pública, prolongar validade, mudar a
palavra-passe, impressão digital, revogar, apagar). O menu só abre com a app desbloqueada, e o
botão "voltar" fecha-o ou regressa às Mensagens.

- **Colar e detetar**: em Mensagens, vê o que está na área de transferência e leva-o para o sítio
  certo (mensagem para Ler, chave pública para Contactos, texto normal para Escrever).
- **Conversa**: num contacto verificado, abre as Mensagens viradas para ele, com o formato e a
  opção do código secreto usados da última vez, e um atalho "Colar o que recebi".
- **Convidar**: em Contactos, partilha a tua chave pública com instruções para quem ainda não usa
  a app. Ao importar, a app tira a chave do meio do texto.
- **Impressão digital em palavras**: ao verificar um contacto (e em "Mostrar QR"), a impressão
  digital aparece também como 20 palavras portuguesas, mais fáceis de ler em voz alta.

## Backup completo

Em ☰ > Definições, "Guardar backup…" cria um só ficheiro (`.rczbak`) com as chaves privadas, os
contactos e as verificações, os códigos secretos e as notas; "Restaurar…" junta-o ao cofre de
outro telemóvel, sem apagar nem substituir o que lá estiver. Os PINs da app não vão.

O ficheiro é cifrado com AES-256-GCM, com a chave derivada da palavra-passe do backup por scrypt.
As chaves privadas lá dentro continuam protegidas pela sua própria palavra-passe.

**Importar qualquer backup pela mesma porta** (1.4.1): em ☰ > As minhas chaves > Importar (ou em
Restaurar) a app reconhece sozinha o que escolheste e leva-o ao sítio certo: a chave de um
"Backup…" (`.asc`), o backup completo (`.rczbak`), um backup protegido com palavra-passe ou código
(como o do OpenKeychain, `.sec.pgp`, ou um ficheiro de `gpg --symmetric`; o código pode ser escrito
com ou sem hífenes) ou uma chave exportada de outro programa (GnuPG, Kleopatra, Proton…). As chaves
públicas de contactos que venham num backup do OpenKeychain são importadas a seguir.

## Ajuda dentro da app

- **Bem-vindo**: na primeira abertura sem chaves, uma explicação curta de como funciona.
- **Primeiros passos**: em As minhas chaves, uma lista (criar chave, backup, trocar chaves,
  verificar) que se vai riscando sozinha e desaparece quando está tudo feito.
- **? Ajuda**: em cada ecrã, explica o que esse ecrã faz.
- **Lembrete de backup**: cada chave sem backup registado mostra um aviso, e definir o PIN de
  pânico sem backup pede confirmação. Conta como backup: guardar em ficheiro, imprimir em papel,
  ou a chave ter sido importada. O registo fica só nas preferências da app.

## Bloqueio da app

Em ☰ > Definições:

- **Impressão digital / bloqueio do telemóvel**: pedido ao abrir e depois de 1 minuto fora da app.
- **PIN da app**: um PIN próprio (guardado só como scrypt com sal). A partir da 5.ª tentativa
  errada, há uma espera que vai duplicando (30 s, 1 min… até 1 h). A espera conta pelo tempo
  desde que o telemóvel ligou, não pela hora: mudar a hora nas definições não a salta (até à 1.4.4
  saltava), e reiniciar o telemóvel faz a espera começar de novo.
- **PIN de pânico**: escrito no ecrã de bloqueio, apaga tudo (ficheiros do cofre e a chave do
  Keystore) e abre a app vazia. Não há volta.

O bloqueio é uma porta, não uma cifra: trava quem pega no telemóvel desbloqueado. A chave do
Keystore não fica presa à impressão digital, de propósito: o Android destrói chaves dessas quando
se tira o bloqueio de ecrã, e o cofre perdia-se. As chaves privadas continuam protegidas pela
palavra-passe OpenPGP.

Não conseguir ler o PIN nunca deixa entrar (1.4.6): se a app não consegue confirmar se há PIN
(o telemóvel bloqueou durante a abertura, ou o Keystore não respondeu), não abre o cofre e volta a
perguntar ao tentar de novo. Até à 1.4.5, um erro a ler o PIN contava como "não há PIN".

## Palavra-passe com impressão digital (opcional)

Em As minhas chaves, cada chave tem "Mais opções… > Usar a impressão digital" (Android 11 ou mais
recente, com bloqueio de ecrã). Escreve-se a palavra-passe uma última vez; depois, para assinar,
desencriptar, abrir notas e prolongar a validade basta a impressão digital ou o PIN/padrão do
telemóvel. Também aparece como opção ("Da próxima vez, usar a impressão digital") na janela que
pede a palavra-passe.

A palavra-passe fica cifrada (AES-256-GCM) com uma chave do Keystore que exige a confirmação do
dono em cada utilização (impressão digital de classe forte ou o bloqueio do telemóvel), e só com o
telemóvel desbloqueado. Se se juntar uma impressão digital nova ou se tirar o bloqueio de ecrã, o
Android invalida essa chave: a palavra-passe guardada deixa de servir e escreve-se de novo. Perder
isto não faz perder nada (as chaves continuam no cofre). Fica guardada dentro do cofre (cifrada
também com a chave dele), por isso nenhum nome de ficheiro tem o fingerprint da chave. O PIN de
pânico apaga-a também. Não usa o
PIN da app, de propósito: um PIN de 4 algarismos protegeria a palavra-passe muito menos do que o
chip de segurança do telemóvel.

## Modo disfarçado

Uma mensagem PGP normal vê-se logo que é PGP (`-----BEGIN PGP MESSAGE-----`). Em "Formato" podes
escolher a aparência. Por baixo são todos iguais (a mesma mensagem OpenPGP, com a mesma camada de
disfarce); só muda a forma de a escrever, e quem recebe não escolhe nada: a app reconhece o formato.

- **PGP normal**: abre em qualquer programa OpenPGP.
- **Disfarçado: código**: uma linha de letras e números ao acaso, sem cabeçalhos. O mais curto.
- **Disfarçado: poema**: versos em português, em quadras ("Sobre o muro querido morre um luar").
  Cada palavra de três listas (substantivos, adjetivos, verbos) leva um byte.
- **Disfarçado: crónica do dia-a-dia**: as novidades da semana ("No sábado à noite, a avó Graça fez
  cozido à portuguesa para toda a família."), com provérbios e expressões.
- **Disfarçado: diário de viagem**: uma volta por Portugal, com terras, tascas e monumentos.
- **Disfarçado: relato de futebol**: lances, faltas e substituições ("Pouco depois, Rui Matos
  arranca pela esquerda e remata de longe!").
- **Disfarçado: letra de rap**: barras rimadas aos pares, com deuses antigos, futebol e géneros
  musicais ("Do amapiano à kizomba, celebro o manjar").
- **Disfarçado: letra de rap 2** (1.4.4): como a letra de rap, com heróis, musas e criaturas ao
  lado dos deuses ("Sou Anansi no dancehall, sigo a segurança"). O mesmo nome nunca aparece duas
  vezes na mesma barra, há 14 barras diferentes em vez de 10, e 12 aberturas e 12 fechos que às
  vezes nem aparecem: o princípio e o fim deixam de ser uma marca fácil de procurar. A letra de
  rap antiga continua no menu e a abrir; quem recebe a 2 precisa da versão 1.4.4.

Os textos corridos são moldes de frase com espaços, e cada espaço tem a sua lista de opções, à
medida daquele sítio da frase; cada opção guarda alguns bits (ver `Prose.kt` e `Books.kt`).
As listas evitam palavras de duplo sentido e números. Em todos os formatos de texto, maiúsculas,
acentos, pontuação e quebras de linha não contam ao ler, por isso sobrevivem ao que as apps de
mensagens fazem. O antigo formato "palavras" (palavras soltas) já não se oferece, mas continua a
abrir.

Tamanho, para uma mensagem curta (medido nos testes; depois de encriptar a app mostra o tamanho):

| Formato | Chave ECC, normal | ECC, compacto | Chave RSA, normal | RSA, compacto |
|---|---|---|---|---|
| Poema | 113 versos | 58 versos | 460 versos | 170 versos |
| Crónica | 155 frases | 78 frases | 606 frases | 228 frases |
| Diário de viagem | 218 frases | 107 frases | 859 frases | 315 frases |
| Relato de futebol | 149 frases | 70 frases | 575 frases | 218 frases |
| Letra de rap | 130 barras | 64 barras | 526 barras | 190 barras |
| Letra de rap 2 | 148 barras | 76 barras | 590 barras | 216 barras |

Com chaves RSA, as mensagens PGP são cerca de 4 vezes maiores. Para os textos corridos, o modo
compacto ajuda muito.

**Modo compacto** (em Escrever): a mensagem vai sem assinatura e sem cópia para ti, e fica com menos
de metade do tamanho (175 em vez de 398 bytes numa mensagem curta). Em troca, o destinatário não
confirma que é tua e tu não a consegues reler.

A chave pública também pode ser partilhada disfarçada. A app reconhece sozinha um texto disfarçado
ao colar, importar ou receber por partilha.

### Desfazedor de disfarce (no computador)

Um pequeno programa Java que tira o disfarce e mostra o PGP normal que está por baixo, sem a app e
sem Internet. Usa o mesmo código da app, por isso lê exatamente os mesmos formatos. Não desencripta
nada nem pede chaves privadas: só tira a camada de fora.

```bash
./gradlew :core:desfazerJar                         # core/build/libs/reczi-desfazer.jar
java -jar reczi-desfazer.jar mensagem.txt           # escreve o PGP que está por baixo
java -jar reczi-desfazer.jar mensagem.txt | gpg -d  # e o GnuPG desencripta
java -jar reczi-desfazer.jar --codigo --chaves <impressão digital> <impressão digital> mensagem.txt
                                                    # com código secreto (pede a frase; as duas
                                                    # impressões digitais desde a 1.4.6)
```

Serve para confirmar, de fora, que o disfarce só esconde PGP normal, e para ler no computador uma
mensagem disfarçada. Também é reprodutível: o mesmo commit dá sempre o mesmo `.jar`.

Como as mensagens disfarçadas não dizem para que chave são (ver Destinatários escondidos, abaixo), o
GnuPG escreve "anonymous recipient" e experimenta as tuas chaves secretas. A cópia de quem envia vai
em primeiro lugar na mensagem para o GnuPG de quem recebe acertar à primeira, sem avisos.

### Código secreto por contacto (opcional)

Em Contactos, num contacto verificado, podes combinar um **código secreto**: uma frase que os dois
escrevem, cada um na sua app (combinada em pessoa ou por chamada). A app mostra seis algarismos de
confirmação, que têm de ser iguais nos dois telemóveis. Depois, em Encriptar, com um formato
disfarçado e só esse destinatário, aparece a opção "Fechar com o código secreto", desligada por
omissão: marca-se quando se quer usar, e a escolha fica lembrada para esse contacto.

Com o código, a camada de fora passa a ser uma segunda cifra a sério (ChaCha20, com chave derivada
da frase por scrypt): sem a frase, nem com a app se consegue ver que por baixo está PGP. Desde a
versão 1.4 é ChaCha20 e não AES, porque o OpenPGP por baixo já usa AES: assim são dois algoritmos
diferentes com chaves independentes (uma "cascata"), e se um dia um deles falhar o outro continua a
proteger. As mensagens com código feitas antes da 1.4 (AES) continuam a abrir. Fica guardada
só a chave derivada, dentro do cofre. Se mudarem a frase, as mensagens antigas com código deixam de
abrir.

**Sal das duas chaves (1.4.6).** Até à 1.4.5, o scrypt usava um sal fixo, igual para toda a gente:
quem preparasse uma tabela de frases comuns podia usá-la contra as mensagens de todos ao mesmo
tempo. Agora o sal leva as impressões digitais das duas chaves (a tua e a do contacto, por ordem),
que são públicas e que os dois já confirmaram: cada par de pessoas tem o seu próprio espaço de
procura, e quem apanha uma mensagem nem sabe a que par pertence (os disfarces não levam os ids das
chaves). Contra quem ataca o vosso par em concreto, o que protege continua a ser uma frase longa e
pessoal.

- Não há interruptor "o outro já atualizou": ao combinarem o código, os algarismos só coincidem se as
  duas apps forem da 1.4.6 ou mais recentes. Se no telemóvel do outro aparecerem os algarismos que a
  app indica como "de uma app antiga", atualizem os dois antes de usar o código.
- Os códigos combinados antes da 1.4.6 continuam a funcionar como antes, com o aviso de que são da
  versão antiga. Para os reforçar, combinem-nos de novo, os dois (pode ser a mesma frase): as
  mensagens antigas continuam a abrir.
- Com várias chaves tuas, a app mostra os algarismos de cada uma (coincidem os da chave que o
  contacto tem). Uma chave criada depois de combinarem o código não o tem: para a usares com esse
  contacto, combinem-no de novo.
- No desfazedor: `java -jar reczi-desfazer.jar --codigo --chaves <a tua impressão digital> <a do contacto> mensagem.txt`.

Limites do disfarce sem código secreto, para não haver ilusões:

- Só quem usa o Reczi cypher (ou o desfazedor acima) consegue tirar o disfarce; o GnuPG sozinho não.
- É camuflagem, não é segurança a mais: a chave do disfarce é fixa e está dentro da app, por isso
  quem tiver a app consegue ver que por baixo está PGP. O segredo da mensagem continua a depender
  só do OpenPGP.
- Esconde que é PGP, não esconde que é texto cifrado.

**Destinatários escondidos (1.4.6).** As mensagens disfarçadas não levam os ids das chaves para que
foram encriptadas (ficam a zeros, como com o `--throw-keyids` do GnuPG). Quem tirar o disfarce, com
a app ou com o desfazedor, vê que é PGP mas não para quem é nem quem o enviou: a assinatura vai lá
dentro, cifrada. Quem recebe experimenta as chaves que tem. O "PGP normal" continua com os ids,
porque pode ir para outros programas OpenPGP. Se tiveres várias chaves e a palavra-passe (ou a
impressão digital) abrir a errada, a app diz-te e pede a da outra. As versões anteriores da app já
abriam mensagens assim.

## Segurança

- **Sem Internet**: a app não tem acesso à rede. Os ficheiros só entram e saem quando os
  escolhes. Permissões: `HIDE_OVERLAY_WINDOWS`, para esconder janelas de outras apps por cima
  desta (Android 12+; os toques são ignorados quando há algo por cima), e `CAMERA`, pedida só
  quando carregas em "Ler QR" (as imagens não são guardadas, e podes recusar e usar uma fotografia).
- **Chaves privadas protegidas em duas camadas**:
  1. A palavra-passe OpenPGP (mínimo 12 caracteres): AES-256, SHA-512 iterado com sal,
     65 011 712 iterações. É o máximo do formato que o GnuPG 2.4 também aceita.
  2. Cada ficheiro do cofre é cifrado com AES-256-GCM, com uma chave do Android Keystore
     (StrongBox quando existe) que não sai do chip de segurança do telemóvel.
- **Cofre só com o telemóvel desbloqueado (1.4.6, Android 15 ou mais recente).** A chave do cofre
  só funciona com o telemóvel desbloqueado: quando bloqueia, o Android tira-a da memória, e nem
  quem consiga correr código como a app (uma ferramenta forense num telemóvel apreendido ligado,
  por exemplo) abre o cofre. Os cofres que já existiam mudam de chave sozinhos na primeira abertura
  com o Android 15: cada ficheiro é cifrado de novo, um a um, e se a app parar a meio continua na
  vez seguinte, sem perder nada. Em ☰ > Definições aparece se está ligado.
  - Não se usa antes do Android 15: do 12 ao 14, tirar o bloqueio de ecrã apagava estas chaves (e
    com elas o cofre), e sem bloqueio de ecrã nem funcionavam. O Android 15 corrigiu isso.
  - Se tiveres um desbloqueio "fraco" ligado (reconhecimento facial que não seja de classe 3, ou
    Smart Lock / desbloqueio prolongado), o Android guarda a chave em memória enquanto esse
    desbloqueio valer, e esta proteção perde-se nesse tempo.
  - Com o telemóvel bloqueado a meio de uma operação, a app diz "O telemóvel bloqueou" e não toma
    isso por ficheiros estragados: nada vai para o lado, nada se apaga.
- Os dados ficam em `noBackupFilesDir` e estão excluídos de cópias de segurança e de transferências
  para outro telemóvel. **Se desinstalares a app, as chaves desaparecem: faz backup.**
- **Nada de pessoal fora do cofre (1.4.3)**. Os nomes dos ficheiros do cofre são aleatórios
  (`v2-<aleatório>`); o nome de cada entrada (que tem o fingerprint do contacto ou da chave) está
  lá dentro, cifrado, e um índice cifrado liga uns aos outros. Quem copiar os ficheiros não fica a
  saber de quem são as chaves, com quem há código secreto, nem se há PIN de pânico: só quantos
  ficheiros há. O formato usado com cada contacto, as chaves com backup e o formato escolhido
  também ficam no cofre (até à 1.4.2 estavam em claro nas preferências do Android). Nas
  preferências do Android só ficam opções sem nada de pessoal (modo compacto, bloqueio por
  impressão digital, contador de PIN errado). Os cofres antigos passam para o formato novo na
  primeira abertura.
- **Capturas de ecrã bloqueadas** (`FLAG_SECURE`), na janela principal e em cada diálogo.
- **Serviços de acessibilidade (Android 14+)**: o conteúdo da app fica escondido dos serviços de
  acessibilidade que não são ferramentas de acessibilidade. Esses serviços conseguem ler tudo o que
  está no ecrã (é o truque mais usado pelo spyware no Android) e o bloqueio de capturas não os
  trava. O TalkBack e as outras ferramentas de acessibilidade continuam a funcionar.
- **Teclado e área de transferência**: o teclado não aprende o que escreves, e o preenchimento
  automático está desligado. O texto desencriptado não é selecionável. Ao copiá-lo pelo botão, é
  marcado como sensível e apagado da área de transferência após ~45 s, por um alarme do sistema que
  funciona mesmo com a app fechada.
- **Contactos**: as chaves públicas são validadas antes de serem guardadas, e as subchaves que
  não pertencem à chave são retiradas. Na verificação de assinaturas, as tuas chaves e os contactos
  verificados têm prioridade, por isso uma chave importada não consegue fazer-se passar por eles.
- **Cofre robusto**: um ficheiro estragado não impede o acesso ao resto. Se o telemóvel perder a
  chave do Keystore, a app avisa e não apaga nada.
- **Mensagens em claro** são apagadas do ecrã quando ficas mais de 5 minutos fora da app.
- **Memória**: as palavras-passe e os PINs passam em arrays que se apagam logo a seguir. Em
  Kotlin/Java não há forma garantida de apagar tudo da RAM (o sistema copia objetos e as
  bibliotecas guardam as chaves em números que não se apagam); o Android isola a memória de cada app.
- **Aleatório só criptográfico**: chaves, nonces e sais vêm do `SecureRandom`, e também as
  escolhas que não protegem nada (a ordem dos moldes do disfarce, os parágrafos, o enchimento do
  fim). Um teste lê o código-fonte e recusa qualquer outro gerador.
- **Criptografia**: feita pelo [PGPainless](https://pgpainless.org) 1.7.8 / BouncyCastle 1.82.
  Não há criptografia própria no OpenPGP. Os códigos QR usam o ZXing 3.5.3.
- **Bibliotecas conferidas na compilação**: o Gradle descarregado tem de ter o SHA-256 oficial, e
  cada biblioteca (da app, do núcleo, dos testes e das ferramentas de compilação) tem o SHA-256 em
  `gradle/verification-metadata.xml`. Uma biblioteca adulterada faz a compilação parar.

## Modelo de ameaça

Para que serve a app e para que não serve. É isto que uma auditoria compara com o código. A app
ainda não teve uma auditoria independente.

**Protege contra:**

- **Quem interceta as mensagens** (rede, operador, servidores da app de mensagens): só vê texto
  cifrado com OpenPGP. O segredo depende só do OpenPGP; sem código secreto, o disfarce não
  acrescenta segurança.
- **Filtros automáticos e quem lê de passagem**: os formatos disfarçados não têm "BEGIN PGP" nem
  base64 e leem-se como texto. Com o código secreto, sem a frase nem se percebe que há PGP por baixo.
- **Quem tira o disfarce** (com a app ou o desfazedor): vê PGP, mas não para quem é nem quem o
  enviou, porque os disfarces não levam os ids das chaves (1.4.6).
- **Quem pega no telemóvel desbloqueado**: PIN da app ou impressão digital, bloqueio ao fim de
  1 minuto fora, e o texto em claro sai do ecrã ao fim de 5 minutos fora.
- **Coação para abrir a app**: o PIN de pânico destrói as chaves do Keystore (o que sobrar no
  armazenamento fica ilegível para sempre) e a app abre vazia, como nova. O ecrã diz "A abrir…"
  como numa abertura normal, e o tempo de resposta é o mesmo.
- **Cópia dos ficheiros da app** (extração forense): o cofre só se abre com a chave do chip de
  segurança, que não sai do telemóvel; os nomes dos ficheiros não dizem nada; as chaves privadas
  têm ainda a palavra-passe OpenPGP. Nada vai para cópias de segurança. No Android 15 ou mais
  recente, com o telemóvel bloqueado, nem a correr como a app se abre o cofre (1.4.6).
- **Outras apps no mesmo telemóvel**: as proteções descritas em Segurança (capturas, janelas por
  cima, teclado, preenchimento automático, área de transferência, acessibilidade).
- **Fugas pela rede**: a app não tem permissão de Internet, por isso o Android não a deixa abrir
  ligações.
- **Bibliotecas adulteradas na compilação**: conferidas por SHA-256.

**Não protege contra:**

- **Um telemóvel comprometido** (root, spyware com controlo total, ou um serviço de acessibilidade
  que se declare ferramenta de acessibilidade): vê o que tu vês e o que escreves.
- **O teclado**: um teclado de terceiros pode registar o que escreves. O pedido para não aprender
  é só um pedido; usa um teclado de confiança.
- **Análise estatística do disfarce**: quem souber o que procura percebe que o texto foi gerado (as
  palavras saem uniformes demais). É camuflagem, não esteganografia indetetável.
- **Metadados fora da app**: com quem trocas mensagens, quando e quanto, na app de mensagens que
  usas.
- **O tamanho da mensagem**: o comprimento do texto disfarçado deixa adivinhar o tamanho do que vai
  lá dentro, como em qualquer encriptação sem enchimento. Também se vê quantas cópias leva (uma
  por destinatário, mais a tua) e o tipo de chave (ECC ou RSA), mas não de quem são.
- **Desbloqueio forçado com o dedo**: se ligares a impressão digital, alguém pode obrigar-te a
  usá-la, e o PIN de pânico nunca chega a ser pedido. Com esse risco, usa só o PIN da app.
- **Quem conhece o Reczi**: a app é pública, por isso quem a conhece sabe que existe PIN de pânico.
  Garante-se que os dados não se recuperam, não que ninguém desconfie.
- **Frases fracas no código secreto**: desde a 1.4.6 o sal é de cada par de chaves, por isso já não
  se testa uma frase contra as mensagens de toda a gente de uma vez; mas quem atacar o vosso par em
  concreto pode experimentar frases comuns. Usa uma frase longa e pessoal. Os códigos combinados
  antes da 1.4.6 continuam com o sal antigo, igual para todos, até os combinarem de novo.
- **Perder o telemóvel sem backup**: as chaves vão com ele.
- **Verificar o destinatário errado**: confirmar o fingerprint de cada contacto é contigo.

## Estrutura

- O id interno da app continua `app.reczi.pgp` (só o nome visível mudou), para as atualizações
  se instalarem por cima da versão anterior sem perder as chaves.
- `core/`: a criptografia e o cofre, em Kotlin puro. Tem testes que incluem trocas reais com o
  GnuPG 2.4 nos dois sentidos, e testes de "fuzzing": milhares de textos, ficheiros e códigos QR
  estragados ou ao acaso passam por tudo o que lê coisas vindas de fora, e só se aceita a resposta
  "não é válido", sem exceções inesperadas nem demoras (o texto colado pode ser um livro inteiro).
- `app/`: a interface Android (só a framework, sem AndroidX) e o armazenamento no Keystore.
  Um ficheiro por separador (`KeysScreen.kt`, `EncryptScreen.kt`, `DecryptScreen.kt`…); o
  `MainActivity.kt` só tem o que é comum: o bloqueio e o PIN de pânico, os diálogos, os ficheiros
  e os QR. As ajudas de interface estão em `Ui.kt` e o armazenamento cifrado em `KeystoreStore.kt`.
  Tem testes da interface (Robolectric, correm no computador sem telemóvel): criar chave,
  encriptar para ti e ler, assinar e verificar, o menu e os submenus das chaves, o cofre (nomes
  dos ficheiros, passagem dos cofres antigos, ficheiros estragados) e a acessibilidade. Só os testes usam
  AndroidX; o APK não leva nenhuma dependência AndroidX.

## Testes de ataque

Para validar um mínimo de segurança, há duas baterias que fazem o papel de quem tenta tirar alguma
coisa da app. Não substituem uma auditoria independente, mas apanham os erros mais comuns.

**`AttackTest`** (`./gradlew :app:testDebugUnitTest`), 13 cenários:

| Quem ataca | O que tenta | O que se verifica |
|---|---|---|
| Root ou análise forense | Copiar os ficheiros da app depois de um uso normal | Nenhum nome, email, fingerprint, id de chave, palavra-passe, frase do código, nota, mensagem ou chave PGP aparece, nem em UTF-8 nem UTF-16; os nomes dos ficheiros não dizem nada |
| Cópia de segurança | adb backup, cloud do Google, passar para outro telemóvel | Tudo excluído |
| Outra app | Procurar portas abertas | Só a atividade principal, que só aceita texto; sem serviços, fornecedores ou recetores abertos; sem Internet; tarefa própria (contra StrandHogg) |
| Outra app | Partilhar um "ficheiro" que aponta para o cofre | Ignorado: a app só lê texto partilhado |
| Outra app | Partilhar texto com a app bloqueada | Só aparece o ecrã do PIN; menu e "voltar" não passam |
| Outra app | Capturas e gravação de ecrã | Todas as janelas e diálogos com FLAG_SECURE e escondidos da acessibilidade |
| Outra app | Toques através de uma janela por cima (tapjacking) | Recusados |
| Quem pega no telemóvel | Adivinhar o PIN | Espera a partir do 5.º erro, que não se salta fechando a app |
| Quem pega no telemóvel | Mudar a hora ou reiniciar para saltar a espera | Não salta |
| Quem pega no telemóvel | Ler a área de transferência | Marcada como sensível e limpa ao fim de 45 s, mesmo com a app fechada |
| Quem pega no telemóvel | Ecrã esquecido aberto | Bloqueia ao fim de 1 min fora; ao fim de 5 min o texto em claro desaparece |
| O teclado | Aprender o que se escreve | Todos os campos pedem "não aprender" e ficam fora do preenchimento automático |
| Quem lê o código | Registos (logcat) ou ligações à rede | Nenhum |

Para confirmar que os testes servem para alguma coisa, estragou-se a app de propósito (sem
FLAG_SECURE, sem proteção contra toques por cima, a espera do PIN pela hora, sem limpar o ecrã ao
fim de 5 minutos), e de cada vez falhou o teste certo.

**`UnlockedKeyTest`** e **`LockedStoreTest`** (1.4.6), com chaves que se portam como as do Android 15:

| Quem ataca | O que tenta | O que se verifica |
|---|---|---|
| Quem pega no telemóvel | Abrir a app com o telemóvel bloqueado para ela não conseguir ler o PIN | Não abre o cofre; depois de desbloquear, pede o PIN da app |
| Quem pega no telemóvel | Um erro do Keystore ao ler o PIN | Não abre o cofre; "Tentar de novo" volta ao PIN |
| Ferramenta forense | Correr como a app com o telemóvel bloqueado | O cofre não abre, e nada passa por "estragado" |
| O próprio telemóvel | Bloquear a meio de uma leitura, ou desbloquear entre a leitura e a escrita | Nada vai para o lado, nenhuma lista fica vazia, nenhum backup sai incompleto |
| O próprio telemóvel | Parar a meio da mudança de chave | Lê-se tudo com as duas chaves e a mudança acaba na vez seguinte |

Também aqui se estragou a app de propósito (o erro a ler o PIN a contar como "sem PIN", as
leituras bloqueadas a passar por "ilegível", a chave nova sem a exigência do desbloqueio), e de
cada vez falhou o teste certo.

**`tools/auditar-apk.sh`** olha para o APK final como quem o descarrega: não é depurável, cópias de
segurança desligadas, só as permissões esperadas e sem Internet, só a atividade principal aberta,
assinatura v2/v3 sem v1 e com o certificado do Reczi cypher, sem bibliotecas nativas, sem chaves
ou palavras-passe embutidas, sem bibliotecas de testes, rede, anúncios ou estatísticas, sem logcat.

```bash
ANDROID_HOME=/caminho/do/sdk tools/auditar-apk.sh app/build/outputs/apk/release/app-release.apk
```

## Compilar

Precisa de JDK 17+ e do SDK do Android (plataforma 35).

```bash
./gradlew :core:test              # testes do núcleo (precisa do gpg instalado para os de interoperabilidade)
./gradlew :app:testDebugUnitTest  # testes da interface
./gradlew :app:assembleRelease
# APK em app/build/outputs/apk/release/app-release.apk
```

### Compilação reprodutível

O mesmo código dá sempre o mesmo APK, byte a byte. A 1.4.3 foi compilada duas vezes do zero, uma
delas noutra pasta, e o APK assinado saiu com o mesmo SHA-256
(`dc2e4e52f676a81a4b64f9805b8ab425259ab21e76e6f8f2685cb4833f68dc94`). Isto foi confirmado com o
OpenJDK 21 e o Linux; noutro sistema ou com outro JDK ainda não foi experimentado. Assim, qualquer
pessoa pode confirmar que um APK publicado vem deste código, sem ter de confiar em quem o compilou:

1. Compila o mesmo commit com uma chave tua (`-Preczi.storeFile=...`).
2. Compara o conteúdo, que não depende da chave: a assinatura fica fora dos ficheiros do zip
   (assinatura v2/v3; a v1 não é usada).

```bash
mkdir a b
unzip -q -d a reczi-cypher-publicado.apk
unzip -q -d b app/build/outputs/apk/release/app-release.apk
diff -r a b && echo "igual"
```

### Verificação das bibliotecas

Compila sempre a partir da pasta de cima (como acima): é aí que está a verificação das bibliotecas
(`gradle/verification-metadata.xml`), que também cobre o núcleo. Ao mudar uma biblioteca, atualiza
as somas e confere o que mudou antes de o guardar:

```bash
./gradlew --write-verification-metadata sha256 clean :app:assembleDebug :app:assembleRelease :app:testDebugUnitTest :app:lintDebug :core:test
```

A assinatura usa a chave `../reczi-signing/reczi-release.p12`, fora do projeto (ou outra com
`-Preczi.storeFile=<caminho>`), e a palavra-passe `reczi.storePassword` em `~/.gradle/gradle.properties`
(ou a variável `RECZI_STORE_PASSWORD`). Sem isso, a compilação de release falha em vez de produzir um
APK sem assinatura. **Guarda a chave e a palavra-passe em segurança e em sítios diferentes, e nunca as
publiques**: as atualizações da app têm de ser assinadas com a mesma chave, senão o Android obriga a
desinstalar (e perdes as chaves que não tenham backup).
