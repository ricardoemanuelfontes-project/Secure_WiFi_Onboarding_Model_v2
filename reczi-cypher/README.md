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
  errada, há uma espera que vai duplicando.
- **PIN de pânico**: escrito no ecrã de bloqueio, apaga tudo (ficheiros do cofre e a chave do
  Keystore) e abre a app vazia. Não há volta.

O bloqueio é uma porta, não uma cifra: trava quem pega no telemóvel desbloqueado. A chave do
Keystore não fica presa à impressão digital, de propósito: o Android destrói chaves dessas quando
se tira o bloqueio de ecrã, e o cofre perdia-se. As chaves privadas continuam protegidas pela
palavra-passe OpenPGP.

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
isto não faz perder nada (as chaves continuam no cofre). O PIN de pânico apaga-a também. Não usa o
PIN da app, de propósito: um PIN de 4 algarismos protegeria a palavra-passe muito menos do que o
chip de segurança do telemóvel.

## Modo disfarçado

Uma mensagem PGP normal vê-se logo que é PGP (`-----BEGIN PGP MESSAGE-----`). Em "Formato" podes
escolher:

- **PGP normal**: abre em qualquer programa OpenPGP.
- **Disfarçado: código**: uma linha de letras e números ao acaso, sem cabeçalhos.
- **Disfarçado: palavras**: uma lista de palavras portuguesas soltas (bem mais comprido).
- **Disfarçado: poema**: versos em português, em quadras ("Sobre o muro querido morre um luar").
  Cada palavra de três listas (substantivos, adjetivos, verbos) leva um byte; maiúsculas, acentos,
  pontuação e quebras de linha não contam ao ler. É o formato mais comprido: cerca de 100 versos
  para uma mensagem curta assinada, cerca de 50 com o modo compacto.

**Modo compacto** (em Escrever): a mensagem vai sem assinatura e sem cópia para ti, e fica com menos
de metade do tamanho (175 em vez de 398 bytes numa mensagem curta). Em troca, o destinatário não
confirma que é tua e tu não a consegues reler.

A chave pública também pode ser partilhada disfarçada. A app reconhece sozinha um texto disfarçado
ao colar, importar ou receber por partilha.

### Código secreto por contacto (opcional)

Em Contactos, num contacto verificado, podes combinar um **código secreto**: uma frase que os dois
escrevem, cada um na sua app (combinada em pessoa ou por chamada). A app mostra seis algarismos de
confirmação, que têm de ser iguais nos dois telemóveis. Depois, em Encriptar, com um formato
disfarçado e só esse destinatário, aparece a opção "Fechar com o código secreto", desligada por
omissão: marca-se quando se quer usar, e a escolha fica lembrada para esse contacto.

Com o código, a camada de fora passa a ser uma segunda cifra a sério (AES-256 com chave derivada da
frase por scrypt): sem a frase, nem com a app se consegue ver que por baixo está PGP. Fica guardada
só a chave derivada, dentro do cofre. Se mudarem a frase, as mensagens antigas com código deixam de
abrir.

Limites do disfarce sem código secreto, para não haver ilusões:

- Só quem usa o Reczi cypher consegue abrir um texto disfarçado (o GnuPG não).
- É camuflagem, não é segurança a mais: a chave do disfarce é fixa e está dentro da app, por isso
  quem tiver a app consegue ver que por baixo está PGP. O segredo da mensagem continua a depender
  só do OpenPGP.
- Esconde que é PGP (e os ids das chaves dos destinatários), não esconde que é texto cifrado.

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
- Os dados ficam em `noBackupFilesDir` e estão excluídos de cópias de segurança e de transferências
  para outro telemóvel. **Se desinstalares a app, as chaves desaparecem: faz backup.**
- **Capturas de ecrã bloqueadas** (`FLAG_SECURE`).
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
- **Criptografia**: feita pelo [PGPainless](https://pgpainless.org) 1.7.8 / BouncyCastle 1.82.
  Não há criptografia própria no OpenPGP. Os códigos QR usam o ZXing 3.5.3.

## Estrutura

- O id interno da app continua `app.reczi.pgp` (só o nome visível mudou), para as atualizações
  se instalarem por cima da versão anterior sem perder as chaves.
- `core/`: a criptografia e o cofre, em Kotlin puro. Tem testes que incluem trocas reais com o
  GnuPG 2.4 nos dois sentidos.
- `app/`: a interface Android (só a framework, sem AndroidX) e o armazenamento no Keystore.
  Tem testes da interface (Robolectric, correm no computador sem telemóvel): criar chave,
  encriptar para ti e ler, assinar e verificar, o menu e os submenus das chaves. Só os testes usam
  AndroidX; o APK não leva nenhuma dependência AndroidX.

## Compilar

Precisa de JDK 17+ e do SDK do Android (plataforma 35).

```bash
cd core && ../gradlew test        # testes do núcleo (precisa do gpg instalado para os de interoperabilidade)
cd .. && ./gradlew :app:testDebugUnitTest   # testes da interface
./gradlew :app:assembleRelease
# APK em app/build/outputs/apk/release/app-release.apk
```

A assinatura usa a chave `../reczi-signing/reczi-release.p12`, fora do projeto (ou outra com
`-Preczi.storeFile=<caminho>`), e a palavra-passe `reczi.storePassword` em `~/.gradle/gradle.properties`
(ou a variável `RECZI_STORE_PASSWORD`). Sem isso, a compilação de release falha em vez de produzir um
APK sem assinatura. **Guarda a chave e a palavra-passe em segurança e em sítios diferentes, e nunca as
publiques**: as atualizações da app têm de ser assinadas com a mesma chave, senão o Android obriga a
desinstalar (e perdes as chaves que não tenham backup).
