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
- **Só assinar**: em Encriptar, "Só assinar" assina um texto sem o encriptar (fica legível por
  todos, serve para provar que é teu). Em Desencriptar, um texto assinado é verificado.
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

Separadores: **Mensagens** (Ler e Escrever, que são o Desencriptar e o Encriptar), **Contactos**,
**Notas**, **Chaves** e **⚙** (bloqueio da app e ajuda).

- **Colar e detetar**: em Mensagens, vê o que está na área de transferência e leva-o para o sítio
  certo (mensagem para Ler, chave pública para Contactos, texto normal para Escrever).
- **Conversa**: num contacto verificado, abre as Mensagens viradas para ele, com o formato e a
  opção do código secreto usados da última vez, e um atalho "Colar o que recebi".
- **Convidar**: em Contactos, partilha a tua chave pública com instruções para quem ainda não usa
  a app. Ao importar, a app tira a chave do meio do texto.
- **Impressão digital em palavras**: ao verificar um contacto (e em "Mostrar QR"), a impressão
  digital aparece também como 20 palavras portuguesas, mais fáceis de ler em voz alta.

## Ajuda dentro da app

- **Bem-vindo**: na primeira abertura sem chaves, uma explicação curta de como funciona.
- **Primeiros passos**: no separador Chaves, uma lista (criar chave, backup, trocar chaves,
  verificar) que se vai riscando sozinha e desaparece quando está tudo feito.
- **? Ajuda**: em cada separador, explica o que esse ecrã faz.
- **Lembrete de backup**: cada chave sem backup registado mostra um aviso, e definir o PIN de
  pânico sem backup pede confirmação. Conta como backup: guardar em ficheiro, imprimir em papel,
  ou a chave ter sido importada. O registo fica só nas preferências da app.

## Bloqueio da app

No separador ⚙:

- **Impressão digital / bloqueio do telemóvel**: pedido ao abrir e depois de 1 minuto fora da app.
- **PIN da app**: um PIN próprio (guardado só como scrypt com sal). A partir da 5.ª tentativa
  errada, há uma espera que vai duplicando.
- **PIN de pânico**: escrito no ecrã de bloqueio, apaga tudo (ficheiros do cofre e a chave do
  Keystore) e abre a app vazia. Não há volta.

O bloqueio é uma porta, não uma cifra: trava quem pega no telemóvel desbloqueado. A chave do
Keystore não fica presa à impressão digital, de propósito: o Android destrói chaves dessas quando
se tira o bloqueio de ecrã, e o cofre perdia-se. As chaves privadas continuam protegidas pela
palavra-passe OpenPGP, que é sempre pedida.

## Modo disfarçado

Uma mensagem PGP normal vê-se logo que é PGP (`-----BEGIN PGP MESSAGE-----`). Em "Formato" podes
escolher:

- **PGP normal**: abre em qualquer programa OpenPGP.
- **Disfarçado: código**: uma linha de letras e números ao acaso, sem cabeçalhos.
- **Disfarçado: palavras**: uma lista de palavras portuguesas soltas (bem mais comprido).

A chave pública também pode ser partilhada disfarçada. A app reconhece sozinha um texto disfarçado
ao colar, importar ou receber por partilha.

### Código secreto por contacto (opcional)

Em Contactos, num contacto verificado, podes combinar um **código secreto**: uma frase que os dois
escrevem, cada um na sua app (combinada em pessoa ou por chamada). A app mostra seis algarismos de
confirmação, que têm de ser iguais nos dois telemóveis. Depois, em Encriptar, com um formato
disfarçado e só esse destinatário, aparece a opção "Fechar com o código secreto".

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

## Compilar

Precisa de JDK 17+ e do SDK do Android (plataforma 35).

```bash
cd core && ../gradlew test        # testes do núcleo (precisa do gpg instalado para os de interoperabilidade)
cd .. && ./gradlew :app:assembleRelease
# APK em app/build/outputs/apk/release/app-release.apk
```

A assinatura usa a chave `../reczi-signing/reczi-release.p12`, fora do projeto (ou outra com
`-Preczi.storeFile=<caminho>`), e a palavra-passe `reczi.storePassword` em `~/.gradle/gradle.properties`
(ou a variável `RECZI_STORE_PASSWORD`). Sem isso, a compilação de release falha em vez de produzir um
APK sem assinatura. **Guarda a chave e a palavra-passe em segurança e em sítios diferentes, e nunca as
publiques**: as atualizações da app têm de ser assinadas com a mesma chave, senão o Android obriga a
desinstalar (e perdes as chaves que não tenham backup).
