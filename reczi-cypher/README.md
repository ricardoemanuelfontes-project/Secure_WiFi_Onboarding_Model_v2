# Reczi cypher

App Android para encriptar e desencriptar mensagens com OpenPGP, compatível com o GnuPG
(e com o `cofre` / Cofre PGP do Debian).

- **Chaves**: criar (Curve25519: ed25519 + cv25519, válida 2 anos), importar a tua chave privada
  do computador, partilhar a chave pública, backup da privada, prolongar a validade.
- **Contactos**: importar chaves públicas (colar, ficheiro ou partilhar a partir de outra app) e
  verificar a impressão digital. Só se pode encriptar para contactos verificados.
- **Encriptar**: para um ou vários destinatários, sempre também para ti, assinado por omissão.
  Também podes escolher só a tua própria chave (uma nota para ti).
- **Desencriptar**: mostra o texto só depois de confirmar a integridade, e diz quem assinou.
  O botão "Responder" abre o Encriptar já com o remetente escolhido.
- **Avisos de validade**: ao abrir, a app avisa das chaves que expiram nos próximos 30 dias.

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

- **Sem Internet**: a app não tem acesso à rede nem a nada no telemóvel. Os ficheiros só
  entram e saem quando os escolhes. A única permissão (`HIDE_OVERLAY_WINDOWS`) serve para
  esconder janelas de outras apps por cima desta (Android 12+), e os toques são ignorados
  quando há algo por cima.
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
  Não há criptografia própria.

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
