# reczi-pgp

App Android para encriptar e desencriptar mensagens com OpenPGP, compatível com o GnuPG
(e com o `cofre` / Cofre PGP do Debian).

- **Chaves**: criar (Curve25519: ed25519 + cv25519, válida 2 anos), importar a tua chave privada
  do computador, partilhar a chave pública, backup da privada, prolongar a validade.
- **Contactos**: importar chaves públicas (colar, ficheiro ou partilhar a partir de outra app) e
  verificar a impressão digital. Só se pode encriptar para contactos verificados.
- **Encriptar**: para um ou vários destinatários, sempre também para ti, assinado por omissão.
- **Desencriptar**: mostra o texto só depois de confirmar a integridade, e diz quem assinou.

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
