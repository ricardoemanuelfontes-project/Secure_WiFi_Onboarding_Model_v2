# Modelo de ameaça do Reczi cypher

Versão 1.4.6. Este documento diz o que a app protege, contra quem, e onde acaba. Serve para quem a
usa decidir se lhe serve, e para uma auditoria comparar com o código.

Regra do documento: cada garantia e cada limite apontam para o sítio onde se confirmam, um ficheiro
ou um teste. Uma garantia sem teste é uma intenção. Os caminhos são relativos a esta pasta:
`core/` é o núcleo (Kotlin puro, `core/src/main/kotlin/app/reczi/pgp/core/`), `app/` é a app
Android (`app/src/main/kotlin/app/reczi/pgp/`), e os testes estão em `*/src/test/`.

A app nunca teve uma auditoria independente. Foi desenhada, atacada e medida por quem a fez.

## 1. O que há para proteger

| Ativo | Onde vive | Como está protegido |
|---|---|---|
| Chaves privadas OpenPGP | Cofre (`sec-<impressão digital>`) | Palavra-passe OpenPGP (mín. 12 caracteres; AES-256, SHA-512 iterado, contagem 65 011 712) e, por cima, a cifra do cofre |
| O texto das mensagens | Só em memória e no ecrã, enquanto estão abertas | OpenPGP em trânsito; ecrã protegido; apagado do ecrã ao fim de 5 min fora da app |
| Com quem falas | Contactos e lista de verificados, no cofre | Cifra do cofre; nomes dos ficheiros aleatórios |
| Códigos secretos | Chaves derivadas (nunca a frase), no cofre | Cifra do cofre |
| Notas | Cofre | OpenPGP para as tuas chaves e cifra do cofre |
| PIN da app e PIN de pânico | Cofre | scrypt (N=2^14, r=8, p=1) com sal, e cifra do cofre |
| Preferências pessoais (formato por contacto, backups feitos) | Cofre | Cifra do cofre |
| Mensagens em trânsito | A app de mensagens que escolheres | OpenPGP, e opcionalmente disfarce e código secreto |

A "cifra do cofre" é AES-256-GCM por ficheiro, com uma chave do Android Keystore que não sai do chip
de segurança (StrongBox, quando existe). Atenção: só as chaves privadas e as notas precisam também
da palavra-passe OpenPGP. O resto do cofre (contactos, verificados, códigos, PIN, preferências)
depende só da chave do Keystore.

## 2. Quem ataca

| | Quem | O que consegue à partida |
|---|---|---|
| A1 | Quem interceta as mensagens: rede, operador, servidores da app de mensagens | Ler e guardar tudo o que passa |
| A2 | Filtros automáticos e quem lê de passagem | Procurar palavras e formatos conhecidos |
| A3 | Quem tem a app, o código ou o desfazedor e tira o disfarce | Ver o OpenPGP que está por baixo de um disfarce sem código secreto |
| A4 | Quem pega no telemóvel desbloqueado | Usar o ecrã e as apps durante algum tempo |
| A5 | Quem obriga a abrir a app | Exigir o PIN ou o dedo |
| A6 | Análise forense de um telemóvel apreendido | Copiar os ficheiros da app; com uma falha do sistema, correr código como a app |
| A7 | Outra app sem privilégios no mesmo telemóvel | Desenhar por cima, ler a área de transferência quando pode, mandar intents, usar acessibilidade |
| A8 | Um teclado de terceiros | Ver tudo o que se escreve |
| A9 | A cadeia de fornecimento | Trocar uma biblioteca, o Gradle ou o APK que alguém instala |
| A10 | Quem ataca um par concreto com código secreto | Experimentar frases comuns contra as mensagens desse par |

**Fora do modelo** (a app não se defende disto, e diz que não):

- Root, spyware com controlo total, um sistema operativo comprometido.
- Um serviço de acessibilidade que se declare ferramenta de acessibilidade.
- Ataques ao hardware (ler a memória com o telemóvel aberto, falhas do chip de segurança).
- Análise estatística dirigida ao formato dos disfarces.
- Os metadados da app de mensagens (quem, quando, quanto).

## 3. Fronteiras de confiança

1. **Chip de segurança ↔ app.** A chave do cofre vive no Keystore; a app só lhe pede para cifrar e
   decifrar (`app/KeystoreStore.kt`).
2. **App ↔ outras apps.** A caixa de areia do Android, mais as proteções da interface (secção 4.4).
3. **Telemóvel ↔ mundo.** Sem permissão de Internet: só sai o que tu partilhas, copias ou guardas
   num ficheiro (`app/src/main/AndroidManifest.xml`).
4. **Entradas de fora ↔ núcleo.** Texto colado ou partilhado, ficheiros, QR e backups são lidos
   como não confiáveis. Os leitores são Kotlin puro (sem código nativo) e passaram por fuzzing.

## 4. O que se garante, e onde se confirma

### 4.1 Mensagens

| Garantia | Como | Onde se confirma |
|---|---|---|
| Só o destinatário lê (A1) | OpenPGP com PGPainless 1.7.8 sobre BouncyCastle 1.82; não há criptografia feita à mão nas mensagens | `core/Pgp.kt`; `PgpTest.encryptDecryptBetweenTwoPeople`; `GnuPgInteropTest` (GnuPG 2.4, nos dois sentidos) |
| Uma mensagem alterada não abre | O texto só é devolvido depois de lida até ao fim e verificada a integridade (MDC/AEAD); a assinatura vai à parte | `Pgp.decrypt`; `PgpTest.failureCases`; `CypherTest.damagedDisguiseIsRejected` |
| Assinaturas que não enganam | Uma subchave alheia não tapa um contacto verificado; chaves revogadas ou expiradas não contam | `ReviewFixesTest.foreignSubkeyCannotShadowAVerifiedContact` e seguintes |
| Os disfarces não dizem quem fala com quem (A3) | Destinatários escondidos: os ids das chaves vão a zeros; a assinatura vai cifrada | `HiddenRecipientsTest`; `GnuPgInteropTest.hiddenRecipientsBothWays` |
| Os disfarces passam por texto (A2) | Formatos de prosa sem "BEGIN PGP", sem base64, sem números nem palavras de duplo sentido | `core/Prose.kt`, `core/Books.kt`; `ProseTest` |
| Um formato publicado nunca muda | Cada formato fixado por SHA-256 nos testes; melhorias vão para formatos novos | `ProseTest` (lista de digests) |
| Por baixo do disfarce só há OpenPGP | O desfazedor, com o mesmo código, mostra o que está por baixo | `core/Desfazer.kt`; `DesfazerTest` |
| Com código secreto, nem quem tem a app vê PGP (A3) | Camada ChaCha20 por cima do AES do OpenPGP, com chave derivada da frase por scrypt (N=2^15) | `core/Disguise.kt`; `CypherTest.secretCodeLayerNeedsTheSameCodeOnBothSides` |
| Uma tabela de frases não serve contra todos (A10) | Desde a 1.4.6, o sal são as impressões digitais das duas chaves; cada par tem o seu | `Disguise.deriveSecret`; `PairCodeTest` |

### 4.2 O cofre e os ficheiros (A6)

| Garantia | Como | Onde se confirma |
|---|---|---|
| Os ficheiros copiados não dizem nada | AES-256-GCM com chave do Keystore; nomes aleatórios; o nome de cada entrada vai lá dentro, cifrado; o nome do ficheiro entra como AAD | `app/KeystoreStore.kt`; `AttackTest.stolenFilesShowNothing`; `SecureStoreTest` |
| Trocar ficheiros não engana a app | O AAD prende cada conteúdo ao seu ficheiro | `SecureStoreTest.swappedFilesAreRefused` |
| Nada vai para cópias de segurança | `allowBackup=false`, `dataExtractionRules` a excluir tudo, dados em `noBackupFilesDir` | `AttackTest.backupsTakeNothing` |
| Uma escrita interrompida não estraga o cofre | Escrita atómica (temporário, fsync, rename); o índice refaz-se a partir dos ficheiros | `SecureStoreTest.orphanFromAnInterruptedWriteIsPutAside`, `lostOrBrokenIndexIsRebuiltFromTheFiles` |
| Com o telemóvel bloqueado, o cofre não abre (Android 15+) | A chave tem `setUnlockedDeviceRequired`; os cofres antigos mudam de chave na abertura, sem perder nada | `KeystoreStore.upgradeKey`; `UnlockedKeyTest` |
| Bloqueado não é estragado | Uma leitura que falha por bloqueio nunca vira "ilegível", "lista vazia" ou backup incompleto | `StoreLockedException` em `core/Vault.kt`; `LockedStoreTest`; `UnlockedKeyTest.aLockedPhoneIsNeverABrokenVault` |
| Backup completo cifrado | scrypt (N=2^15) e AES-256-GCM, com a palavra-passe do backup | `core/Backup.kt`; `PhasesTest.fullBackupMovesEverythingToANewPhone`; `ImportBackupTest` |

### 4.3 Quem pega no telemóvel (A4, A5)

| Garantia | Como | Onde se confirma |
|---|---|---|
| Adivinhar o PIN é lento | A partir do 5.º erro, espera que duplica (30 s até 1 h), contada pelo tempo desde que o telemóvel ligou | `AttackTest.guessingThePinIsSlowedDown`, `changingTheClockOrRebootingDoesNotSkipTheWait` |
| Não conseguir ler o PIN não deixa entrar | O arranque falha fechado (até à 1.4.5 contava como "sem PIN") | `UnlockedKeyTest.openingWhileThePhoneIsLockedDoesNotSkipTheAppPin`, `aKeystoreErrorWhileReadingThePinDoesNotOpenTheVault` |
| Ecrã esquecido | Bloqueia ao fim de 1 min fora; o texto em claro sai do ecrã ao fim de 5 min | `AttackTest.forgottenScreenLocksAndForgets` |
| Partilhar para a app bloqueada não passa | Só aparece o ecrã do PIN | `AttackTest.sharingDoesNotGetPastTheLock` |
| PIN de pânico | Destrói as chaves do Keystore e os ficheiros, e abre a app vazia, com o mesmo tempo de resposta | `KeystoreStore.wipe`; `PrivacyFlowTest.panicPinLeavesNothingBehind`; `PhasesTest.appPinAndPanicPin` |

### 4.4 Outras apps no mesmo telemóvel (A7, A8)

| Garantia | Como | Onde se confirma |
|---|---|---|
| Sem capturas nem gravação de ecrã | `FLAG_SECURE` em todas as janelas e diálogos | `AttackTest.noScreenshotsAnywhere` |
| Acessibilidade de spyware não lê o ecrã (Android 14+) | `setAccessibilityDataSensitive` | `PrivacyFlowTest.screenIsHiddenFromAccessibilitySpyware` |
| Toques através de janelas por cima são recusados | `guard()` nos botões críticos, `setHideOverlayWindows` (Android 12+) | `app/Ui.kt`; `AttackTest.tapsThroughAnOverlayAreRefused` |
| O teclado não aprende | `IME_FLAG_NO_PERSONALIZED_LEARNING` e fora do preenchimento automático | `AttackTest.theKeyboardLearnsNothing` |
| A área de transferência esquece | Copiado como sensível e limpo depois | `app/ClipboardClearReceiver.kt`; `AttackTest.copiedSecretsLeaveTheClipboard` |
| Só a porta da frente está aberta | Uma só atividade exportada, que só aceita texto; tarefa própria | `AttackTest.onlyTheFrontDoorIsOpen`, `sharedFilePointingAtTheVaultIsIgnored` |

### 4.5 Código e distribuição (A9)

| Garantia | Como | Onde se confirma |
|---|---|---|
| Sem rede e sem registos | Sem permissão de Internet (o Android recusa qualquer ligação); nada de `android.util.Log` | `AttackTest.noLogsAndNoNetworkInTheCode`; `tools/auditar-apk.sh` |
| Aleatoriedade boa | `SecureRandom` em tudo | `NoWeakRandomTest` |
| Entradas maliciosas não rebentam a app | Cerca de 23 000 entradas estragadas ou aleatórias em todos os leitores de fora | `FuzzTest` |
| Bibliotecas conferidas | SHA-256 de cada dependência e do Gradle wrapper | `gradle/verification-metadata.xml`, `gradle/wrapper/gradle-wrapper.properties` |
| O APK é o que o código diz | Compilação reprodutível (byte a byte) e auditoria do APK final: não depurável, permissões mínimas, assinatura v2/v3 com o certificado esperado, sem código nativo nem bibliotecas de rede | `README.md` (Compilação reprodutível); `tools/auditar-apk.sh` |

## 5. Limites conhecidos

O que a app não garante, e onde isso está.

- **Telemóvel comprometido** (root, spyware, acessibilidade que se declara ferramenta): vê o que tu
  vês e o que escreves. Fora do modelo.
- **O resto do cofre não precisa da palavra-passe OpenPGP.** Contactos, lista de verificados,
  códigos, PIN e preferências dependem só da chave do Keystore. Quem conseguir correr código como a
  app com o telemóvel desbloqueado lê-os. As chaves privadas e as notas não (`core/Vault.kt`).
- **Antes do Android 15**, a chave do cofre funciona sempre que o telemóvel já foi desbloqueado
  desde que ligou. Prendê-la ao desbloqueio só é seguro a partir do 15: do 12 ao 14, tirar o
  bloqueio de ecrã apagava-a (`VaultKeys.unlockedOnlySupported` em `app/KeystoreStore.kt`).
- **Desbloqueio "fraco"** (rosto que não seja de classe 3, Smart Lock): enquanto vale, o Android
  guarda a chave do cofre em memória com o telemóvel bloqueado, e a proteção do Android 15 perde-se
  nesse tempo (Keystore do Android, `keystore2/src/super_key.rs`, `lock_unlocked_device_required_keys`).
- **O disfarce é camuflagem, não esteganografia indetetável.** Vocabulário fixo e repetitivo, sem
  sentido global: engana filtros de palavras e leituras rápidas, não uma análise estatística
  dirigida (`core/Prose.kt`, `core/Books.kt`).
- **Sem código secreto, a camada do disfarce não acrescenta segredo.** A chave é fixa e está no
  código (`Disguise.fixed`).
- **O tamanho e a forma da mensagem veem-se.** O comprimento do disfarce deixa adivinhar o tamanho
  do texto. Sem código secreto, também se vê quantas cópias leva (uma por destinatário, mais a tua)
  e o tipo de chave, mas não de quem são (`HiddenRecipientsTest`).
- **Sem sigilo futuro.** É OpenPGP, não Signal: quem obtiver a chave privada e a palavra-passe lê
  as mensagens antigas que tiver guardado.
- **Frases fracas no código secreto** continuam a cair a um ataque dirigido ao vosso par (A10). Os
  códigos combinados antes da 1.4.6 ficam com o sal antigo, igual para todos, até serem combinados
  de novo (`Contact.codeIsOld`).
- **Memória da JVM.** O texto em claro passa por `String` e pelo `TextView`, que não se apagam. Os
  `CharArray` das palavras-passe apagam-se depois de usados, onde a biblioteca deixa.
- **Área de transferência.** Com a app aberta, limpa aos 45 s. Com a app fechada, quem limpa é um
  alarme que o Android trata como inexato e pode atrasar com o telemóvel em repouso
  (`setAndAllowWhileIdle` em `app/ClipboardClearReceiver.kt`).
- **Desbloqueio forçado com o dedo** (A5): com a impressão digital ligada, o PIN de pânico nunca
  chega a ser pedido.
- **Quem conhece a app** sabe que existe PIN de pânico. Garante-se que os dados não se recuperam, não
  que ninguém desconfie de uma app vazia.
- **Ficheiros postos de lado** (`vault-avariados`) ficam ilegíveis para sempre depois da mudança
  para a chave do Android 15, porque a chave antiga é destruída (`KeystoreStore.upgradeKey`).
- **A primeira instalação é confiança cega.** O Android recusa atualizações assinadas por outra
  chave, mas na primeira instalação ninguém confere. O certificado esperado está em
  `tools/auditar-apk.sh` (`EXPECTED_CERT`).
- **Os testes correm no computador** (Robolectric), não num telemóvel. O comportamento do Keystore
  real (StrongBox, chaves "só desbloqueado") é imitado nos testes (`MemoryVaultKeys` em
  `UnlockedKeyTest`); falta confirmá-lo num Android 15 a sério.
- **Auto-auditoria.** Quem fez a app auditou-a. É necessário, não é suficiente.

## 6. Em aberto

Já identificados e ainda não feitos.

- **Diálogos de confirmação sem proteção contra toques por cima.** "Apagar nota", "Remover
  contacto", "Tirar código secreto" e "Cofre novo" usam `confirm`/`typedConfirm` (`app/MainActivity.kt`)
  sem `guard()`. Uma app que desenhe por cima pode levar a apagar coisas (não a ler segredos).
- **Ensaio de restauro do backup.** Depois de gravar, a app relê o ficheiro e compara os bytes;
  ainda não o abre com a palavra-passe para confirmar que restaura.
- **Esteganografia em imagem**, se for feita: descodificar imagens de fora num processo isolado
  (`isolatedProcess`), porque os descodificadores de imagem do Android são código nativo.
- **Auditoria independente.**

## 7. Suposições

- O Android, o Keystore e o chip de segurança cumprem o que prometem.
- PGPainless e BouncyCastle estão corretos.
- Confirmas a impressão digital de cada contacto fora da app (em pessoa ou por chamada).
- As palavras-passe e as frases dos códigos são fortes.
- O APK instalado é o oficial (o certificado confere).

## 8. Como verificar sem acreditar nisto

1. Corre os testes: `./gradlew :core:test :app:testDebugUnitTest`. Têm de ficar verdes.
2. Escolhe uma defesa, tira-a do código e corre outra vez. Se nada falhar, a defesa não estava a ser
   medida, e isso é um achado. Foi assim que se validaram `AttackTest`, `UnlockedKeyTest` e
   `LockedStoreTest`.
3. Corre `tools/auditar-apk.sh` sobre o APK que tens instalado.
4. Compila de novo e compara o SHA-256 do APK (secção Compilação reprodutível do `README.md`).
5. Usa o desfazedor (`reczi-desfazer.jar`) para confirmar que por baixo de um disfarce só está
   OpenPGP normal, que o GnuPG abre.
