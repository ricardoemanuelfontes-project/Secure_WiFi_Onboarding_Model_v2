package app.reczi.pgp.core

import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.openpgp.PGPKeyRing
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider
import org.pgpainless.PGPainless
import org.pgpainless.algorithm.DocumentSignatureType
import org.pgpainless.algorithm.HashAlgorithm
import org.pgpainless.algorithm.KeyFlag
import org.pgpainless.algorithm.SymmetricKeyAlgorithm
import org.pgpainless.decryption_verification.ConsumerOptions
import org.pgpainless.decryption_verification.MessageInspector
import org.pgpainless.decryption_verification.MessageMetadata
import org.pgpainless.decryption_verification.MissingKeyPassphraseStrategy
import org.pgpainless.encryption_signing.EncryptionOptions
import org.pgpainless.encryption_signing.ProducerOptions
import org.pgpainless.encryption_signing.SigningOptions
import org.pgpainless.exception.MissingDecryptionMethodException
import org.pgpainless.exception.WrongPassphraseException
import org.pgpainless.key.OpenPgpFingerprint
import org.pgpainless.key.generation.KeySpec
import org.pgpainless.key.generation.type.KeyType
import org.pgpainless.key.generation.type.eddsa_legacy.EdDSALegacyCurve
import org.pgpainless.key.generation.type.xdh_legacy.XDHLegacySpec
import org.pgpainless.key.protection.KeyRingProtectionSettings
import org.pgpainless.key.protection.SecretKeyRingProtector
import org.pgpainless.key.protection.UnlockSecretKey
import org.pgpainless.util.Passphrase
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.util.Calendar
import java.util.Date

/** Erro com uma mensagem pronta a mostrar ao utilizador. */
open class PgpError(message: String, cause: Throwable? = null) : Exception(message, cause)

class WrongPassphraseError(cause: Throwable? = null) : PgpError("Palavra-passe errada.", cause)

data class KeyInfo(
    val fingerprint: String,
    /** Nome e email, já limpos para mostrar no ecrã. */
    val userId: String,
    val created: Date,
    val expires: Date?,
    val revoked: Boolean,
    val canEncrypt: Boolean,
    val canSign: Boolean,
)

sealed interface SignatureStatus {
    /** A mensagem não estava assinada. */
    data object None : SignatureStatus

    /** Assinatura válida de uma chave que conhecemos. */
    data class Valid(val fingerprint: String) : SignatureStatus

    /** Assinada por uma chave que não está no cofre. */
    data object UnknownSigner : SignatureStatus

    /** A assinatura não confere com a chave: a mensagem foi alterada ou é falsa. */
    data object Invalid : SignatureStatus

    /** Assinatura matematicamente correta, mas recusada: a chave de quem assinou está revogada
     *  ou expirada, ou usa algoritmos que já não são seguros. */
    data class Rejected(val fingerprint: String) : SignatureStatus
}

data class Decrypted(val text: String, val signature: SignatureStatus)

object Pgp {
    /**
     * Proteção das chaves privadas: AES-256 com a palavra-passe derivada por SHA-512
     * iterado e com sal, no máximo de iterações do OpenPGP (65 011 712). É o mais forte
     * que o GnuPG 2.4 também consegue importar.
     */
    val PROTECTION = KeyRingProtectionSettings(SymmetricKeyAlgorithm.AES_256, HashAlgorithm.SHA512, 0xff)

    const val MIN_PASSPHRASE = 12

    /** Limite do texto desencriptado (protege contra "bombas" de compressão). */
    const val MAX_PLAINTEXT = 4 shl 20

    /** Limite de um ficheiro desencriptado (2 GB). */
    const val MAX_FILE = 2L shl 30

    /** Cria um par de chaves Curve25519 (como o GnuPG): primária ed25519 só para certificar,
     *  subchave ed25519 para assinar e subchave cv25519 para encriptar. */
    fun generate(name: String, email: String, passphrase: CharArray, validYears: Int = 2, now: Date = Date()): PGPSecretKeyRing {
        val n = name.trim()
        val e = email.trim()
        if (n.isEmpty() || !Regex("^[^@\\s<>]+@[^@\\s<>]+$").matches(e)) {
            throw PgpError("Indica um nome e um email válido.")
        }
        if (n.any { it == '<' || it == '>' || Character.isISOControl(it) }) throw PgpError("O nome não pode ter < ou >.")
        checkNewPassphrase(passphrase)
        val unprotected = PGPainless.buildKeyRing()
            .setPrimaryKey(KeySpec.getBuilder(KeyType.EDDSA_LEGACY(EdDSALegacyCurve._Ed25519), KeyFlag.CERTIFY_OTHER).setKeyCreationDate(now).build())
            .addSubkey(KeySpec.getBuilder(KeyType.EDDSA_LEGACY(EdDSALegacyCurve._Ed25519), KeyFlag.SIGN_DATA).setKeyCreationDate(now).build())
            .addSubkey(
                KeySpec.getBuilder(KeyType.XDH_LEGACY(XDHLegacySpec._X25519), KeyFlag.ENCRYPT_COMMS, KeyFlag.ENCRYPT_STORAGE)
                    .setKeyCreationDate(now).build()
            )
            .addUserId("$n <$e>")
            .setExpirationDate(plusYears(now, validYears))
            .build()
        return protect(unprotected, Passphrase.emptyPassphrase(), passphrase)
    }

    fun checkNewPassphrase(passphrase: CharArray) {
        if (passphrase.size < MIN_PASSPHRASE) {
            throw PgpError("A palavra-passe tem de ter pelo menos $MIN_PASSPHRASE caracteres. Usa uma frase com 5 ou mais palavras.")
        }
    }

    /** Lê uma ou mais chaves públicas (texto ASCII-armor ou binário). */
    fun parseCertificates(data: ByteArray): List<PGPPublicKeyRing> {
        if (String(data, Charsets.ISO_8859_1).contains("PRIVATE KEY BLOCK")) {
            throw PgpError("Isto é uma chave PRIVADA. Importa-a no separador \"Chaves\".")
        }
        val certs = try {
            PGPainless.readKeyRing().publicKeyRingCollection(data).keyRings.asSequence().toList()
        } catch (e: Exception) {
            throw PgpError("Não reconheço isto como uma chave pública.", e)
        }
        if (certs.isEmpty()) throw PgpError("Não encontrei nenhuma chave pública.")
        return certs
    }

    /** Lê uma ou mais chaves privadas. */
    fun parseSecretKeys(data: ByteArray): List<PGPSecretKeyRing> {
        val keys = try {
            PGPainless.readKeyRing().secretKeyRingCollection(data).keyRings.asSequence().toList()
        } catch (e: Exception) {
            throw PgpError("Não reconheço isto como uma chave privada.", e)
        }
        if (keys.isEmpty()) throw PgpError("Não encontrei nenhuma chave privada.")
        return keys
    }

    /**
     * Valida uma chave pública antes de a guardar e retira-lhe as subchaves que não estão
     * validamente ligadas à primária (p. ex. subchaves de outra pessoa coladas por um atacante).
     * Com [requireUsable], exige também um nome válido e que sirva para encriptar.
     */
    fun cleanCertificate(cert: PGPPublicKeyRing, requireUsable: Boolean, now: Date = Date()): PGPPublicKeyRing {
        val info = try {
            PGPainless.inspectKeyRing(cert, now)
        } catch (e: Exception) {
            throw PgpError("Chave pública inválida: sem auto-assinatura válida, com algoritmos rejeitados ou com data no futuro (confirma o relógio).", e)
        }
        var ring = cert
        val primary = cert.publicKey
        for (k in cert.publicKeys.asSequence().filterNot { it.isMasterKey }.toList()) {
            // Fica: subchave validamente ligada (e, se assina, com a assinatura de volta da própria
            // subchave), ou subchave revogada pela PRÓPRIA chave primária (para se saber da revogação).
            val keep = if (info.isKeyValidlyBound(k.keyID)) {
                !hasFlag(k, KeyFlag.SIGN_DATA) || hasValidBacksig(primary, k)
            } else {
                hasVerifiedRevocation(primary, k)
            }
            if (!keep) ring = PGPPublicKeyRing.removePublicKey(ring, k) ?: ring
        }
        if (requireUsable) {
            val i = try { PGPainless.inspectKeyRing(ring, now) } catch (e: Exception) { throw PgpError("Chave pública inválida.", e) }
            if (i.validUserIds.isEmpty()) {
                throw PgpError("Esta chave não tem nenhum nome/email válido (por exemplo, do keys.openpgp.org sem o email confirmado).")
            }
            if (!i.isUsableForEncryption) throw PgpError("Esta chave não pode ser usada para encriptar (expirada ou revogada).")
        }
        return ring
    }

    private fun isRevokedSubkey(k: PGPPublicKey) = k.getSignaturesOfType(PGPSignature.SUBKEY_REVOCATION).hasNext()

    private val verifier = BcPGPContentVerifierBuilderProvider()

    /** A subchave tem uma revogação assinada pela chave primária indicada. */
    private fun hasVerifiedRevocation(primary: PGPPublicKey, sub: PGPPublicKey): Boolean =
        sub.getSignaturesOfType(PGPSignature.SUBKEY_REVOCATION).asSequence().any { sig ->
            runCatching { sig.init(verifier, primary); sig.verifyCertification(primary, sub) }.getOrDefault(false)
        }

    /**
     * Uma subchave de assinatura tem de provar que aceita pertencer a esta chave primária:
     * a ligação contém uma assinatura "de volta" (0x19) feita pela própria subchave.
     * Sem isto, qualquer pessoa podia colar a subchave de assinatura de outra pessoa na sua chave.
     */
    private fun hasValidBacksig(primary: PGPPublicKey, sub: PGPPublicKey): Boolean =
        sub.getSignaturesOfType(PGPSignature.SUBKEY_BINDING).asSequence().any { binding ->
            val bindingOk = runCatching { binding.init(verifier, primary); binding.verifyCertification(primary, sub) }.getOrDefault(false)
            bindingOk && listOfNotNull(binding.hashedSubPackets, binding.unhashedSubPackets)
                .flatMap { v -> runCatching { v.embeddedSignatures.toList() }.getOrDefault(emptyList()) }
                .any { back ->
                    back.signatureType == PGPSignature.PRIMARYKEY_BINDING &&
                        runCatching { back.init(verifier, sub); back.verifyCertification(primary, sub) }.getOrDefault(false)
                }
        }

    /** true se todas as partes privadas presentes estão protegidas por palavra-passe. */
    fun isProtected(key: PGPSecretKeyRing): Boolean =
        key.secretKeys.asSequence().filterNot { it.isPrivateKeyEmpty }.all { it.keyEncryptionAlgorithm != 0 }

    /**
     * true se a chave contém mesmo a parte privada de uma subchave de encriptação não revogada
     * (e não só "stubs", como numa exportação de uma chave que vive num smartcard). Chaves
     * expiradas contam: podem ser importadas e depois renovadas.
     */
    fun hasUsableSecret(key: PGPSecretKeyRing): Boolean =
        key.secretKeys.asSequence().any { sk ->
            !sk.isPrivateKeyEmpty && sk.publicKey.isEncryptionKey && !isRevokedSubkey(sk.publicKey)
        }

    fun checkPassphrase(key: PGPSecretKeyRing, passphrase: CharArray): Boolean {
        val pp = Passphrase(passphrase.copyOf())
        return try {
            val protector = SecretKeyRingProtector.unlockAnyKeyWith(pp)
            val real = key.secretKeys.asSequence().filterNot { it.isPrivateKeyEmpty }.toList()
            if (real.isEmpty()) return false
            real.forEach { UnlockSecretKey.unlockSecretKey(it, protector) }
            true
        } catch (e: WrongPassphraseException) {
            false
        } finally {
            pp.clear()
        }
    }

    /**
     * Prepara uma chave privada importada: confirma a palavra-passe e volta a protegê-la
     * com [PROTECTION]. Uma chave sem palavra-passe fica protegida com [passphrase].
     */
    fun prepareImported(key: PGPSecretKeyRing, passphrase: CharArray): PGPSecretKeyRing {
        info(key) // falha com PgpError se a chave não puder ser avaliada
        if (!hasUsableSecret(key)) {
            throw PgpError("Este ficheiro não contém a parte privada da chave (está num cartão/smartcard?).")
        }
        if (!isProtected(key)) {
            checkNewPassphrase(passphrase)
            return protect(key, Passphrase.emptyPassphrase(), passphrase)
        }
        if (!checkPassphrase(key, passphrase)) throw WrongPassphraseError()
        return try {
            protect(key, Passphrase(passphrase.copyOf()), passphrase)
        } catch (e: Exception) {
            key // p. ex. chave com a primária offline (gnu-dummy): fica com a proteção original
        }
    }

    private fun protect(key: PGPSecretKeyRing, old: Passphrase, new: CharArray): PGPSecretKeyRing {
        val pp = Passphrase(new.copyOf())
        try {
            return PGPainless.modifyKeyRing(key)
                .changePassphraseFromOldPassphrase(old)
                .withCustomSettings(PROTECTION)
                .toNewPassphrase(pp)
                .done()
        } finally {
            old.clear()
            pp.clear()
        }
    }

    fun certificateOf(key: PGPSecretKeyRing): PGPPublicKeyRing = PGPainless.extractCertificate(key)

    fun armor(key: PGPKeyRing): String = PGPainless.asciiArmor(key)

    fun fingerprint(key: PGPKeyRing): String = OpenPgpFingerprint.of(key).fingerprint

    fun info(key: PGPKeyRing, now: Date = Date()): KeyInfo {
        val i = try {
            PGPainless.inspectKeyRing(key, now)
        } catch (e: Exception) {
            throw PgpError("Não consigo avaliar esta chave (assinaturas inválidas ou data no futuro).", e)
        }
        return KeyInfo(
            fingerprint = i.fingerprint.fingerprint,
            userId = displayName(
                i.primaryUserId?.takeIf { it in i.validUserIds } ?: i.validUserIds.firstOrNull() ?: i.getPossiblyExpiredPrimaryUserId()
                    ?: i.userIds.firstOrNull() ?: "(sem nome)"
            ),
            created = i.creationDate,
            expires = i.primaryKeyExpirationDate,
            revoked = !i.revocationState.isNotRevoked(),
            canEncrypt = i.isUsableForEncryption,
            canSign = i.isUsableForSigning,
        )
    }

    /**
     * Limpa um nome para mostrar no ecrã: retira caracteres de controlo e de formatação
     * (incluindo os bidirecionais, usados para disfarçar texto), junta espaços e corta o tamanho.
     */
    fun displayName(raw: String): String {
        val cleaned = raw.map { if (Character.isISOControl(it)) ' ' else it }
            .filterNot { Character.getType(it) == Character.FORMAT.toInt() }
            .joinToString("").replace(Regex("\\s+"), " ").trim()
        return if (cleaned.length > 80) cleaned.take(79) + "…" else cleaned.ifEmpty { "(sem nome)" }
    }

    /** Agrupa a impressão digital como o GnuPG: "ABCD 1234 ... (5 grupos)  (5 grupos)". */
    fun prettyFingerprint(fpr: String): String {
        val groups = fpr.uppercase().chunked(4)
        return if (groups.size == 10) {
            groups.take(5).joinToString(" ") + "  " + groups.drop(5).joinToString(" ")
        } else {
            groups.joinToString(" ")
        }
    }

    /**
     * A impressão digital em palavras portuguesas (uma por byte), mais fáceis de ler em voz alta
     * do que letras e números. É a impressão digital inteira, só escrita de outra maneira.
     */
    fun fingerprintWords(fpr: String): List<String> = fpr.chunked(2).map { Disguise.WORDS[it.toInt(16)] }

    /**
     * Se [text] trouxer chaves públicas armoradas no meio de outro texto (p. ex. um convite com
     * instruções), devolve só os blocos das chaves; caso contrário devolve [text] tal como veio.
     */
    fun extractPublicKeys(text: String): String {
        val blocks = Regex("-----BEGIN PGP PUBLIC KEY BLOCK-----.*?-----END PGP PUBLIC KEY BLOCK-----", RegexOption.DOT_MATCHES_ALL)
            .findAll(text).map { it.value }.toList()
        return if (blocks.isEmpty()) text else blocks.joinToString("\n")
    }

    /** Converte uma mensagem binária (.gpg/.pgp) em texto ASCII-armor; texto já armorado fica igual. */
    fun ensureArmored(data: ByteArray): String {
        val head = String(data, 0, minOf(data.size, 64), Charsets.ISO_8859_1).trimStart()
        if (head.startsWith("-----BEGIN PGP")) return String(data, Charsets.UTF_8)
        if (data.isEmpty() || (data[0].toInt() and 0x80) == 0) throw PgpError("Não reconheço isto como uma mensagem PGP.")
        val out = ByteArrayOutputStream()
        ArmoredOutputStream.builder().clearHeaders().build(out).use { it.write(data) }
        return out.toString(Charsets.US_ASCII.name())
    }

    /** Converte texto ASCII-armor (mensagem ou chave) nos bytes binários OpenPGP. */
    fun dearmor(armored: String): ByteArray = try {
        org.bouncycastle.openpgp.PGPUtil.getDecoderStream(armored.toByteArray(Charsets.UTF_8).inputStream()).use { it.readBytes() }
    } catch (e: Exception) {
        throw PgpError("Não reconheço isto como PGP.", e)
    }

    /**
     * Disfarça uma mensagem ou chave PGP (armorada) para não parecer PGP: como um código, ou,
     * com [words], como uma sequência de palavras portuguesas. Ver [Disguise].
     */
    fun disguise(armored: String, words: Boolean = false): String = Disguise.hide(dearmor(armored), words)

    /**
     * Se [text] for um texto disfarçado pela app, devolve-o como PGP normal (ASCII-armor);
     * caso contrário devolve null.
     */
    fun undisguise(text: String): String? {
        val bytes = Disguise.reveal(text) ?: return null
        return runCatching { ensureArmored(bytes) }.getOrNull()
    }

    /** Ids (64 bits) das chaves para as quais a mensagem foi encriptada (0 = destinatário oculto). */
    fun recipientKeyIds(message: String): List<Long> = try {
        MessageInspector.determineEncryptionInfoForMessage(message).keyIds
    } catch (e: Exception) {
        throw PgpError("Não reconheço isto como uma mensagem PGP.", e)
    }

    fun keyIds(key: PGPKeyRing): Set<Long> = key.publicKeys.asSequence().map { it.keyID }.toSet()

    fun encrypt(
        text: String,
        recipients: List<PGPPublicKeyRing>,
        signer: PGPSecretKeyRing?,
        passphrase: CharArray?,
    ): String {
        val out = ByteArrayOutputStream()
        produce(text.toByteArray(Charsets.UTF_8).inputStream(), out, recipients, signer, passphrase, armor = true, fileName = null)
        return out.toString(Charsets.UTF_8.name())
    }

    /**
     * Encripta um ficheiro (fotografia, documento...) de [input] para [output], em OpenPGP binário
     * (o formato dos ficheiros .pgp/.gpg). O nome original vai guardado dentro da parte encriptada.
     */
    fun encryptFile(
        input: InputStream,
        output: OutputStream,
        fileName: String?,
        recipients: List<PGPPublicKeyRing>,
        signer: PGPSecretKeyRing?,
        passphrase: CharArray?,
    ) = produce(input, output, recipients, signer, passphrase, armor = false, fileName = fileName)

    private fun produce(
        input: InputStream,
        output: OutputStream,
        recipients: List<PGPPublicKeyRing>,
        signer: PGPSecretKeyRing?,
        passphrase: CharArray?,
        armor: Boolean,
        fileName: String?,
    ) {
        if (recipients.isEmpty()) throw PgpError("Escolhe pelo menos um destinatário.")
        val enc = EncryptionOptions.encryptCommunications()
        for (r in recipients) {
            try {
                enc.addRecipient(r)
            } catch (e: Exception) {
                throw PgpError("A chave de ${info(r).userId} não pode ser usada para encriptar (expirada ou revogada?).", e)
            }
        }
        val pp = passphrase?.let { Passphrase(it.copyOf()) }
        try {
            val options = if (signer != null) {
                ProducerOptions.signAndEncrypt(enc, signing(signer, pp, detached = false))
            } else {
                ProducerOptions.encrypt(enc)
            }
            options.setAsciiArmor(armor)
            if (fileName != null) options.setFileName(displayName(fileName).replace('/', '_'))
            PGPainless.encryptAndOrSign().onOutputStream(output).withOptions(options).use { input.copyTo(it, 64 * 1024) }
        } finally {
            pp?.clear()
        }
    }

    private fun signing(signer: PGPSecretKeyRing, pp: Passphrase?, detached: Boolean): SigningOptions = try {
        val protector = SecretKeyRingProtector.unlockAnyKeyWith(pp ?: Passphrase.emptyPassphrase())
        if (detached) SigningOptions.get().addDetachedSignature(protector, signer, DocumentSignatureType.CANONICAL_TEXT_DOCUMENT)
        else SigningOptions.get().addInlineSignature(protector, signer, DocumentSignatureType.BINARY_DOCUMENT)
    } catch (e: WrongPassphraseException) {
        throw WrongPassphraseError(e)
    } catch (e: PgpError) {
        throw e
    } catch (e: Exception) {
        val stub = signer.secretKeys.asSequence().any { it.isPrivateKeyEmpty }
        throw PgpError(
            if (stub) "A parte de assinatura da tua chave não está neste telemóvel (está num cartão/smartcard?). Desliga \"Assinar\"."
            else "A tua chave não pode assinar (expirada ou revogada?).", e,
        )
    }

    /**
     * Assina um texto SEM o encriptar: o texto fica legível por toda a gente, com a assinatura por
     * baixo ("-----BEGIN PGP SIGNED MESSAGE-----"). Serve para provar que um texto público é teu.
     */
    fun sign(text: String, signer: PGPSecretKeyRing, passphrase: CharArray): String {
        if (text.isBlank()) throw PgpError("Escreve primeiro o texto.")
        val pp = Passphrase(passphrase.copyOf())
        try {
            val options = ProducerOptions.sign(signing(signer, pp, detached = true)).setCleartextSigned()
            val out = ByteArrayOutputStream()
            PGPainless.encryptAndOrSign().onOutputStream(out).withOptions(options).use { it.write(text.toByteArray(Charsets.UTF_8)) }
            return out.toString(Charsets.UTF_8.name())
        } finally {
            pp.clear()
        }
    }

    fun isSignedText(text: String): Boolean = text.trimStart().startsWith("-----BEGIN PGP SIGNED MESSAGE-----")

    /** Verifica um texto assinado (ver [sign]) e devolve o texto e o estado da assinatura. */
    fun verify(message: String, verificationCerts: List<PGPPublicKeyRing>): Decrypted {
        if (!isSignedText(message)) throw PgpError("Isto não é um texto assinado.")
        try {
            val options = ConsumerOptions.get()
            val certs = dedupe(verificationCerts)
            certs.forEach { options.addVerificationCert(it) }
            val out = ByteArrayOutputStream()
            val stream = PGPainless.decryptAndOrVerify()
                .onInputStream(message.trimStart().toByteArray(Charsets.UTF_8).inputStream())
                .withOptions(options)
            stream.use { copyLimited(it, out, MAX_PLAINTEXT.toLong()) }
            val plaintext = out.toByteArray()
            val status = signatureStatus(stream.metadata, certs, plaintext)
            if (status == SignatureStatus.None) throw PgpError("Não encontrei nenhuma assinatura neste texto.")
            return Decrypted(String(plaintext, Charsets.UTF_8), status)
        } catch (e: PgpError) {
            throw e
        } catch (e: Exception) {
            throw PgpError("O texto assinado está danificado; não é possível verificá-lo.", e)
        }
    }

    /**
     * Desencripta e verifica. O texto só é devolvido depois de a mensagem ter sido lida
     * até ao fim e a verificação de integridade ter passado.
     *
     * [verificationCerts] vai por ordem de confiança (as tuas chaves, depois os contactos
     * verificados, depois os outros): se duas chaves partilharem uma subchave, fica a de maior
     * confiança, para que uma chave importada não possa "tapar" a de um contacto verificado.
     */
    fun decrypt(
        message: String,
        myKeys: List<PGPSecretKeyRing>,
        passphrase: CharArray,
        verificationCerts: List<PGPPublicKeyRing>,
    ): Decrypted {
        val out = ByteArrayOutputStream()
        val bytes = message.toByteArray(Charsets.UTF_8)
        val r = consume({ bytes.inputStream() }, out, MAX_PLAINTEXT.toLong(), myKeys, passphrase, verificationCerts) { out.toByteArray() }
        return Decrypted(String(out.toByteArray(), Charsets.UTF_8), r.signature)
    }

    /**
     * Desencripta um ficheiro encriptado (.pgp/.gpg, binário ou armorado) de [open] para [output].
     * [open] é chamado duas vezes (ver para quem é, depois desencriptar). Em [Decrypted.text] vem o
     * nome original do ficheiro, se a mensagem o trouxer.
     *
     * ATENÇÃO: os bytes vão sendo escritos em [output] antes de a integridade estar confirmada.
     * Se esta função lançar um erro, quem a chamou tem de APAGAR o que foi escrito.
     */
    fun decryptFile(
        open: () -> InputStream,
        output: OutputStream,
        myKeys: List<PGPSecretKeyRing>,
        passphrase: CharArray,
        verificationCerts: List<PGPPublicKeyRing>,
        limit: Long = MAX_FILE,
    ): Decrypted = consume(open, output, limit, myKeys, passphrase, verificationCerts, null)

    /** Ids das chaves para as quais um ficheiro encriptado foi feito (0 = destinatário oculto). */
    fun recipientKeyIds(input: InputStream): List<Long> = try {
        MessageInspector.determineEncryptionInfoForMessage(input).keyIds
    } catch (e: Exception) {
        throw PgpError("Não reconheço isto como um ficheiro encriptado com PGP.", e)
    }

    private fun copyLimited(input: InputStream, out: OutputStream, limit: Long) {
        val buf = ByteArray(64 * 1024)
        var total = 0L
        while (true) {
            val n = input.read(buf)
            if (n < 0) break
            total += n
            if (total > limit) throw PgpError("O conteúdo é demasiado grande.")
            out.write(buf, 0, n)
        }
    }

    /** [plaintext]: dá os bytes já escritos (mensagens de texto); null nos ficheiros, que não ficam em memória. */
    private fun consume(
        open: () -> InputStream,
        out: OutputStream,
        limit: Long,
        myKeys: List<PGPSecretKeyRing>,
        passphrase: CharArray,
        verificationCerts: List<PGPPublicKeyRing>,
        plaintext: (() -> ByteArray)?,
    ): Decrypted {
        val recipients = open().use { recipientKeyIds(it) }.toSet()
        val pp = Passphrase(passphrase.copyOf())
        try {
            // Só entram as chaves que a palavra-passe abre: com várias chaves e palavras-passe
            // diferentes, uma chave que não abre faria falhar toda a desencriptação.
            val unlocked = myKeys.filter { unlocksForMessage(it, recipients, pp) }
            if (unlocked.isEmpty()) throw WrongPassphraseError()

            val options = ConsumerOptions.get()
                .setMissingKeyPassphraseStrategy(MissingKeyPassphraseStrategy.THROW_EXCEPTION)
            val protector = SecretKeyRingProtector.unlockAnyKeyWith(pp)
            unlocked.forEach { options.addDecryptionKey(it, protector) }
            val certs = dedupe(verificationCerts)
            certs.forEach { options.addVerificationCert(it) }

            val stream = open().use { input ->
                val s = PGPainless.decryptAndOrVerify().onInputStream(input).withOptions(options)
                s.use { copyLimited(it, out, limit) }
                s
            }
            val meta = stream.metadata
            if (!meta.isEncrypted) throw PgpError("Esta mensagem não está encriptada.")
            return Decrypted(meta.filename?.takeIf { it.isNotBlank() }?.let(::displayName).orEmpty(), signatureStatus(meta, certs, plaintext?.invoke()))
        } catch (e: PgpError) {
            throw e
        } catch (e: WrongPassphraseException) {
            throw WrongPassphraseError(e)
        } catch (e: MissingDecryptionMethodException) {
            // Destinatário oculto: a palavra-passe abriu outra das tuas chaves, não a certa.
            if (0L in recipients) throw WrongPassphraseError(e)
            throw PgpError("Esta mensagem não foi encriptada para nenhuma das tuas chaves.", e)
        } catch (e: OutOfMemoryError) {
            throw PgpError("A mensagem é demasiado grande para este telemóvel.")
        } catch (e: Exception) {
            throw PgpError("A mensagem está danificada ou foi alterada; não é possível desencriptá-la.", e)
        } finally {
            pp.clear()
        }
    }

    private fun signatureStatus(meta: MessageMetadata, certs: List<PGPPublicKeyRing>, plaintext: ByteArray?): SignatureStatus {
        val rejectedKnown = meta.rejectedSignatures.map { it.signature }.filter { sig -> certs.any { it.getPublicKey(sig.keyID) != null } }
        return when {
            rejectedKnown.isNotEmpty() -> {
                val sig = rejectedKnown.first()
                val owner = certs.first { it.getPublicKey(sig.keyID) != null }
                // Distingue "não confere" (alterada/falsa) de "confere mas a chave já não é aceite".
                // Nos ficheiros (sem os bytes em memória) vale o estado da chave de quem assinou.
                val keyProblem = if (plaintext != null) mathematicallyValid(sig, owner.getPublicKey(sig.keyID), plaintext)
                else runCatching { !info(owner).canSign }.getOrDefault(false)
                if (keyProblem) SignatureStatus.Rejected(fingerprint(owner)) else SignatureStatus.Invalid
            }
            meta.verifiedSignatures.isNotEmpty() ->
                SignatureStatus.Valid(meta.verifiedSignatures.first().signingKey.primaryKeyFingerprint.fingerprint)
            meta.hasSignature -> SignatureStatus.UnknownSigner
            else -> SignatureStatus.None
        }
    }

    /** Verifica só a matemática da assinatura sobre o texto (sem regras de validade da chave). */
    private fun mathematicallyValid(sig: PGPSignature, key: PGPPublicKey, data: ByteArray): Boolean = runCatching {
        sig.init(verifier, key)
        when (sig.signatureType) {
            PGPSignature.BINARY_DOCUMENT -> sig.update(data)
            PGPSignature.CANONICAL_TEXT_DOCUMENT -> sig.update(
                String(data, Charsets.UTF_8).replace("\r\n", "\n").replace("\n", "\r\n").toByteArray(Charsets.UTF_8)
            )
            else -> return@runCatching false
        }
        sig.verify()
    }.getOrDefault(false)

    /** true se [pp] abre a parte privada de uma subchave de [key] para a qual a mensagem foi encriptada. */
    private fun unlocksForMessage(key: PGPSecretKeyRing, recipients: Set<Long>, pp: Passphrase): Boolean {
        val protector = SecretKeyRingProtector.unlockAnyKeyWith(pp)
        val wildcard = 0L in recipients
        val targets = key.secretKeys.asSequence()
            .filterNot { it.isPrivateKeyEmpty }
            .filter { it.keyID in recipients || (wildcard && it.publicKey.isEncryptionKey) }
            .toList()
        if (targets.isEmpty()) return false
        return try {
            UnlockSecretKey.unlockSecretKey(targets.first(), protector)
            true
        } catch (e: WrongPassphraseException) {
            false
        }
    }

    /**
     * Quando um id de chave aparece em várias chaves, fica só onde pertence de facto: na chave em
     * que é a primária, ou onde está ligada com a assinatura "de volta" da própria subchave. Em caso
     * de dúvida, fica na chave de maior confiança (as listas vêm por ordem de confiança).
     */
    private fun dedupe(certs: List<PGPPublicKeyRing>): List<PGPPublicKeyRing> {
        val primaries = certs.map { it.publicKey.keyID }.toSet()
        val count = HashMap<Long, Int>()
        certs.forEach { c -> keyIds(c).forEach { count[it] = (count[it] ?: 0) + 1 } }
        val claimed = HashSet<Long>()
        val result = mutableListOf<PGPPublicKeyRing>()
        for (cert in certs) {
            if (!claimed.add(cert.publicKey.keyID)) continue // a mesma chave primária repetida
            var ring = cert
            for (k in cert.publicKeys.asSequence().filterNot { it.isMasterKey }.toList()) {
                if ((count[k.keyID] ?: 0) <= 1) continue
                val legit = k.keyID !in primaries && hasValidBacksig(cert.publicKey, k) && claimed.add(k.keyID)
                if (!legit) ring = PGPPublicKeyRing.removePublicKey(ring, k) ?: ring
            }
            result.add(ring)
        }
        return result
    }

    /**
     * Prolonga a validade por [years] anos a partir de [now]. Só renova as subchaves em uso:
     * nunca as revogadas (mesmo as só "retiradas"). Se a chave inteira expirou, renova a
     * subchave mais recente de cada função (encriptar, assinar).
     */
    fun extendExpiry(key: PGPSecretKeyRing, passphrase: CharArray, years: Int = 2, now: Date = Date()): PGPSecretKeyRing {
        val pp = Passphrase(passphrase.copyOf())
        try {
            val protector = SecretKeyRingProtector.unlockAnyKeyWith(pp)
            val expiry = plusYears(now, years)
            val info = PGPainless.inspectKeyRing(key, now)
            val subkeys = key.publicKeys.asSequence().filterNot { it.isMasterKey || isRevokedSubkey(it) }.toList()
            // Em uso = validamente ligada e ainda não expirada (as que expiraram foram substituídas).
            val chosen = subkeys.filter {
                info.isKeyValidlyBound(it.keyID) && info.getSubkeyExpirationDate(it.keyID).let { exp -> exp == null || exp.after(now) }
            }.toMutableSet()
            for (flag in listOf(KeyFlag.ENCRYPT_COMMS, KeyFlag.SIGN_DATA)) {
                if (chosen.none { hasFlag(it, flag) }) {
                    subkeys.filter { hasFlag(it, flag) }.maxByOrNull { it.creationTime }?.let { chosen += it }
                }
            }
            val editor = PGPainless.modifyKeyRing(key, now).setExpirationDate(expiry, protector)
            chosen.forEach { editor.setExpirationDateOfSubkey(expiry, it.keyID, protector) }
            return editor.done()
        } catch (e: WrongPassphraseException) {
            throw WrongPassphraseError(e)
        } catch (e: PgpError) {
            throw e
        } catch (e: Exception) {
            throw PgpError("Não foi possível prolongar a validade desta chave.", e)
        } finally {
            pp.clear()
        }
    }

    /** Funções declaradas na assinatura de ligação mais recente da subchave. */
    private fun hasFlag(sub: PGPPublicKey, flag: KeyFlag): Boolean {
        val latest = sub.getSignaturesOfType(PGPSignature.SUBKEY_BINDING).asSequence().maxByOrNull { it.creationTime }
            ?: return false
        val flags = latest.hashedSubPackets?.keyFlags ?: 0
        return KeyFlag.hasKeyFlag(flags, flag)
    }

    private fun plusYears(date: Date, years: Int): Date =
        Calendar.getInstance().apply { time = date; add(Calendar.YEAR, years) }.time
}
