package app.reczi.pgp.core

import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureGenerator
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder
import org.pgpainless.PGPainless
import org.pgpainless.algorithm.KeyFlag
import org.pgpainless.encryption_signing.EncryptionOptions
import org.pgpainless.encryption_signing.ProducerOptions
import org.pgpainless.key.generation.KeySpec
import org.pgpainless.key.generation.type.KeyType
import org.pgpainless.key.generation.type.xdh_legacy.XDHLegacySpec
import org.pgpainless.key.protection.SecretKeyRingProtector
import org.pgpainless.key.protection.UnlockSecretKey
import org.pgpainless.key.util.RevocationAttributes
import org.pgpainless.util.Passphrase
import java.io.ByteArrayOutputStream
import java.util.Calendar
import java.util.Date
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Testes para o que a segunda verificação encontrou. */
class SecondRoundTest {
    private val pass = "cavalo bateria agrafo correto".toCharArray()

    private fun protector() = SecretKeyRingProtector.unlockAnyKeyWith(Passphrase(pass.copyOf()))

    /** O "atacante" assina com a SUA primária uma ligação a uma subchave de outra pessoa. */
    private fun bindForeign(attacker: PGPSecretKeyRing, foreign: PGPPublicKey, flags: Int, revoke: Boolean = false): PGPPublicKeyRing {
        val priv = UnlockSecretKey.unlockSecretKey(attacker.secretKey, protector())
        val primaryPub = attacker.publicKey
        fun sig(type: Int): PGPSignature {
            val gen = PGPSignatureGenerator(BcPGPContentSignerBuilder(primaryPub.algorithm, HashAlgorithmTags.SHA512), primaryPub)
            gen.init(type, priv)
            gen.setHashedSubpackets(PGPSignatureSubpacketGenerator().apply {
                setSignatureCreationTime(false, Date())
                if (type == PGPSignature.SUBKEY_BINDING) setKeyFlags(false, flags)
                setIssuerFingerprint(false, primaryPub)
            }.generate())
            return gen.generateCertification(primaryPub, foreign)
        }
        var k = PGPPublicKey.addCertification(foreign, sig(PGPSignature.SUBKEY_BINDING))
        if (revoke) k = PGPPublicKey.addCertification(k, sig(PGPSignature.SUBKEY_REVOCATION))
        return PGPPublicKeyRing.insertPublicKey(Pgp.certificateOf(attacker), k)
    }

    private fun signingSub(k: PGPSecretKeyRing) = Pgp.certificateOf(k).publicKeys.asSequence().first { !it.isMasterKey && !it.isEncryptionKey }

    @Test
    fun foreignSigningSubkeyBoundByAttackerIsStrippedAndCannotShadow() {
        val alice = Pgp.generate("Alice", "alice@exemplo.pt", pass)
        val mallory = Pgp.generate("Mallory", "m@exemplo.pt", pass)
        val bob = Pgp.generate("Bob", "bob@exemplo.pt", pass)
        val evil = bindForeign(mallory, signingSub(alice), KeyFlag.toBitmask(KeyFlag.SIGN_DATA))
        assertTrue(PGPainless.inspectKeyRing(evil).isKeyValidlyBound(signingSub(alice).keyID), "o PGPainless aceita a ligação sem a assinatura de volta")

        val v = Vault(MemoryStore()).apply { addMyKey(bob) }
        v.importContacts(listOf(evil, Pgp.certificateOf(alice)))
        v.contacts().forEach { v.setVerified(it.info.fingerprint, true) } // as duas verificadas (mesma confiança)
        assertFalse(v.contacts().first { it.info.userId.startsWith("Mallory") }.cert.publicKeys.asSequence().any { it.keyID == signingSub(alice).keyID })

        val msg = Pgp.encrypt("sou a Alice", listOf(Pgp.certificateOf(bob)), alice, pass)
        assertEquals(SignatureStatus.Valid(Pgp.fingerprint(alice)), v.decrypt(msg, pass).signature)
        // Mesmo sem a limpeza da importação, e com a Mallory primeiro na lista, a deduplicação protege.
        val direct = Pgp.decrypt(msg, listOf(bob), pass, listOf(evil, Pgp.certificateOf(alice)))
        assertEquals(SignatureStatus.Valid(Pgp.fingerprint(alice)), direct.signature)
    }

    @Test
    fun fakeUpdateWithBogusRevocationsCannotInjectKeys() {
        val alice = Pgp.generate("Alice", "alice@exemplo.pt", pass)
        val carol = Pgp.generate("Carol", "carol@exemplo.pt", pass)
        val mallory = Pgp.generate("Mallory", "m@exemplo.pt", pass)
        val bob = Pgp.generate("Bob", "bob@exemplo.pt", pass)
        val v = Vault(MemoryStore()).apply { addMyKey(bob) }
        v.importContacts(listOf(Pgp.certificateOf(alice), Pgp.certificateOf(carol)))
        v.contacts().forEach { v.setVerified(it.info.fingerprint, true) }

        // "Atualização" falsa da Alice com a subchave de assinatura da Carol e uma revogação forjada.
        val injected = PGPPublicKeyRing.insertPublicKey(
            Pgp.certificateOf(alice),
            bindForeign(mallory, signingSub(carol), KeyFlag.toBitmask(KeyFlag.SIGN_DATA), revoke = true)
                .getPublicKey(signingSub(carol).keyID),
        )
        v.importContacts(listOf(injected))
        val stored = v.contacts().first { it.info.userId.startsWith("Alice") }.cert
        assertFalse(stored.publicKeys.asSequence().any { it.keyID == signingSub(carol).keyID })

        val fromCarol = Pgp.encrypt("sou a Carol", listOf(Pgp.certificateOf(bob)), carol, pass)
        val r = v.decrypt(fromCarol, pass)
        assertEquals(SignatureStatus.Valid(Pgp.fingerprint(carol)), r.signature)
        assertTrue(r.signerVerified)
    }

    @Test
    fun signatureOfRevokedKeyIsRejectedNotInvalid() {
        val alice = Pgp.generate("Alice", "alice@exemplo.pt", pass)
        val bob = Pgp.generate("Bob", "bob@exemplo.pt", pass)
        val msg = Pgp.encrypt("antes da revogação", listOf(Pgp.certificateOf(bob)), alice, pass)
        val revoked = PGPainless.modifyKeyRing(alice)
            .revoke(protector(), RevocationAttributes.createKeyRevocation().withReason(RevocationAttributes.Reason.KEY_COMPROMISED).withoutDescription())
            .done()
        val r = Pgp.decrypt(msg, listOf(bob), pass, listOf(Pgp.certificateOf(revoked)))
        assertEquals(SignatureStatus.Rejected(Pgp.fingerprint(alice)), r.signature)
        assertTrue(Pgp.info(revoked).revoked)

        // E o cofre recusa encriptar para uma chave revogada, mesmo verificada.
        val v = Vault(MemoryStore()).apply { addMyKey(bob) }
        v.importContacts(listOf(Pgp.certificateOf(alice)))
        v.setVerified(Pgp.fingerprint(alice), true)
        v.importContacts(listOf(Pgp.certificateOf(revoked))) // atualização com a revogação: aceite
        assertTrue(v.contacts().single().info.revoked)
        val e = runCatching { v.encrypt("x", listOf(Pgp.fingerprint(alice)), Pgp.fingerprint(bob), false, null) }.exceptionOrNull()
        assertTrue(e is PgpError && e.message!!.contains("REVOGADA"))
    }

    @Test
    fun extendExpiryDoesNotReviveSubkeyThatExpiredOnItsOwn() {
        var key = Pgp.generate("Ana", "ana@exemplo.pt", pass)
        val oldEnc = Pgp.certificateOf(key).publicKeys.asSequence().first { it.isEncryptionKey }.keyID
        val soon = Calendar.getInstance().apply { add(Calendar.DAY_OF_MONTH, 1) }.time
        key = PGPainless.modifyKeyRing(key)
            .addSubKey(KeySpec.getBuilder(KeyType.XDH_LEGACY(XDHLegacySpec._X25519), KeyFlag.ENCRYPT_COMMS, KeyFlag.ENCRYPT_STORAGE).build(),
                Passphrase(pass.copyOf()), protector())
            .setExpirationDateOfSubkey(soon, oldEnc, protector())
            .done()
        val later = Calendar.getInstance().apply { add(Calendar.DAY_OF_MONTH, 10) }.time
        val extended = Pgp.extendExpiry(key, pass, years = 2, now = later)
        val info = PGPainless.inspectKeyRing(extended, Calendar.getInstance().apply { add(Calendar.MONTH, 6) }.time)
        val stillExpired = info.getSubkeyExpirationDate(oldEnc)
        assertTrue(stillExpired != null && stillExpired.before(later), "a subchave antiga continua expirada")
        assertTrue(info.isUsableForEncryption)
    }

    @Test
    fun batchImportSkipsBadKeysAndKeepsGoodOnes() {
        val good1 = Pgp.certificateOf(Pgp.generate("Um", "um@exemplo.pt", pass))
        val future = Pgp.certificateOf(Pgp.generate("Futuro", "f@exemplo.pt", pass,
            now = Calendar.getInstance().apply { add(Calendar.HOUR, 3) }.time))
        val good2 = Pgp.certificateOf(Pgp.generate("Dois", "dois@exemplo.pt", pass))
        val v = Vault(MemoryStore()).apply { addMyKey(Pgp.generate("Eu", "eu@exemplo.pt", pass)) }
        val r = v.importContacts(listOf(good1, future, good2))
        assertEquals(listOf(Pgp.fingerprint(good1), Pgp.fingerprint(good2)), r.added)
        assertEquals(1, r.rejected.size)
        assertEquals(2, v.contacts().size)
    }

    @Test
    fun hiddenRecipientWithOtherKeysPassphraseSaysWrongPassphrase() {
        val a = Pgp.generate("A", "a@exemplo.pt", pass)
        val bPass = "frase da segunda chave muito longa".toCharArray()
        val b = Pgp.generate("B", "b@exemplo.pt", bPass)
        val v = Vault(MemoryStore()).apply { addMyKey(a); addMyKey(b) }
        val out = ByteArrayOutputStream()
        PGPainless.encryptAndOrSign().onOutputStream(out).withOptions(
            ProducerOptions.encrypt(EncryptionOptions.encryptCommunications().addHiddenRecipient(Pgp.certificateOf(b))).setAsciiArmor(true)
        ).use { it.write("oculto".toByteArray()) }
        val msg = out.toString()
        assertTrue(v.isForMe(msg))
        assertTrue(runCatching { v.decrypt(msg, pass) }.exceptionOrNull() is WrongPassphraseError)
        assertEquals("oculto", v.decrypt(msg, bPass).text)
    }

    @Test
    fun revokedUserIdIsNotShownAsName() {
        var key = Pgp.generate("Nome Antigo", "antigo@exemplo.pt", pass)
        key = PGPainless.modifyKeyRing(key).addUserId("Nome Novo <novo@exemplo.pt>", protector()).done()
        key = PGPainless.modifyKeyRing(key).revokeUserId("Nome Antigo <antigo@exemplo.pt>", protector(),
            RevocationAttributes.createCertificateRevocation().withReason(RevocationAttributes.Reason.USER_ID_NO_LONGER_VALID).withoutDescription()).done()
        assertEquals("Nome Novo <novo@exemplo.pt>", Pgp.info(key).userId)
    }
}
