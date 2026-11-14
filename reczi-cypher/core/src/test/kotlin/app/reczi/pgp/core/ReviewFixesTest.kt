package app.reczi.pgp.core

import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.util.encoders.Hex
import org.gnupg.GnuPGDummyKeyUtil
import org.pgpainless.PGPainless
import org.pgpainless.algorithm.KeyFlag
import org.pgpainless.key.generation.KeySpec
import org.pgpainless.key.generation.type.KeyType
import org.pgpainless.key.generation.type.xdh_legacy.XDHLegacySpec
import org.pgpainless.key.protection.SecretKeyRingProtector
import org.pgpainless.key.util.RevocationAttributes
import org.pgpainless.util.Passphrase
import java.util.Calendar
import java.util.Date
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Testes para os problemas confirmados na revisão de segurança. */
class ReviewFixesTest {
    private val pass = "cavalo bateria agrafo correto".toCharArray()
    private val pass2 = "outra frase completamente diferente".toCharArray()

    private fun cal(field: Int, amount: Int, from: Date = Date()) =
        Calendar.getInstance().apply { time = from; add(field, amount) }.time

    private fun vaultWith(key: PGPSecretKeyRing) = Vault(MemoryStore()).apply { addMyKey(key) }

    @Test
    fun badContactIsRejectedAndBrokenFilesDoNotBreakTheVault() {
        val store = MemoryStore()
        val v = Vault(store)
        val me = Pgp.generate("Eu", "eu@exemplo.pt", pass)
        v.addMyKey(me)

        // Chave com data no futuro (relógio adiantado de quem a criou): recusada na importação.
        val future = Pgp.generate("Futuro", "f@exemplo.pt", pass, now = cal(Calendar.HOUR, 2))
        assertFailsWith<PgpError> { v.importContacts(listOf(Pgp.certificateOf(future))) }
        assertEquals(0, v.contacts().size)

        // Ficheiros estragados no cofre: aparecem como "estragados", o resto continua a funcionar.
        store.write("pub-" + "AB".repeat(20), "lixo".toByteArray())
        store.write("sec-" + "CD".repeat(20), "lixo".toByteArray())
        store.write("verified", byteArrayOf(-1, -2))
        val snap = v.snapshot()
        assertEquals(1, snap.myKeys.size)
        assertEquals(setOf("pub-" + "AB".repeat(20), "sec-" + "CD".repeat(20)), snap.broken.map { it.name }.toSet())
        assertTrue(snap.broken.single { it.name.startsWith("sec-") }.isPrivateKey)

        val other = Pgp.generate("Outro", "o@exemplo.pt", pass)
        v.importContacts(listOf(Pgp.certificateOf(other)))
        v.setVerified(Pgp.fingerprint(other), true)
        val msg = v.encrypt("ainda funciona", listOf(Pgp.fingerprint(other)), Pgp.fingerprint(me), true, pass)
        assertEquals("ainda funciona", v.decrypt(msg, pass).text)

        v.discardBroken("pub-" + "AB".repeat(20))
        assertEquals(1, v.snapshot().broken.size)
    }

    @Test
    fun keyWithoutNameIsRejected() {
        val key = Pgp.generate("Sem Nome", "s@exemplo.pt", pass)
        val cert = Pgp.certificateOf(key)
        val primary = cert.publicKey
        val stripped = org.bouncycastle.openpgp.PGPPublicKey.removeCertification(primary, "Sem Nome <s@exemplo.pt>")
        val noUid = PGPPublicKeyRing.insertPublicKey(cert, stripped)
        val v = vaultWith(Pgp.generate("Eu", "eu@exemplo.pt", pass))
        assertFailsWith<PgpError> { v.importContacts(listOf(noUid)) }
        assertEquals(0, v.snapshot().broken.size)
    }

    @Test
    fun foreignSubkeyCannotShadowAVerifiedContact() {
        val alice = Pgp.generate("Alice", "alice@exemplo.pt", pass)
        val mallory = Pgp.generate("Mallory", "m@exemplo.pt", pass)
        val aliceSigning = Pgp.certificateOf(alice).publicKeys.asSequence()
            .first { !it.isMasterKey && !it.isEncryptionKey }
        // A Mallory cola a subchave de assinatura da Alice na sua própria chave pública.
        val evil = PGPPublicKeyRing.insertPublicKey(Pgp.certificateOf(mallory), aliceSigning)
        assertTrue(Pgp.keyIds(evil).contains(aliceSigning.keyID))

        // Na importação, a subchave que não está ligada à Mallory é retirada.
        val bob = vaultWith(Pgp.generate("Bob", "bob@exemplo.pt", pass))
        bob.importContacts(listOf(evil))
        assertFalse(bob.contacts().single().cert.publicKeys.asSequence().any { it.keyID == aliceSigning.keyID })

        // E mesmo sem essa limpeza, a ordem de confiança protege: a chave verificada (Alice) vem primeiro.
        val aliceVault = vaultWith(alice)
        val bobKey = Pgp.generate("Bob2", "bob2@exemplo.pt", pass)
        aliceVault.importContacts(listOf(Pgp.certificateOf(bobKey)))
        aliceVault.setVerified(Pgp.fingerprint(bobKey), true)
        val msg = aliceVault.encrypt("sou a Alice", listOf(Pgp.fingerprint(bobKey)), Pgp.fingerprint(alice), true, pass)
        val shadowFirst = Pgp.decrypt(msg, listOf(bobKey), pass, listOf(evil, Pgp.certificateOf(alice)))
        assertEquals(SignatureStatus.Valid(Pgp.fingerprint(alice)), shadowFirst.signature) // a deduplicação protege em qualquer ordem
        val trustedFirst = Pgp.decrypt(msg, listOf(bobKey), pass, listOf(Pgp.certificateOf(alice), evil))
        assertEquals(SignatureStatus.Valid(Pgp.fingerprint(alice)), trustedFirst.signature)
    }

    @Test
    fun stubPrivateKeyIsRejected() {
        val real = Pgp.generate("Alguém", "a@exemplo.pt", pass)
        val stub = GnuPGDummyKeyUtil.modify(real).removePrivateKeys(GnuPGDummyKeyUtil.KeyFilter.any())
        assertFalse(Pgp.hasUsableSecret(stub))
        assertFalse(Pgp.checkPassphrase(stub, "x".toCharArray()))
        assertFailsWith<PgpError> { Pgp.prepareImported(stub, "x".toCharArray()) }
        assertFailsWith<PgpError> { Vault(MemoryStore()).addMyKey(stub) }
        assertTrue(Pgp.hasUsableSecret(real))
    }

    @Test
    fun extendExpiryDoesNotReviveRetiredSubkey() {
        val created = Date()
        var key = Pgp.generate("Ana", "ana@exemplo.pt", pass, now = created)
        val protector = SecretKeyRingProtector.unlockAnyKeyWith(Passphrase(pass.copyOf()))
        val oldEnc = Pgp.certificateOf(key).publicKeys.asSequence().first { it.isEncryptionKey }.keyID
        // Nova subchave de encriptação e a antiga é "retirada" (revogação suave).
        key = PGPainless.modifyKeyRing(key)
            .addSubKey(
                KeySpec.getBuilder(KeyType.XDH_LEGACY(XDHLegacySpec._X25519), KeyFlag.ENCRYPT_COMMS, KeyFlag.ENCRYPT_STORAGE).build(),
                Passphrase(pass.copyOf()), protector,
            ).done()
        key = PGPainless.modifyKeyRing(key)
            .revokeSubKey(oldEnc, protector, RevocationAttributes.createKeyRevocation().withReason(RevocationAttributes.Reason.KEY_RETIRED).withoutDescription())
            .done()
        assertFalse(PGPainless.inspectKeyRing(key).isKeyValidlyBound(oldEnc))

        val extended = Pgp.extendExpiry(key, pass, years = 3, now = cal(Calendar.YEAR, 1))
        val later = cal(Calendar.YEAR, 3)
        val info = PGPainless.inspectKeyRing(extended, later)
        assertFalse(info.isKeyValidlyBound(oldEnc), "a subchave retirada não pode voltar a ser usada")
        assertTrue(info.isUsableForEncryption)
        assertTrue(info.isUsableForSigning)
    }

    @Test
    fun fullyExpiredKeyCanBeRenewed() {
        val key = Pgp.generate("Ana", "ana@exemplo.pt", pass, validYears = 2)
        // Daqui a 2 anos e meio a chave inteira (primária e subchaves) já expirou.
        val later = cal(Calendar.MONTH, 30)
        assertFalse(Pgp.info(key, later).canEncrypt)
        val renewed = Pgp.extendExpiry(key, pass, years = 2, now = later)
        val after = cal(Calendar.DAY_OF_MONTH, 1, later)
        assertTrue(Pgp.info(renewed, after).canEncrypt)
        assertTrue(Pgp.info(renewed, after).canSign)
    }

    @Test
    fun twoOwnKeysWithDifferentPassphrases() {
        val a = Pgp.generate("A", "a@exemplo.pt", pass)
        val b = Pgp.generate("B", "b@exemplo.pt", pass2)
        val v = Vault(MemoryStore()).apply { addMyKey(a); addMyKey(b) }
        // Mensagem para as duas chaves: cada palavra-passe tem de funcionar.
        val msg = Pgp.encrypt("para as duas", listOf(Pgp.certificateOf(a), Pgp.certificateOf(b)), null, null)
        assertEquals("para as duas", v.decrypt(msg, pass).text)
        assertEquals("para as duas", v.decrypt(msg, pass2).text)
        assertFailsWith<WrongPassphraseError> { v.decrypt(msg, "nenhuma das duas frases".toCharArray()) }
    }

    @Test
    fun hugePlaintextIsRefused() {
        val me = Pgp.generate("Eu", "eu@exemplo.pt", pass)
        val v = vaultWith(me)
        val big = "a".repeat(Pgp.MAX_PLAINTEXT + 1000)
        val msg = Pgp.encrypt(big, listOf(Pgp.certificateOf(me)), null, null)
        val e = assertFailsWith<PgpError> { v.decrypt(msg, pass) }
        assertTrue(e.message!!.contains("grande"))
    }

    @Test
    fun binaryMessageFromFileIsAccepted() {
        val me = Pgp.generate("Eu", "eu@exemplo.pt", pass)
        val v = vaultWith(me)
        val armored = Pgp.encrypt("de um ficheiro .gpg", listOf(Pgp.certificateOf(me)), null, null)
        val binary = org.bouncycastle.bcpg.ArmoredInputStream(armored.byteInputStream()).readBytes()
        assertTrue((binary[0].toInt() and 0x80) != 0)
        assertEquals("de um ficheiro .gpg", v.decrypt(Pgp.ensureArmored(binary), pass).text)
        assertEquals(armored, Pgp.ensureArmored(armored.toByteArray()))
        assertFailsWith<PgpError> { Pgp.ensureArmored("texto normal".toByteArray()) }
    }

    @Test
    fun displayNameRemovesTricks() {
        val rlo = '‮'
        assertEquals("Ana gpj.exe", Pgp.displayName("Ana ${rlo}gpj.exe"))
        assertEquals("Linha1 Linha2", Pgp.displayName("Linha1\n\nLinha2"))
        assertEquals(80, Pgp.displayName("x".repeat(200)).length)
        assertEquals("(sem nome)", Pgp.displayName("\u0000​"))
        assertTrue(Hex.toHexString(byteArrayOf(1)).isNotEmpty())
    }
}
