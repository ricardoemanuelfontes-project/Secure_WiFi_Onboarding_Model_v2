package app.reczi.pgp.core

import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import java.util.Calendar
import java.util.Date
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class PgpTest {
    private val pass = "cavalo bateria agrafo correto".toCharArray()

    private fun vaultWithKey(name: String, email: String): Pair<Vault, String> {
        val v = Vault(MemoryStore())
        val key = Pgp.generate(name, email, pass)
        v.addMyKey(key)
        return v to Pgp.fingerprint(key)
    }

    private fun introduce(from: Vault, fromFpr: String, to: Vault) {
        val armored = Pgp.armor(Pgp.certificateOf(from.myKey(fromFpr)))
        val added = to.importContacts(Pgp.parseCertificates(armored.toByteArray())).added
        assertEquals(listOf(fromFpr), added)
        to.setVerified(fromFpr, true)
    }

    @Test
    fun generatedKeyIsModernAndStronglyProtected() {
        val key = Pgp.generate("Ana Lima", "ana@exemplo.pt", pass)
        val info = Pgp.info(key)
        assertEquals("Ana Lima <ana@exemplo.pt>", info.userId)
        assertTrue(info.canEncrypt)
        assertTrue(info.canSign)
        assertFalse(info.revoked)
        val years = (info.expires!!.time - info.created.time) / (365.2 * 24 * 3600 * 1000)
        assertTrue(years in 1.9..2.1, "validade de ~2 anos, foi $years")
        assertEquals(3, key.secretKeys.asSequence().count())
        for (sk in key.secretKeys) {
            assertEquals(SymmetricKeyAlgorithmTags.AES_256, sk.keyEncryptionAlgorithm)
            assertEquals(HashAlgorithmTags.SHA512, sk.s2K.hashAlgorithm)
            assertEquals(65011712L, sk.s2K.iterationCount)
        }
        assertTrue(Pgp.checkPassphrase(key, pass))
        assertFalse(Pgp.checkPassphrase(key, "errada errada errada".toCharArray()))
    }

    @Test
    fun rejectsWeakPassphraseAndBadInput() {
        assertFailsWith<PgpError> { Pgp.generate("Ana", "ana@exemplo.pt", "curta".toCharArray()) }
        assertFailsWith<PgpError> { Pgp.generate("Ana", "sem-arroba", pass) }
        assertFailsWith<PgpError> { Pgp.generate("Ana <x>", "ana@exemplo.pt", pass) }
        assertFailsWith<PgpError> { Pgp.parseCertificates("isto não é uma chave".toByteArray()) }
        val secret = Pgp.armor(Pgp.generate("Ana", "ana@exemplo.pt", pass))
        assertFailsWith<PgpError> { Pgp.parseCertificates(secret.toByteArray()) }
    }

    @Test
    fun encryptDecryptBetweenTwoPeople() {
        val (ana, anaFpr) = vaultWithKey("Ana", "ana@exemplo.pt")
        val (rui, ruiFpr) = vaultWithKey("Rui", "rui@exemplo.pt")

        // Antes de importar e verificar, não é possível encriptar.
        assertFailsWith<PgpError> { ana.encrypt("olá", listOf(ruiFpr), anaFpr, true, pass) }
        ana.importContacts(Pgp.parseCertificates(Pgp.armor(Pgp.certificateOf(rui.myKey(ruiFpr))).toByteArray()))
        val e = assertFailsWith<PgpError> { ana.encrypt("olá", listOf(ruiFpr), anaFpr, true, pass) }
        assertTrue(e.message!!.contains("verificaste"))
        ana.setVerified(ruiFpr, true)

        val text = "Olá Rui, ção ñ 😀\nsegunda linha"
        val msg = ana.encrypt(text, listOf(ruiFpr), anaFpr, true, pass)
        assertTrue(msg.startsWith("-----BEGIN PGP MESSAGE-----"))
        assertFalse(msg.contains("Olá"))

        // O Rui ainda não tem a chave da Ana: desencripta, mas não sabe quem assinou.
        val r1 = rui.decrypt(msg, pass)
        assertEquals(text, r1.text)
        assertEquals(SignatureStatus.UnknownSigner, r1.signature)
        assertFalse(r1.signerVerified)

        // Com a chave da Ana importada mas não verificada: assinatura válida, remetente por confirmar.
        rui.importContacts(Pgp.parseCertificates(Pgp.armor(Pgp.certificateOf(ana.myKey(anaFpr))).toByteArray()))
        val r2 = rui.decrypt(msg, pass)
        assertEquals(SignatureStatus.Valid(anaFpr), r2.signature)
        assertEquals("Ana <ana@exemplo.pt>", r2.signerName)
        assertFalse(r2.signerVerified)

        rui.setVerified(anaFpr, true)
        assertTrue(rui.decrypt(msg, pass).signerVerified)

        // A Ana consegue reler o que enviou.
        assertEquals(text, ana.decrypt(msg, pass).text)

        // Sem assinatura.
        val unsigned = ana.encrypt("sem assinatura", listOf(ruiFpr), anaFpr, false, null)
        assertEquals(SignatureStatus.None, rui.decrypt(unsigned, pass).signature)
    }

    @Test
    fun failureCases() {
        val (ana, anaFpr) = vaultWithKey("Ana", "ana@exemplo.pt")
        val (rui, ruiFpr) = vaultWithKey("Rui", "rui@exemplo.pt")
        val (eva, _) = vaultWithKey("Eva", "eva@exemplo.pt")
        introduce(rui, ruiFpr, ana)
        val msg = ana.encrypt("segredo", listOf(ruiFpr), anaFpr, true, pass)

        assertFailsWith<WrongPassphraseError> { rui.decrypt(msg, "palavra-passe errada".toCharArray()) }
        assertFailsWith<WrongPassphraseError> { ana.encrypt("x", listOf(ruiFpr), anaFpr, true, "palavra-passe errada".toCharArray()) }

        val notForMe = assertFailsWith<PgpError> { eva.decrypt(msg, pass) }
        assertTrue(notForMe.message!!.contains("não foi encriptada"))

        // Alterar um carácter do corpo da mensagem tem de ser detetado.
        val lines = msg.lines().toMutableList()
        val i = lines.indexOfFirst { it.length > 40 }
        val c = lines[i][10]
        lines[i] = lines[i].substring(0, 10) + (if (c == 'A') 'B' else 'A') + lines[i].substring(11)
        assertFailsWith<PgpError> { rui.decrypt(lines.joinToString("\n"), pass) }

        assertFailsWith<PgpError> { rui.decrypt("lixo", pass) }
    }

    @Test
    fun importingUnprotectedKeyRequiresNewPassphrase() {
        val key = Pgp.generate("Ana", "ana@exemplo.pt", pass)
        val unprotected = org.pgpainless.PGPainless.modifyKeyRing(key)
            .changePassphraseFromOldPassphrase(org.pgpainless.util.Passphrase(pass.copyOf()))
            .withSecureDefaultSettings().toNoPassphrase().done()
        assertFalse(Pgp.isProtected(unprotected))
        assertFailsWith<PgpError> { Vault(MemoryStore()).addMyKey(unprotected) }
        assertFailsWith<PgpError> { Pgp.prepareImported(unprotected, "curta".toCharArray()) }
        val fixed = Pgp.prepareImported(unprotected, pass)
        assertTrue(Pgp.isProtected(fixed))
        assertTrue(Pgp.checkPassphrase(fixed, pass))
        assertFailsWith<WrongPassphraseError> { Pgp.prepareImported(key, "palavra-passe errada".toCharArray()) }
    }

    @Test
    fun extendExpiryKeepsKeyUsable() {
        val now = Date()
        val key = Pgp.generate("Ana", "ana@exemplo.pt", pass, validYears = 2, now = now)
        val in3y = Calendar.getInstance().apply { add(Calendar.YEAR, 3) }.time
        assertFalse(Pgp.info(key, in3y).canEncrypt)
        val in1y = Calendar.getInstance().apply { add(Calendar.YEAR, 1) }.time
        val extended = Pgp.extendExpiry(key, pass, years = 3, now = in1y)
        assertTrue(Pgp.info(extended, in3y).canEncrypt)
        assertTrue(Pgp.info(extended, in3y).canSign)
        assertTrue(Pgp.checkPassphrase(extended, pass))
    }

    @Test
    fun updatingContactMergesAndKeepsVerification() {
        val (ana, anaFpr) = vaultWithKey("Ana", "ana@exemplo.pt")
        val (rui, ruiFpr) = vaultWithKey("Rui", "rui@exemplo.pt")
        introduce(rui, ruiFpr, ana)
        val in1y = Calendar.getInstance().apply { add(Calendar.YEAR, 1) }.time
        val renewed = Pgp.extendExpiry(rui.myKey(ruiFpr), pass, years = 3, now = in1y)
        assertEquals(emptyList(), ana.importContacts(listOf(Pgp.certificateOf(renewed))).added)
        val c = ana.contacts().single()
        assertTrue(c.verified)
        val in3y = Calendar.getInstance().apply { add(Calendar.YEAR, 3) }.time
        assertTrue(Pgp.info(c.cert, in3y).canEncrypt)
        // As próprias chaves não entram como destinatários.
        assertEquals(emptyList(), ana.importContacts(listOf(Pgp.certificateOf(ana.myKey(anaFpr)))).added)
    }
}
