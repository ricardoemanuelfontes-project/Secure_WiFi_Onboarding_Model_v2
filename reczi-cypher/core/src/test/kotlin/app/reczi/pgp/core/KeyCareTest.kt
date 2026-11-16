package app.reczi.pgp.core

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/** Versão 1.3: mudar a palavra-passe, revogar, assinaturas à parte e sem cabeçalho "Version". */
class KeyCareTest {
    private val pass = "cavalo bateria agrafo correto".toCharArray()
    private val newPass = "outra frase bem comprida".toCharArray()

    private fun vaultWithKey(name: String, rsa: Boolean = false): Pair<Vault, String> {
        val v = Vault(MemoryStore())
        val key = Pgp.generate(name, "${name.lowercase()}@exemplo.pt", pass, rsa = rsa)
        v.addMyKey(key)
        return v to Pgp.fingerprint(key)
    }

    @Test
    fun noVersionHeaderAnywhere() {
        val (v, fpr) = vaultWithKey("Ana")
        val signed = v.sign("olá", fpr, pass)
        val encrypted = v.encrypt("olá", listOf(fpr), fpr, true, pass)
        val pub = Pgp.armor(Pgp.certificateOf(v.myKey(fpr)))
        val sig = v.signDetached("dados".byteInputStream(), fpr, pass)
        for (text in listOf(signed, encrypted, pub, sig)) assertFalse("Version:" in text, text)
        // E continua a verificar.
        assertIs<SignatureStatus.Valid>(v.verify(signed).signature)
    }

    @Test
    fun changePassphrase() {
        val (v, fpr) = vaultWithKey("Ana")
        val msg = v.encrypt("segredo", listOf(fpr), fpr, false, null)
        assertFailsWith<WrongPassphraseError> { v.changePassphrase(fpr, "errada errada errada".toCharArray(), newPass) }
        assertFailsWith<PgpError> { v.changePassphrase(fpr, pass, "curta".toCharArray()) }
        v.changePassphrase(fpr, pass, newPass)
        assertEquals("segredo", v.decrypt(msg, newPass).text)
        assertFailsWith<WrongPassphraseError> { v.decrypt(msg, pass) }
        assertTrue(Pgp.checkPassphrase(v.myKey(fpr), newPass))
    }

    @Test
    fun revocationCertificateRevokesWhenImported() {
        val (ana, anaFpr) = vaultWithKey("Ana")
        val (rui, _) = vaultWithKey("Rui")
        rui.importContacts(listOf(Pgp.certificateOf(ana.myKey(anaFpr))))
        rui.setVerified(anaFpr, true)

        val cert = ana.revocationCertificate(anaFpr, pass)
        assertTrue("BEGIN PGP PUBLIC KEY BLOCK" in cert)
        assertFalse("Version:" in cert)
        // Criar o certificado não revoga a chave.
        assertFalse(ana.snapshot().myKeys.single().info.revoked)
        assertFailsWith<WrongPassphraseError> { ana.revocationCertificate(anaFpr, newPass) }

        // Quando o Rui o importa, a chave da Ana fica revogada e já não se encripta para ela.
        rui.importContacts(Pgp.parseCertificates(cert.toByteArray()))
        val c = rui.snapshot().contacts.single { it.info.fingerprint == anaFpr }
        assertTrue(c.info.revoked)
        assertFalse(c.info.canEncrypt)
    }

    @Test
    fun revokeOwnKey() {
        for (rsa in listOf(false, true)) {
            val (v, fpr) = vaultWithKey("Ana", rsa)
            val old = v.encrypt("antes", listOf(fpr), fpr, false, null)
            val pub = v.revoke(fpr, pass, Pgp.RevokeReason.Compromised)
            val info = v.snapshot().myKeys.single().info
            assertTrue(info.revoked)
            assertFalse(info.canSign)
            assertFalse(Pgp.info(Pgp.parseCertificates(pub.toByteArray()).single()).canEncrypt)
            // Já não assina, mas as mensagens antigas continuam a abrir.
            assertFailsWith<PgpError> { v.sign("depois", fpr, pass) }
            assertEquals("antes", v.decrypt(old, pass).text)
        }
    }

    @Test
    fun detachedSignatures() {
        val (ana, anaFpr) = vaultWithKey("Ana")
        val (rui, _) = vaultWithKey("Rui")
        val data = ByteArray(300_000) { (it * 31).toByte() }
        val sig = ana.signDetached(data.inputStream(), anaFpr, pass)
        assertTrue(sig.startsWith("-----BEGIN PGP SIGNATURE-----"))
        assertFailsWith<WrongPassphraseError> { ana.signDetached(data.inputStream(), anaFpr, newPass) }

        // A própria Ana: válida e dela.
        val own = ana.verifyDetached({ data.inputStream() }, sig.toByteArray())
        assertIs<SignatureStatus.Valid>(own.signature)
        assertTrue(own.signerVerified)

        // O Rui sem a chave da Ana: não sabe de quem é.
        assertEquals(SignatureStatus.UnknownSigner, rui.verifyDetached({ data.inputStream() }, sig.toByteArray()).signature)
        rui.importContacts(listOf(Pgp.certificateOf(ana.myKey(anaFpr))))
        val r = rui.verifyDetached({ data.inputStream() }, sig.toByteArray())
        assertIs<SignatureStatus.Valid>(r.signature)
        assertEquals("Ana <ana@exemplo.pt>", r.signerName)
        assertFalse(r.signerVerified) // ainda não verificou a impressão digital

        // Ficheiro alterado num só byte: inválida.
        val changed = data.copyOf().also { it[1234] = (it[1234] + 1).toByte() }
        assertEquals(SignatureStatus.Invalid, rui.verifyDetached({ changed.inputStream() }, sig.toByteArray()).signature)

        // Assinatura em binário (.sig) também serve.
        val binary = Pgp.dearmor(sig)
        assertIs<SignatureStatus.Valid>(rui.verifyDetached({ data.inputStream() }, binary).signature)

        // Uma mensagem encriptada não é uma assinatura.
        val notSig = ana.encrypt("x", listOf(anaFpr), anaFpr, false, null)
        assertFailsWith<PgpError> { rui.verifyDetached({ data.inputStream() }, notSig.toByteArray()) }
    }

    @Test
    fun whichOfMyKeysAMessageIsFor() {
        val v = Vault(MemoryStore())
        val a = Pgp.generate("Ana", "ana@exemplo.pt", pass).also { v.addMyKey(it) }
        val b = Pgp.generate("Ana trabalho", "ana@trabalho.pt", newPass).also { v.addMyKey(it) }
        val fa = Pgp.fingerprint(a)
        val fb = Pgp.fingerprint(b)
        val toB = v.encrypt("só b", listOf(fb), fb, false, null, toSelf = false)
        assertEquals(listOf(fb), v.myKeysFor(toB))
        val toBoth = v.encrypt("ambas", listOf(fa, fb), fa, false, null)
        assertEquals(setOf(fa, fb), v.myKeysFor(toBoth).toSet())
        // Disfarçada também.
        assertEquals(listOf(fb), v.myKeysFor(v.disguise(toB, Disguise.Style.Poem)))
    }
}

class RevokeKeepsSubkeysTest {
    @Test
    fun revokedKeyKeepsItsSubkeys() {
        val pass = "cavalo bateria agrafo correto".toCharArray()
        val k = Pgp.generate("Ana", "ana@exemplo.pt", pass)
        val r = Pgp.revoke(k, pass, Pgp.RevokeReason.Retired)
        assertEquals(Pgp.keyIds(k), Pgp.keyIds(r))
        assertEquals(k.secretKeys.asSequence().count(), r.secretKeys.asSequence().count())
        assertTrue(Pgp.checkPassphrase(r, pass))
    }
}
