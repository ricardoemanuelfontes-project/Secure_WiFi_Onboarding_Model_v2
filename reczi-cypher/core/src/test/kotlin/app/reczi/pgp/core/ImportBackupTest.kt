package app.reczi.pgp.core

import org.pgpainless.PGPainless
import org.pgpainless.encryption_signing.EncryptionOptions
import org.pgpainless.encryption_signing.ProducerOptions
import org.pgpainless.util.Passphrase
import java.io.ByteArrayOutputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Versão 1.4.1: importar qualquer tipo de backup pela mesma porta, incluindo os protegidos com código. */
class ImportBackupTest {
    private val pass = "cavalo bateria agrafo correto".toCharArray()

    /** Como o OpenKeychain faz o backup: as chaves em texto, encriptadas só com o código de backup. */
    private fun passwordBackup(inside: ByteArray, code: String): ByteArray {
        val out = ByteArrayOutputStream()
        PGPainless.encryptAndOrSign().onOutputStream(out).withOptions(
            ProducerOptions.encrypt(EncryptionOptions.get().addMessagePassphrase(Passphrase(code.toCharArray()))).setAsciiArmor(true),
        ).use { it.write(inside) }
        return out.toByteArray()
    }

    @Test
    fun backupWithCodeOpensHoweverTheCodeIsWritten() {
        val mine = Pgp.generate("Ana", "ana@exemplo.pt", pass, rsa = true)
        val friend = Pgp.certificateOf(Pgp.generate("Rui", "rui@exemplo.pt", pass))
        val inside = (Pgp.armor(mine) + "\n" + Pgp.armor(Pgp.certificateOf(mine)) + "\n" + Pgp.armor(friend)).toByteArray()
        val code = "1234-5678-9012-3456-7890-1234-5678-9012-3456"
        val backup = passwordBackup(inside, code)

        assertTrue(Pgp.isPasswordEncrypted(backup))
        assertEquals(Pgp.ImportKind.PasswordBackup, Pgp.importKind(backup))
        for (typed in listOf(code, code.replace("-", ""), code.replace("-", " "), " $code ")) {
            val opened = Pgp.openPasswordBackup(backup, typed.toCharArray())
            // Ficam as chaves privadas; os contactos (sem a parte pública da própria chave) vêm à parte.
            assertEquals(listOf(Pgp.fingerprint(mine)), Pgp.parseSecretKeys(opened).map { Pgp.fingerprint(it) })
            assertEquals(listOf(Pgp.fingerprint(friend)), Pgp.parseCertificates(Pgp.otherCertificates(opened)).map { Pgp.fingerprint(it) })
            // E a chave importa-se com a palavra-passe dela, como qualquer outra.
            assertTrue(Pgp.checkPassphrase(Pgp.prepareImported(Pgp.parseSecretKeys(opened).single(), pass), pass))
        }
        assertFailsWith<WrongPassphraseError> { Pgp.openPasswordBackup(backup, "0000-0000-0000".toCharArray()) }

        // Uma frase normal (gpg --symmetric) também serve, escrita tal e qual.
        val gpgStyle = passwordBackup(Pgp.armor(mine).toByteArray(), "a minha frase de backup")
        assertEquals(1, Pgp.parseSecretKeys(Pgp.openPasswordBackup(gpgStyle, "a minha frase de backup".toCharArray())).size)
    }

    @Test
    fun everyKindOfFileIsRecognised() {
        val v = Vault(MemoryStore())
        val k = Pgp.generate("Ana", "ana@exemplo.pt", pass).also { v.addMyKey(it) }
        val fpr = Pgp.fingerprint(k)
        assertEquals(Pgp.ImportKind.PrivateKeys, Pgp.importKind(Pgp.armor(k).toByteArray()))
        assertEquals(Pgp.ImportKind.PrivateKeys, Pgp.importKind(k.encoded))
        assertEquals(Pgp.ImportKind.PublicKeys, Pgp.importKind(Pgp.armor(Pgp.certificateOf(k)).toByteArray()))
        assertEquals(Pgp.ImportKind.FullBackup, Pgp.importKind(v.exportBackup("palavra-passe do backup".toCharArray())))
        assertEquals(Pgp.ImportKind.Unknown, Pgp.importKind("olá, isto não é uma chave".toByteArray()))
        // Uma mensagem encriptada para uma chave não é um backup com palavra-passe.
        val msg = v.encrypt("olá", listOf(fpr), fpr, false, null)
        assertFalse(Pgp.isPasswordEncrypted(msg.toByteArray()))
        assertFalse(Pgp.isPasswordEncrypted(Pgp.dearmor(msg)))
        // Uma chave privada e a pública dela no mesmo ficheiro (exportação de alguns programas).
        val both = (Pgp.armor(Pgp.certificateOf(k)) + "\n" + Pgp.armor(k)).toByteArray()
        assertEquals(listOf(fpr), Pgp.parseSecretKeys(both).map { Pgp.fingerprint(it) })
        assertEquals(0, Pgp.otherCertificates(both).size)
    }
}
