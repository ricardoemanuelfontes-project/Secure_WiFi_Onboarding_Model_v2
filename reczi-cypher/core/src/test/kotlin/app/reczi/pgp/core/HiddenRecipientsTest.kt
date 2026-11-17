package app.reczi.pgp.core

import java.io.ByteArrayOutputStream
import java.io.PrintStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Mensagens disfarçadas sem os ids das chaves: quem tirar a camada de fora (com a app, ou lendo o
 * código) fica a ver PGP, mas não para quem é nem quem o enviou.
 */
class HiddenRecipientsTest {
    private val pass = "cavalo bateria agrafo correto".toCharArray()
    private val pass2 = "outra frase da segunda chave".toCharArray()

    private class Person(val vault: Vault, val fpr: String, val key: org.bouncycastle.openpgp.PGPSecretKeyRing)

    private fun person(name: String, p: CharArray = pass): Person {
        val key = Pgp.generate(name, "${name.lowercase()}@exemplo.pt", p)
        return Person(Vault(MemoryStore()).apply { addMyKey(key) }, Pgp.fingerprint(key), key)
    }

    private fun Vault.knows(other: Person) {
        importContacts(listOf(Pgp.certificateOf(other.key)))
        setVerified(other.fpr, true)
    }

    /** Os 8 bytes de cada id de chave (primária e subchaves). */
    private fun idBytes(key: org.bouncycastle.openpgp.PGPSecretKeyRing): List<ByteArray> =
        Pgp.keyIds(key).map { id -> ByteArray(8) { i -> (id ushr (56 - 8 * i)).toByte() } }

    private fun ByteArray.contains(part: ByteArray): Boolean =
        (0..size - part.size).any { i -> part.indices.all { this[i + it] == part[it] } }

    @Test
    fun disguisedMessageNamesNoKeyButBothSidesOpenIt() {
        val ana = person("Ana")
        val rui = person("Rui")
        ana.vault.knows(rui)
        rui.vault.knows(ana)

        val msg = ana.vault.encrypt("vemo-nos no sítio do costume", listOf(rui.fpr), ana.fpr, true, pass, hideRecipients = true)
        assertEquals(listOf(0L, 0L), Pgp.recipientKeyIds(msg), "para o Rui e a cópia para a Ana, sem ids")
        // Nem os ids de quem recebe nem os de quem assina aparecem nos bytes (a assinatura vai lá dentro).
        val raw = Pgp.dearmor(msg)
        (idBytes(ana.key) + idBytes(rui.key)).forEach { assertFalse(raw.contains(it), "id de chave visível na mensagem") }

        for (style in listOf(Disguise.Style.Code, Disguise.Style.Lyrics2)) {
            val disguised = ana.vault.disguise(msg, style)
            assertTrue(rui.vault.isForMe(disguised))
            val r = rui.vault.decrypt(disguised, pass)
            assertEquals("vemo-nos no sítio do costume", r.text)
            assertEquals(SignatureStatus.Valid(ana.fpr), r.signature)
            assertTrue(r.signerVerified)
            assertEquals("vemo-nos no sítio do costume", ana.vault.decrypt(disguised, pass).text, "quem enviou consegue reler")
        }

        // Modo compacto: um só destinatário, também sem id.
        val compact = ana.vault.encrypt("curta", listOf(rui.fpr), ana.fpr, false, null, toSelf = false, hideRecipients = true)
        assertEquals(listOf(0L), Pgp.recipientKeyIds(compact))
        assertEquals("curta", rui.vault.decrypt(ana.vault.disguise(compact, Disguise.Style.Chronicle), pass).text)
    }

    @Test
    fun normalPgpStillNamesTheKeys() {
        val ana = person("Ana")
        val rui = person("Rui")
        ana.vault.knows(rui)
        val msg = ana.vault.encrypt("normal", listOf(rui.fpr), ana.fpr, false, null)
        val ids = Pgp.recipientKeyIds(msg)
        assertEquals(2, ids.size)
        assertTrue(ids.none { it == 0L }, "o PGP normal pode ir para outras apps: fica como sempre foi")
    }

    @Test
    fun withSeveralKeysTheWrongOneAsksForTheOther() {
        val ana = person("Ana")
        // O Rui tem duas chaves com palavras-passe diferentes; a Ana só conhece a segunda.
        val first = Pgp.generate("Rui", "rui@trabalho.pt", pass)
        val second = Pgp.generate("Rui", "rui@pessoal.pt", pass2)
        val rui = Vault(MemoryStore()).apply { addMyKey(first); addMyKey(second) }
        ana.vault.importContacts(listOf(Pgp.certificateOf(second)))
        ana.vault.setVerified(Pgp.fingerprint(second), true)

        val msg = ana.vault.encrypt("para a segunda", listOf(Pgp.fingerprint(second)), ana.fpr, false, null, hideRecipients = true)
        assertEquals(2, rui.myKeysFor(msg).size, "sem ids, servem todas as chaves")
        val e = assertFailsWith<OtherKeyError> { rui.decrypt(msg, pass) }
        assertTrue("outra chave" in e.message!!)
        assertTrue(e is WrongPassphraseError, "continua a ser um erro de palavra-passe para quem já o tratava")
        assertEquals("para a segunda", rui.decrypt(msg, pass2).text)
    }

    @Test
    fun hiddenMessageForSomeoneElseIsNotForMe() {
        val ana = person("Ana")
        val rui = person("Rui")
        val ze = person("Zé")
        ana.vault.knows(rui)
        val msg = ana.vault.encrypt("não é para o Zé", listOf(rui.fpr), ana.fpr, false, null, hideRecipients = true)
        // A palavra-passe do Zé está certa: dizer "palavra-passe errada" seria enganá-lo.
        val e = assertFailsWith<PgpError> { ze.vault.decrypt(msg, pass) }
        assertFalse(e is WrongPassphraseError, e.message)
        assertTrue("nenhuma das tuas chaves" in e.message!!)
    }

    @Test
    fun undisguiserSaysTheRecipientIsHidden() {
        val ana = person("Ana")
        val rui = person("Rui")
        ana.vault.knows(rui)
        val msg = ana.vault.encrypt("olá", listOf(rui.fpr), ana.fpr, false, null, hideRecipients = true)
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()
        val rc = Desfazer.run(emptyList(), ana.vault.disguise(msg, Disguise.Style.Football).byteInputStream(),
            PrintStream(out, true, "UTF-8"), PrintStream(err, true, "UTF-8"))
        assertEquals(0, rc)
        assertTrue("(destinatário oculto)" in err.toString("UTF-8"), err.toString("UTF-8"))
        assertTrue(rui.fpr.takeLast(16) !in err.toString("UTF-8"))
    }
}
