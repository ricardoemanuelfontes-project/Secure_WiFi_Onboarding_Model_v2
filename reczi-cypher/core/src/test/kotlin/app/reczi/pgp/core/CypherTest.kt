package app.reczi.pgp.core

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Novidades do Reczi cypher: encriptar só para ti e o modo disfarçado. */
class CypherTest {
    private val pass = "cavalo bateria agrafo correto".toCharArray()

    private fun vaultWithKey(name: String, email: String): Pair<Vault, String> {
        val v = Vault(MemoryStore())
        val key = Pgp.generate(name, email, pass)
        v.addMyKey(key)
        return v to Pgp.fingerprint(key)
    }

    @Test
    fun canEncryptOnlyToMyself() {
        val (v, me) = vaultWithKey("Ana", "ana@exemplo.pt")
        val msg = v.encrypt("nota só para mim", listOf(me), me, true, pass)
        assertEquals(1, Pgp.recipientKeyIds(msg).size, "a própria chave não deve aparecer duas vezes")
        val r = v.decrypt(msg, pass)
        assertEquals("nota só para mim", r.text)
        assertTrue(r.signerVerified)
    }

    @Test
    fun canEncryptToAnotherOfMyKeys() {
        val v = Vault(MemoryStore())
        val a = Pgp.generate("Ana trabalho", "ana@trabalho.pt", pass).also { v.addMyKey(it) }
        val b = Pgp.generate("Ana pessoal", "ana@pessoal.pt", pass).also { v.addMyKey(it) }
        val msg = v.encrypt("entre as minhas chaves", listOf(Pgp.fingerprint(b)), Pgp.fingerprint(a), false, null)
        assertEquals(2, Pgp.recipientKeyIds(msg).size)
        val onlyB = Vault(MemoryStore()).apply { addMyKey(b) }
        assertEquals("entre as minhas chaves", onlyB.decrypt(msg, pass).text)
    }

    @Test
    fun noRecipientsIsStillAnError() {
        val (v, me) = vaultWithKey("Ana", "ana@exemplo.pt")
        assertFailsWith<PgpError> { v.encrypt("x", emptyList(), me, false, null) }
    }

    @Test
    fun disguisedMessageHidesEverySignOfPgpAndStillDecrypts() {
        val (ana, anaFpr) = vaultWithKey("Ana", "ana@exemplo.pt")
        val (rui, ruiFpr) = vaultWithKey("Rui", "rui@exemplo.pt")
        ana.importContacts(listOf(Pgp.certificateOf(rui.myKey(ruiFpr))))
        ana.setVerified(ruiFpr, true)
        rui.importContacts(listOf(Pgp.certificateOf(ana.myKey(anaFpr))))
        rui.setVerified(anaFpr, true)

        val armored = ana.encrypt("encontramo-nos às 8", listOf(ruiFpr), anaFpr, true, pass)
        val hidden = Pgp.disguise(armored)

        assertFalse(hidden.contains("PGP"))
        assertFalse(hidden.contains("-----"))
        assertFalse(hidden.contains('\n'))
        assertTrue(hidden.all { it.isLetterOrDigit() || it == '-' || it == '_' })
        // Os ids das chaves dos destinatários não aparecem nos bytes.
        val raw = java.util.Base64.getUrlDecoder().decode(hidden)
        Pgp.recipientKeyIds(armored).forEach { id ->
            val idBytes = java.nio.ByteBuffer.allocate(8).putLong(id).array()
            assertFalse(raw.toList().windowed(8).any { it == idBytes.toList() })
        }
        // Cada disfarce é diferente, mesmo da mesma mensagem.
        assertNotEquals(hidden, Pgp.disguise(armored))

        assertTrue(rui.isForMe(hidden))
        val r = rui.decrypt(hidden, pass)
        assertEquals("encontramo-nos às 8", r.text)
        assertTrue(r.signerVerified)
        // E com espaços/quebras de linha que a app de mensagens tenha metido pelo meio.
        assertEquals("encontramo-nos às 8", rui.decrypt(hidden.chunked(30).joinToString("\n "), pass).text)
    }

    @Test
    fun disguisedPublicKeyImports() {
        val key = Pgp.generate("Ana", "ana@exemplo.pt", pass)
        val hidden = Pgp.disguise(Pgp.armor(Pgp.certificateOf(key)))
        assertFalse(hidden.contains("PGP"))
        val back = Pgp.undisguise(hidden)!!
        assertTrue(back.startsWith("-----BEGIN PGP PUBLIC KEY BLOCK-----"))
        val certs = Pgp.parseCertificates(back.toByteArray())
        assertEquals(Pgp.fingerprint(key), Pgp.fingerprint(certs.single()))
    }

    @Test
    fun disguiseAsWordsRoundTrips() {
        assertEquals(256, Disguise.WORDS.toSet().size)
        val (v, me) = vaultWithKey("Ana", "ana@exemplo.pt")
        val hidden = Pgp.disguise(v.encrypt("em palavras", listOf(me), me, true, pass), words = true)
        assertTrue(hidden.all { it in 'a'..'z' || it == ' ' })
        assertEquals("em palavras", v.decrypt(hidden, pass).text)
        // Sobrevive a maiúsculas, pontuação e quebras de linha postas pelo caminho.
        val mangled = hidden.split(" ").chunked(9).joinToString(".\n") { it.joinToString(" ").replaceFirstChar(Char::uppercase) }
        assertEquals("em palavras", v.decrypt(mangled, pass).text)
        assertNull(Pgp.undisguise("casa mesa porta janela rua ponte rio mar sol lua ceu nuvem chuva vento neve fogo agua terra pedra areia monte vale"))
    }

    @Test
    fun ordinaryTextIsNotMistakenForDisguise() {
        assertNull(Pgp.undisguise("Olá, tudo bem? Amanhã às 8 no sítio do costume."))
        assertNull(Pgp.undisguise("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"))
        assertNull(Pgp.undisguise("-----BEGIN PGP MESSAGE-----\n\nabc\n-----END PGP MESSAGE-----"))
        assertNull(Pgp.undisguise(""))
    }

    @Test
    fun damagedDisguiseIsRejected() {
        val key = Pgp.generate("Ana", "ana@exemplo.pt", pass)
        val hidden = Pgp.disguise(Pgp.encrypt("x", listOf(Pgp.certificateOf(key)), null, null))
        assertNull(Pgp.undisguise(hidden.dropLast(3)))
        val flipped = hidden.substring(0, 40) + (if (hidden[40] == 'A') 'B' else 'A') + hidden.substring(41)
        assertNull(Pgp.undisguise(flipped))
    }

    /** Ana e Rui conhecem-se e verificaram as chaves um do outro. */
    private fun pair(): List<Pair<Vault, String>> {
        val ana = vaultWithKey("Ana", "ana@exemplo.pt")
        val rui = vaultWithKey("Rui", "rui@exemplo.pt")
        ana.first.importContacts(listOf(Pgp.certificateOf(rui.first.myKey(rui.second))))
        ana.first.setVerified(rui.second, true)
        rui.first.importContacts(listOf(Pgp.certificateOf(ana.first.myKey(ana.second))))
        rui.first.setVerified(ana.second, true)
        return listOf(ana, rui)
    }

    @Test
    fun secretCodeLayerNeedsTheSameCodeOnBothSides() {
        val (a, r) = pair()
        val (ana, anaFpr) = a
        val (rui, ruiFpr) = r
        val check = ana.setCode(ruiFpr, "o gato comeu a sardinha".toCharArray())
        assertEquals(check, ana.contacts().single().codeCheck)
        val armored = ana.encrypt("só nós dois", listOf(ruiFpr), anaFpr, true, pass)

        for (words in listOf(false, true)) {
            val hidden = ana.disguise(armored, words, ruiFpr)
            // Sem o código, nem a app (chave fixa) consegue ver que é PGP.
            assertNull(Pgp.undisguise(hidden))
            assertNull(rui.reveal(hidden))
            val e = assertFailsWith<PgpError> { rui.decrypt(hidden, pass) }
            assertTrue(e.message!!.contains("código secreto"))

            // Código errado: continua fechado.
            rui.setCode(anaFpr, "o gato comeu a sardinha!".toCharArray())
            assertNull(rui.reveal(hidden))

            // Código certo (espaços à volta não contam): abre, e diz com quem é o código.
            assertEquals(check, rui.setCode(anaFpr, "  o gato comeu a sardinha ".toCharArray()))
            assertEquals(anaFpr, rui.reveal(hidden)!!.codeFpr)
            val d = rui.decrypt(hidden, pass)
            assertEquals("só nós dois", d.text)
            assertEquals("Ana <ana@exemplo.pt>", d.secretCodeWith)
            assertTrue(d.signerVerified)
            // A própria Ana também consegue reler.
            assertEquals("só nós dois", ana.decrypt(hidden, pass).text)
            rui.clearCode(anaFpr)
        }
    }

    @Test
    fun secretCodeIsOptionalAndGoesAwayWithTheContact() {
        val (a, r) = pair()
        val (ana, anaFpr) = a
        val (rui, ruiFpr) = r
        ana.setCode(ruiFpr, "o gato comeu a sardinha".toCharArray())
        rui.setCode(anaFpr, "o gato comeu a sardinha".toCharArray())
        val armored = ana.encrypt("sem código", listOf(ruiFpr), anaFpr, false, null)
        // Mesmo com código combinado, as mensagens normais e as disfarçadas sem código continuam a abrir.
        assertEquals("sem código", rui.decrypt(armored, pass).text)
        val plainDisguise = rui.decrypt(ana.disguise(armored, false), pass)
        assertEquals("sem código", plainDisguise.text)
        assertNull(plainDisguise.secretCodeWith)

        assertFailsWith<PgpError> { ana.setCode(ruiFpr, "curto".toCharArray()) }
        assertFailsWith<PgpError> { ana.setCode("0".repeat(40), "frase comprida que chegue".toCharArray()) }

        ana.clearCode(ruiFpr)
        assertNull(ana.contacts().single().codeCheck)
        assertFailsWith<PgpError> { ana.disguise(armored, false, ruiFpr) }

        rui.deleteContact(anaFpr)
        rui.importContacts(listOf(Pgp.certificateOf(ana.myKey(anaFpr))))
        assertNull(rui.contacts().single().codeCheck, "apagar o contacto apaga o código")
    }
}
