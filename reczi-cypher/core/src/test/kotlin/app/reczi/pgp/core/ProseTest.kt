package app.reczi.pgp.core

import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Versão 1.4: crónica, diário de viagem, relato de futebol e letra de rap; código secreto em ChaCha20. */
class ProseTest {
    private val pass = "cavalo bateria agrafo correto".toCharArray()

    private fun flatten(text: String) =
        java.text.Normalizer.normalize(text, java.text.Normalizer.Form.NFD).filter { it.code < 128 }.replace("\n", " ").uppercase() + " !!"

    @Test
    fun everyBookRoundTrips() {
        val random = Random(7)
        for (book in Books.all) {
            for (size in listOf(21, 22, 23, 40, 97, 256, 1179)) {
                repeat(6) {
                    val data = random.nextBytes(size)
                    val text = book.write(data, random)
                    val candidates = assertNotNull(book.read(text), "${book.name}: não leu\n$text")
                    assertTrue(candidates.any { it.contentEquals(data) }, "${book.name}: $size bytes não voltaram")
                    // O que as apps de mensagens fazem: sem acentos, tudo numa linha, maiúsculas, pontuação a mais.
                    assertTrue(book.read(flatten(text))!!.any { it.contentEquals(data) }, "${book.name}: não sobrevive a ser achatado")
                }
            }
            // Todos os valores de byte, em todas as posições.
            val every = ByteArray(256 * 4) { (it / 4).toByte() }
            assertTrue(book.read(book.write(every, random))!!.any { it.contentEquals(every) }, book.name)
        }
    }

    @Test
    fun booksAreAStableAlphabet() {
        // As listas e os moldes são o formato: se alguém os mudar, as mensagens antigas deixam de abrir.
        assertEquals(
            listOf(
                "crónica" to "7b5b15df0a0f2293081736a9f898fd443259eb9b579b7b2768502fca40adbe86",
                "viagem" to "36c7484e9d1a1eb4619b55fffbcad2feadc25c7506e436c94254965c73c4c2fe",
                "futebol" to "affa286c452389e3d8fc731ec220aea1b9f3266a753dd1c7a50f578c476cd325",
                "letra" to "29f707c9fd1c437e6e9db0d024099954035f9f386d4117271b4e266e0557fffd",
            ),
            Books.all.map { it.name to it.digest },
        )
    }

    @Test
    fun disguiseWithEveryStyle() {
        val ana = Vault(MemoryStore())
        val rui = Vault(MemoryStore())
        val a = Pgp.generate("Ana", "ana@exemplo.pt", pass).also { ana.addMyKey(it) }
        val r = Pgp.generate("Rui", "rui@exemplo.pt", pass).also { rui.addMyKey(it) }
        ana.importContacts(listOf(Pgp.certificateOf(r)))
        rui.importContacts(listOf(Pgp.certificateOf(a)))
        val ruiFpr = Pgp.fingerprint(r)
        val anaFpr = Pgp.fingerprint(a)
        ana.setVerified(ruiFpr, true)
        rui.setVerified(anaFpr, true)
        val msg = ana.encrypt("às 8 no sítio do costume", listOf(ruiFpr), anaFpr, true, pass)
        ana.setCode(ruiFpr, "o gato comeu a sardinha".toCharArray())
        rui.setCode(anaFpr, "o gato comeu a sardinha".toCharArray())
        for (style in listOf(Disguise.Style.Chronicle, Disguise.Style.Trip, Disguise.Style.Football, Disguise.Style.Lyrics)) {
            val plain = ana.disguise(msg, style)
            assertFalse(plain.contains("PGP", ignoreCase = true))
            assertTrue(plain.none { it.isDigit() }, "sem números: $style")
            assertEquals("às 8 no sítio do costume", rui.decrypt(plain, pass).text)
            assertEquals("às 8 no sítio do costume", rui.decrypt(flatten(plain), pass).text)
            // Com o código secreto: sem a frase não se vê que é PGP; com ela, abre.
            val coded = ana.disguise(msg, style, ruiFpr)
            assertNull(Pgp.undisguise(coded))
            val d = rui.decrypt(coded, pass)
            assertEquals("às 8 no sítio do costume", d.text)
            assertEquals("Ana <ana@exemplo.pt>", d.secretCodeWith)
            assertTrue(Disguise.units(plain, style)!! > 10)
        }
    }

    @Test
    fun secretCodeLayerIsChaCha20AndOldMessagesStillOpen() {
        val secret = Disguise.deriveSecret("o gato comeu a sardinha".toCharArray())
        // Feito com a versão 1.3.1 (AES): tem de continuar a abrir.
        val old = "NINdQxvNP9b68DuXnn_aec5BJYoc6ftuYzgVYD7schINcYxQI-yuRFvPOapbHTk8aV7f6ID8TJ0oJH2Deg"
        val (bytes, i) = assertNotNull(Disguise.revealWith(old, listOf(secret)))
        assertEquals("Reczi cypher: camada do codigo secreto v1", String(bytes))
        assertEquals(0, i)
        assertNull(Disguise.reveal(old))

        // Agora: outra cifra (o mesmo texto com a mesma chave daria outros bytes) e continua a abrir.
        val data = ByteArray(300) { it.toByte() }
        val now = Disguise.hide(data, Disguise.Style.Code, secret)
        val raw = java.util.Base64.getUrlDecoder().decode(now)
        val nonce = raw.copyOf(16)
        val aes = javax.crypto.Cipher.getInstance("AES/CTR/NoPadding").run {
            val enc = javax.crypto.Mac.getInstance("HmacSHA256").run { init(javax.crypto.spec.SecretKeySpec(secret, "HmacSHA256")); doFinal("enc".toByteArray()) }
            init(javax.crypto.Cipher.ENCRYPT_MODE, javax.crypto.spec.SecretKeySpec(enc, "AES"), javax.crypto.spec.IvParameterSpec(nonce))
            doFinal(data)
        }
        assertFalse(aes.contentEquals(raw.copyOfRange(16, raw.size - 4)), "a camada do código secreto já não é AES")
        assertContentEquals(data, Disguise.revealWith(now, listOf(secret))!!.first)
        assertNull(Disguise.reveal(now))
        assertNull(Disguise.revealWith(now, listOf(Disguise.deriveSecret("outra frase qualquer".toCharArray()))))
    }

    @Test
    fun ordinaryTextIsNotMistakenForADisguise() {
        val texts = listOf(
            "Ontem de manhã a tia Rosa foi à praça e comprou pão.",
            "Olá! Tenho tantas novidades para te contar.",
            "Odin no drill, Anúbis na baliza, risco o trovão",
            "Pouco depois, Rui Matos arranca pela esquerda e remata de longe!",
        )
        for (t in texts) {
            assertNull(Disguise.reveal(t), t)
            assertNull(Pgp.undisguise(t), t)
        }
        // Um poema também não é lido como outro formato (nem ao contrário).
        val poem = Poem.write(Random(1).nextBytes(60))
        assertTrue(Books.all.all { it.read(poem) == null })
        val chron = Books.chronicle.write(Random(2).nextBytes(60))
        assertNull(Poem.read(chron))
    }

    /** Mostra um exemplo de cada formato e quanto ocupa uma mensagem real (para a ajuda e para o README). */
    @Test
    fun samplesAndSizes() {
        for (rsa in listOf(false, true)) {
            val ana = Vault(MemoryStore())
            val a = Pgp.generate("Ana", "ana@exemplo.pt", pass, rsa = rsa).also { ana.addMyKey(it) }
            val r = Pgp.generate("Rui", "rui@exemplo.pt", pass, rsa = rsa)
            ana.importContacts(listOf(Pgp.certificateOf(r)))
            ana.setVerified(Pgp.fingerprint(r), true)
            val normal = ana.encrypt("Encontramo-nos amanhã às 8, no sítio do costume.", listOf(Pgp.fingerprint(r)), Pgp.fingerprint(a), true, pass)
            val compact = ana.encrypt("Encontramo-nos amanhã às 8, no sítio do costume.", listOf(Pgp.fingerprint(r)), Pgp.fingerprint(a), false, null, toSelf = false)
            for ((label, m) in listOf("normal" to normal, "compacto" to compact)) {
                val bytes = Pgp.dearmor(m).size
                val line = Disguise.Style.entries.filter { it != Disguise.Style.Code }.joinToString(", ") { s ->
                    val t = ana.disguise(m, s)
                    "$s=${Disguise.units(t, s)} (${Prose.words(t).size} palavras)"
                }
                println("TAMANHO ${if (rsa) "RSA" else "ECC"} $label $bytes bytes: $line")
            }
        }
        val sample = Random(3).nextBytes(60)
        for (b in Books.all) println("----- ${b.name}\n${b.write(sample, Random(4))}\n")
    }
}
