package app.reczi.pgp.core

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.PrintStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Versão 1.4.4: o desfazedor de disfarce para o computador. */
class DesfazerTest {
    private val pass = "cavalo bateria agrafo correto".toCharArray()

    private fun run(text: String, code: CharArray? = null, args: List<String> = emptyList()): Triple<Int, String, String> {
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()
        val rc = Desfazer.run(args, ByteArrayInputStream(text.toByteArray()), PrintStream(out, true, "UTF-8"), PrintStream(err, true, "UTF-8"), code)
        return Triple(rc, out.toString("UTF-8"), err.toString("UTF-8"))
    }

    @Test
    fun showsThePgpUnderTheDisguise() {
        val ana = Vault(MemoryStore())
        val a = Pgp.generate("Ana", "ana@exemplo.pt", pass).also { ana.addMyKey(it) }
        val r = Pgp.generate("Rui", "rui@exemplo.pt", pass)
        val ruiFpr = Pgp.fingerprint(r)
        ana.importContacts(listOf(Pgp.certificateOf(r)))
        ana.setVerified(ruiFpr, true)
        val msg = ana.encrypt("olá", listOf(ruiFpr), Pgp.fingerprint(a), true, pass)

        for (style in Disguise.Style.entries.filter { it != Disguise.Style.Words }) {
            val (rc, out, err) = run(ana.disguise(msg, style))
            assertEquals(0, rc, "$style: $err")
            assertTrue(out.startsWith("-----BEGIN PGP MESSAGE-----"), "$style")
            // O que sai é a mesma mensagem: abre com a chave do Rui.
            val rui = Vault(MemoryStore()).also { it.addMyKey(r) }
            assertEquals("olá", rui.decrypt(out, pass).text)
            assertTrue(err.contains("%016X".format(Pgp.keyIds(Pgp.certificateOf(r)).last())) || err.contains("Para as chaves"), err)
        }

        // Com código secreto: sem a frase não abre; com ela (e as duas impressões digitais), abre.
        ana.setCode(ruiFpr, "o gato comeu a sardinha".toCharArray())
        val coded = ana.disguise(msg, Disguise.Style.Lyrics2, ruiFpr)
        val both = listOf("--chaves", Pgp.fingerprint(a), ruiFpr)
        assertEquals(1, run(coded).first)
        assertEquals(1, run(coded, "outra frase qualquer".toCharArray(), both).first)
        val (rc, out) = run(coded, "o gato comeu a sardinha".toCharArray(), both)
        assertEquals(0, rc)
        assertTrue(out.startsWith("-----BEGIN PGP MESSAGE-----"))
    }

    @Test
    fun ordinaryTextIsRefused() {
        assertEquals(1, run("Olá, tudo bem? Até logo.").first)
        assertEquals(1, run("").first)
    }
}
