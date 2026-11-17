package app.reczi.pgp.core

import org.bouncycastle.openpgp.PGPSecretKeyRing
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.PrintStream
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * 1.4.6: o sal do código secreto passa a levar as impressões digitais das duas chaves. Uma tabela
 * de frases comuns preparada uma vez deixa de servir contra toda a gente: cada par tem a sua.
 */
class PairCodeTest {
    private val pass = "cavalo bateria agrafo correto".toCharArray()
    private val phrase = "o gato comeu a sardinha"
    private fun phrase() = phrase.toCharArray()

    private class Side(val vault: Vault, val fpr: String, val key: PGPSecretKeyRing, val store: MemoryStore)

    private fun side(name: String): Side {
        val store = MemoryStore()
        val key = Pgp.generate(name, "${name.lowercase()}@exemplo.pt", pass)
        return Side(Vault(store).apply { addMyKey(key) }, Pgp.fingerprint(key), key, store)
    }

    private fun knowEachOther(a: Side, b: Side) {
        a.vault.importContacts(listOf(Pgp.certificateOf(b.key)))
        a.vault.setVerified(b.fpr, true)
        b.vault.importContacts(listOf(Pgp.certificateOf(a.key)))
        b.vault.setVerified(a.fpr, true)
    }

    @Test
    fun saltIsThePairOfFingerprints() {
        val a = "0123456789ABCDEF0123456789ABCDEF01234567"
        val b = "89ABCDEF0123456789ABCDEF0123456789ABCDEF"
        val c = "FEDCBA9876543210FEDCBA9876543210FEDCBA98"
        val ab = Disguise.deriveSecret(phrase(), a, b)
        assertContentEquals(ab, Disguise.deriveSecret(phrase(), b, a), "a ordem das duas não conta")
        assertContentEquals(ab, Disguise.deriveSecret(phrase(), a.lowercase().chunked(4).joinToString(" "), b), "espaços e minúsculas não contam")
        assertFalse(ab.contentEquals(Disguise.deriveSecret(phrase(), a, c)), "outro par, outra chave")
        assertFalse(ab.contentEquals(Disguise.deriveSecret(phrase())), "já não é o sal fixo")
        assertFailsWith<PgpError> { Disguise.deriveSecret(phrase(), "isto não é uma impressão digital", b) }
        assertFailsWith<PgpError> { Disguise.deriveSecret("curta".toCharArray(), a, b) }
    }

    @Test
    fun bothSidesSeeTheSameDigitsAndAnOldAppCannotOpen() {
        val ana = side("Ana")
        val rui = side("Rui")
        knowEachOther(ana, rui)
        val ca = ana.vault.setCode(rui.fpr, phrase())
        val cr = rui.vault.setCode(ana.fpr, phrase())
        assertEquals(ca.digits.values.single(), cr.digits.values.single(), "os dois telemóveis mostram o mesmo")
        assertEquals(ca.digits.values.single(), ana.vault.contacts().single().codeCheck)
        // Uma app antiga mostraria outros algarismos: é assim que se dá pela diferença ao combinar.
        assertEquals(Disguise.checkDigits(Disguise.deriveSecret(phrase())), ca.oldDigits)
        assertNotEquals(ca.digits.values.single(), ca.oldDigits)
        assertFalse(ana.vault.contacts().single().codeIsOld)

        val msg = ana.vault.encrypt("só nós dois", listOf(rui.fpr), ana.fpr, true, pass, hideRecipients = true)
        val coded = ana.vault.disguise(msg, Disguise.Style.Lyrics2, rui.fpr, ana.fpr)
        assertNull(Pgp.undisguise(coded))
        assertNull(Disguise.revealWith(coded, listOf(Disguise.deriveSecret(phrase()))), "com o sal fixo já não abre")
        val d = rui.vault.decrypt(coded, pass)
        assertEquals("só nós dois", d.text)
        assertEquals("Ana <ana@exemplo.pt>", d.secretCodeWith)
        assertFalse(d.oldSecretCode)
        assertTrue(d.signerVerified)
        assertEquals("só nós dois", ana.vault.decrypt(coded, pass).text, "quem envia consegue reler")
    }

    @Test
    fun codesCombinedBeforeKeepWorkingUntilCombinedAgain() {
        val ana = side("Ana")
        val rui = side("Rui")
        knowEachOther(ana, rui)
        // Até à 1.4.5 guardava-se só a chave do sal fixo, com este nome.
        val v1 = Disguise.deriveSecret(phrase())
        ana.store.write("code-${rui.fpr}", v1)
        rui.store.write("code-${ana.fpr}", v1)
        assertTrue(ana.vault.contacts().single().codeIsOld)
        assertEquals(Disguise.checkDigits(v1), ana.vault.contacts().single().codeCheck)

        val msg = ana.vault.encrypt("ainda com o antigo", listOf(rui.fpr), ana.fpr, false, null, hideRecipients = true)
        val before = ana.vault.disguise(msg, Disguise.Style.Code, rui.fpr, ana.fpr)
        assertNotNull(Disguise.revealWith(before, listOf(v1)), "sem combinar de novo, continua a versão antiga")
        val d = rui.vault.decrypt(before, pass)
        assertEquals("ainda com o antigo", d.text)
        assertTrue(d.oldSecretCode)

        // Combinam de novo, com a mesma frase: passa a versão 2 e o que veio antes continua a abrir.
        ana.vault.setCode(rui.fpr, phrase())
        rui.vault.setCode(ana.fpr, phrase())
        assertFalse(rui.vault.contacts().single().codeIsOld)
        assertEquals("ainda com o antigo", rui.vault.decrypt(before, pass).text)
        val after = ana.vault.disguise(msg, Disguise.Style.Code, rui.fpr, ana.fpr)
        assertNull(Disguise.revealWith(after, listOf(v1)))
        assertFalse(rui.vault.decrypt(after, pass).oldSecretCode)
    }

    @Test
    fun withTwoKeysEachHasItsDigitsAndALaterKeyAsksToCombineAgain() {
        val ana = side("Ana")
        val rui = side("Rui")
        knowEachOther(ana, rui) // o Rui tem a primeira chave da Ana
        ana.vault.addMyKey(Pgp.generate("Ana pessoal", "ana@pessoal.pt", pass))
        val ca = ana.vault.setCode(rui.fpr, phrase())
        assertEquals(2, ca.digits.size)
        val cr = rui.vault.setCode(ana.fpr, phrase())
        assertEquals(ca.digits[ana.fpr], cr.digits.values.single(), "coincidem os da chave que o Rui tem")
        assertTrue(ana.vault.contacts().single().codeCheck!!.contains("Ana pessoal"))

        val ok = ana.vault.disguise(ana.vault.encrypt("da primeira", listOf(rui.fpr), ana.fpr, false, null), Disguise.Style.Code, rui.fpr, ana.fpr)
        assertEquals("da primeira", rui.vault.decrypt(ok, pass).text)
        // E o Rui para a Ana: abre na chave certa, entre as duas.
        val back = rui.vault.disguise(rui.vault.encrypt("resposta", listOf(ana.fpr), rui.fpr, false, null), Disguise.Style.Code, ana.fpr, rui.fpr)
        assertEquals("resposta", ana.vault.decrypt(back, pass).text)

        // Uma chave criada depois de combinarem não tem código: a app diz, em vez de usar o antigo às escondidas.
        val third = Pgp.generate("Ana nova", "ana@nova.pt", pass).also { ana.vault.addMyKey(it) }
        val thirdFpr = Pgp.fingerprint(third)
        val msg = ana.vault.encrypt("da nova", listOf(rui.fpr), thirdFpr, false, null)
        val e = assertFailsWith<PgpError> { ana.vault.disguise(msg, Disguise.Style.Code, rui.fpr, thirdFpr) }
        assertTrue(e.message!!.contains("Combinem-no de novo"), e.message)
    }

    @Test
    fun backupCarriesTheNewCodesAndRemovingTheCodeRemovesBoth() {
        val ana = side("Ana")
        val rui = side("Rui")
        knowEachOther(ana, rui)
        ana.vault.setCode(rui.fpr, phrase())
        rui.vault.setCode(ana.fpr, phrase())
        val backupPass = "frase só para o backup".toCharArray()
        val novo = Vault(MemoryStore())
        assertEquals(1, novo.importBackup(ana.vault.exportBackup(backupPass), backupPass).codes)
        assertFalse(novo.contacts().single().codeIsOld)
        val coded = rui.vault.disguise(rui.vault.encrypt("no telemóvel novo", listOf(ana.fpr), rui.fpr, false, null), Disguise.Style.Code, ana.fpr, rui.fpr)
        assertEquals("no telemóvel novo", novo.decrypt(coded, pass).text)

        ana.vault.clearCode(rui.fpr)
        assertNull(ana.vault.contacts().single().codeCheck)
        assertNull(ana.vault.reveal(coded))
        assertTrue(ana.store.names().none { it.startsWith("code") }, ana.store.names().toString())
        rui.vault.deleteContact(ana.fpr)
        assertTrue(rui.store.names().none { it.startsWith("code") }, "apagar o contacto apaga as duas versões")
    }

    @Test
    fun undisguiserNeedsBothFingerprintsForNewCodes() {
        val ana = side("Ana")
        val rui = side("Rui")
        knowEachOther(ana, rui)
        ana.vault.setCode(rui.fpr, phrase())
        val coded = ana.vault.disguise(ana.vault.encrypt("olá", listOf(rui.fpr), ana.fpr, false, null), Disguise.Style.Football, rui.fpr, ana.fpr)

        fun run(args: List<String>, code: CharArray?): Pair<Int, String> {
            val err = ByteArrayOutputStream()
            val rc = Desfazer.run(args, ByteArrayInputStream(coded.toByteArray()), PrintStream(ByteArrayOutputStream(), true, "UTF-8"), PrintStream(err, true, "UTF-8"), code)
            return rc to err.toString("UTF-8")
        }
        val (noPair, why) = run(emptyList(), phrase())
        assertEquals(1, noPair)
        assertTrue(why.contains("--chaves"), why)
        assertEquals(0, run(listOf("--chaves", rui.fpr, ana.fpr), phrase()).first)
        assertEquals(1, run(listOf("--chaves", rui.fpr, ana.fpr), "outra frase qualquer".toCharArray()).first)
        assertEquals(2, run(listOf("--chaves", rui.fpr, ana.fpr), null).first, "--chaves sem --codigo é engano")
        assertEquals(2, run(listOf("--chaves", rui.fpr), phrase()).first)
    }
}
