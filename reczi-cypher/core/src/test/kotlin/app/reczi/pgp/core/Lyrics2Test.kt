package app.reczi.pgp.core

import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Versão 1.4.4: letra de rap 2. */
class Lyrics2Test {
    private val book = Books.lyrics2

    @Test
    fun noNameTwiceInTheSameBar() {
        // "Hera no amapiano, Hera no miolo" não pode acontecer: em cada barra, cada palavra que leva dados é diferente.
        val random = Random(11)
        repeat(20) {
            val text = book.write(random.nextBytes(1200), random)
            for (line in text.lines()) {
                val keys = Prose.words(line).filter { it !in book.glue }
                assertEquals(keys.size, keys.toSet().size, "repetida na barra: $line")
            }
        }
    }

    @Test
    fun beginningAndEndAreNotAFixedMark() {
        val random = Random(12)
        val firsts = HashSet<String>()
        val lasts = HashSet<String>()
        repeat(400) {
            val text = book.write(random.nextBytes(60), random)
            firsts += text.lines().first()
            lasts += text.lines().last()
            assertTrue(book.read(text)!!.isNotEmpty())
        }
        // 12 aberturas e 12 fechos, e às vezes nenhum (aí a primeira e a última linhas são barras).
        assertTrue(firsts.size > 12 + 10, "aberturas: ${firsts.size}")
        assertTrue(lasts.size > 12 + 10, "fechos: ${lasts.size}")
    }

    @Test
    fun theOldLyricsAreUntouchedAndTheTwoDoNotMix() {
        val data = Random(13).nextBytes(200)
        val old = Books.lyrics.write(data)
        val new = book.write(data)
        assertTrue(Books.lyrics.read(old)!!.any { it.contentEquals(data) })
        assertTrue(book.read(new)!!.any { it.contentEquals(data) })
        // Os heróis da letra 2 não existem na letra antiga.
        assertNull(Books.lyrics.read(new))
        // E pelo disfarce completo cada uma abre com a sua aparência.
        val pgp = Random(14).nextBytes(300)
        assertTrue(Disguise.reveal(Disguise.hide(pgp, Disguise.Style.Lyrics2))!!.contentEquals(pgp))
        assertTrue(Disguise.reveal(Disguise.hide(pgp, Disguise.Style.Lyrics))!!.contentEquals(pgp))
    }
}
