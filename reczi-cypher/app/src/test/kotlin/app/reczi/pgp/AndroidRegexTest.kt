package app.reczi.pgp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * O Android usa o motor de expressões regulares do ICU, que é mais exigente do que o do Java:
 * rejeita "{" e "}" sem escape fora de um quantificador como {40,64}. Os outros testes correm no
 * Java do computador e não dão por isso (foi o que partiu a 1.4 nos telemóveis: um "}" sem escape
 * fazia rebentar a classe dos formatos, e o Android passava a responder NoClassDefFoundError).
 * Este teste lê o código-fonte e recusa esses padrões.
 */
class AndroidRegexTest {
    /** O problema do padrão para o ICU, ou null se estiver bem. */
    private fun icuProblem(p: String): String? {
        val quantifier = Regex("""\{\d+(,\d*)?}""")
        var i = 0
        while (i < p.length) {
            val c = p[i]
            when {
                c == '\\' && i + 2 < p.length && p[i + 1] in "pPxN" && p[i + 2] == '{' -> {
                    val end = p.indexOf('}', i + 3)
                    if (end < 0) return "\\${p[i + 1]}{ por fechar"
                    i = end + 1
                }
                c == '\\' -> i += 2
                c == '{' -> {
                    val m = quantifier.find(p, i)?.takeIf { it.range.first == i } ?: return "\"{\" sem escape na posição $i"
                    i = m.range.last + 1
                }
                c == '}' -> return "\"}\" sem escape na posição $i"
                else -> i++
            }
        }
        return null
    }

    @Test
    fun theCheckCatchesWhatBrokeVersion14() {
        assertNotNull(icuProblem("""\{[^}]*}"""))
        assertNotNull(icuProblem("""a{b"""))
        assertNull(icuProblem("""\{[^\}]*\}"""))
        assertNull(icuProblem("""^[0-9A-F]{40,64}$"""))
        assertNull(icuProblem("""_(\p{L}+)"""))
    }

    @Test
    fun everyRegexInTheAppIsValidOnAndroid() {
        val roots = listOf(File("src/main/kotlin"), File("../core/src/main/kotlin"))
        val files = roots.flatMap { r -> r.walkTopDown().filter { it.extension == "kt" }.toList() }
        assertTrue("Não encontrei o código-fonte (diretório: ${File(".").absolutePath})", files.size > 10)
        val literal = Regex("""(?:Regex|Pattern\.compile)\(\s*"((?:[^"\\]|\\.)*)"""")
        val problems = files.flatMap { f ->
            literal.findAll(f.readText()).mapNotNull { m ->
                val pattern = m.groupValues[1].replace("\\\\", "\\").replace("\\\"", "\"")
                icuProblem(pattern)?.let { "${f.name}: \"$pattern\": $it" }
            }.toList()
        }
        assertEquals(emptyList<String>(), problems)
    }
}
