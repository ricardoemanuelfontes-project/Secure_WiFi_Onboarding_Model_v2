package app.reczi.pgp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Nenhum gerador aleatório fraco no código da app nem do núcleo: tudo o que é aleatório vem do
 * SecureRandom, mesmo o que não protege nada (a ordem dos moldes do disfarce, por exemplo).
 * Assim um auditor não tem de decidir caso a caso se um gerador fraco é inofensivo.
 */
class NoWeakRandomTest {
    private val weak = listOf(
        Regex("""(?<![A-Za-z])Random\(""") to "Random(...) (use SecureRandom)",
        Regex("""Random\.Default""") to "Random.Default",
        Regex("""ThreadLocalRandom""") to "ThreadLocalRandom",
        Regex("""Math\.random""") to "Math.random",
        Regex("""\.random\(\)""") to ".random()",
        Regex("""\.shuffled?\(""") to ".shuffle()",
        Regex("""Random\.next""") to "Random.next... (gerador por omissão)",
    )

    @Test
    fun theCheckCatchesWeakGenerators() {
        val bad = listOf("val r = Random(7)", "kotlin.random.Random.Default", "list.random()", "x.shuffled()", "java.util.Random()", "Random.nextInt(3)")
        bad.forEach { line -> assertTrue(line, weak.any { it.first.containsMatchIn(line) }) }
        val good = listOf("SecureRandom()", "java.security.SecureRandom().asKotlinRandom()", "random: Random = SECURE", "random.nextInt(3)")
        good.forEach { line -> assertTrue(line, weak.none { it.first.containsMatchIn(line) }) }
    }

    @Test
    fun everyRandomInTheAppIsCryptographic() {
        val roots = listOf(File("src/main/kotlin"), File("../core/src/main/kotlin"))
        val files = roots.flatMap { r -> r.walkTopDown().filter { it.extension == "kt" }.toList() }
        assertTrue("Não encontrei o código-fonte (diretório: ${File(".").absolutePath})", files.size > 10)
        val problems = files.flatMap { f ->
            f.readLines().withIndex().flatMap { (i, line) ->
                val code = line.substringBefore("//")
                weak.filter { it.first.containsMatchIn(code) }.map { "${f.name}:${i + 1}: ${it.second}: ${line.trim()}" }
            }
        }
        assertEquals(emptyList<String>(), problems)
    }
}
