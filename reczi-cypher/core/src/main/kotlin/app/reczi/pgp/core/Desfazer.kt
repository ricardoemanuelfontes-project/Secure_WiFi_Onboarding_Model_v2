package app.reczi.pgp.core

import java.io.File
import java.io.InputStream
import java.io.PrintStream

/**
 * Desfazedor de disfarce, para o computador: tira o disfarce de um texto do Reczi cypher e mostra a
 * mensagem (ou chave) PGP normal que está por baixo, sem precisar da app nem da Internet.
 *
 * Serve para duas coisas:
 * - confirmar, de fora, que o disfarce só esconde PGP normal (o que sai abre no GnuPG ou noutro
 *   programa OpenPGP, e mais nada fica escondido);
 * - ler no computador uma mensagem disfarçada: `java -jar reczi-desfazer.jar msg.txt | gpg -d`.
 *
 * Não desencripta nada nem pede chaves privadas: só tira a camada de fora. Com `--codigo` pede a
 * frase do código secreto (sem a mostrar no ecrã) para os textos feitos com código.
 *
 * Usa o mesmo código da app (Disguise, Prose, Books), por isso lê exatamente os mesmos formatos.
 */
object Desfazer {
    @JvmStatic
    fun main(args: Array<String>) {
        val code = if ("--codigo" in args) {
            val console = System.console() ?: run { System.err.println("--codigo precisa de um terminal (para não mostrar a frase)."); kotlin.system.exitProcess(2) }
            console.readPassword("Frase do código secreto: ")
        } else null
        kotlin.system.exitProcess(run(args.filter { it != "--codigo" }, System.`in`, System.out, System.err, code))
    }

    /** O trabalho todo; devolve o código de saída (0 = tirou o disfarce). [code] é apagado no fim. */
    fun run(args: List<String>, input: InputStream, out: PrintStream, err: PrintStream, code: CharArray? = null): Int {
        if (args.any { it == "-h" || it == "--ajuda" } || args.size > 1) {
            err.println(
                """
                Uso: java -jar reczi-desfazer.jar [--codigo] [ficheiro]
                Lê o texto disfarçado do ficheiro (ou da entrada, se não houver ficheiro) e escreve o PGP
                que está por baixo. Com --codigo pede a frase do código secreto combinado com o contacto.
                """.trimIndent(),
            )
            return 2
        }
        val text = try {
            if (args.isEmpty()) String(input.readBytes(), Charsets.UTF_8) else File(args[0]).readText(Charsets.UTF_8)
        } catch (e: java.io.IOException) {
            err.println("Não consegui ler: ${e.message}")
            return 2
        }
        val secret = try {
            code?.let { Disguise.deriveSecret(it) }
        } catch (e: PgpError) {
            err.println(e.message)
            return 2
        } finally {
            code?.fill('\u0000')
        }
        val opened = Disguise.revealWith(text, listOfNotNull(secret))
        if (opened == null) {
            err.println(
                if (secret == null) "Não é um texto disfarçado do Reczi cypher (ou foi feito com código secreto: usa --codigo)."
                else "Não abre: não é um texto disfarçado, ou a frase do código secreto não é esta.",
            )
            return 1
        }
        val (bytes, which) = opened
        val armored = runCatching { Pgp.ensureArmored(bytes) }.getOrNull()
        if (armored == null) {
            err.println("O disfarce saiu, mas por baixo não está PGP válido.")
            return 1
        }
        out.print(armored)
        out.flush()
        err.println(if (which < 0) "Disfarce tirado (chave fixa da app)." else "Disfarce tirado com o código secreto.")
        err.println("Por baixo: ${bytes.size} bytes de PGP.")
        runCatching { Pgp.recipientKeyIds(armored) }.getOrNull()?.takeIf { it.isNotEmpty() }?.let { ids ->
            err.println("Para as chaves: " + ids.joinToString(", ") { if (it == 0L) "(destinatário oculto)" else "%016X".format(it) })
        }
        return 0
    }
}
