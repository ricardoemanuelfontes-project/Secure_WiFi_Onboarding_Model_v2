package app.reczi.pgp.core

import java.io.ByteArrayInputStream
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * Revisão de segurança: tudo o que vem de fora (texto colado, ficheiros escolhidos, códigos QR) passa
 * por aqui com milhares de entradas estragadas ou ao acaso. Só se aceita a resposta "não é
 * válido" (null, false, lista vazia, ou um [PgpError] com mensagem para o utilizador): nada de
 * outras exceções, que no Android fechariam a app ou dariam "Erro inesperado", e nada de demoras.
 * A semente é fixa para uma falha se repetir.
 */
class FuzzTest {
    private val random = Random(20261117)
    private val pass = "cavalo bateria agrafo correto".toCharArray()
    /** Tipo de falha -> um exemplo (para o relatório não se afogar em repetições). */
    private val failures = linkedMapOf<String, String>()
    private var slowest = 0L to ""

    /** Corre [block]; só [PgpError] é aceite (e só onde [errorsOk]). Regista o tempo. */
    private fun probe(what: String, input: Any, errorsOk: Boolean = true, block: () -> Unit) {
        val start = System.nanoTime()
        try {
            block()
        } catch (e: PgpError) {
            if (!errorsOk) failures.putIfAbsent("$what: PgpError", "${e.message} com ${show(input)}")
        } catch (e: Throwable) {
            failures.putIfAbsent("$what: ${e.javaClass.name}", "${e.message} com ${show(input)}\n    em ${e.stackTrace.take(4).joinToString(" < ")}")
        }
        val ms = (System.nanoTime() - start) / 1_000_000
        if (ms > slowest.first) slowest = ms to "$what com ${show(input)}"
    }

    private fun show(input: Any): String = when (input) {
        is String -> "texto de ${input.length} caracteres: \"${input.take(80).replace("\n", "⏎")}\""
        is ByteArray -> "${input.size} bytes: ${input.take(24).joinToString("") { "%02x".format(it) }}"
        else -> input.toString()
    }

    private fun finish(maxMs: Long) {
        if (failures.isNotEmpty()) fail("${failures.size} tipo(s) de falha:\n" + failures.entries.joinToString("\n") { "${it.key}: ${it.value}" })
        assertTrue(slowest.first < maxMs, "demasiado lento (${slowest.first} ms): ${slowest.second}")
    }

    // ------------------------------------------------------------------ geradores de lixo

    private val alphabet = "abcdefghijklmnopqrstuvwxyzáéíóúãõçàâêô ABCDEFXYZ0123456789.,;:!?-–—…'\"()[]{}<>/\\|@#\$%&*+=_~^`\n\t\r " +
        "\u0000 ​﻿😀日本語"

    private fun junkText(n: Int = random.nextInt(0, 3000)) = buildString { repeat(n) { append(alphabet[random.nextInt(alphabet.length)]) } }

    /** Palavras das listas da app, em ordem ao acaso: chegam fundo nos descodificadores. */
    private val vocabulary: List<String> by lazy {
        (Books.all.map { it.write(random.nextBytes(300), random) } + Poem.write(random.nextBytes(300)) + Disguise.WORDS.joinToString(" "))
            .flatMap { it.split(Regex("\\s+")) }.filter { it.isNotBlank() }.distinct()
    }

    private fun wordSoup(n: Int = random.nextInt(1, 600)) =
        (1..n).joinToString(if (random.nextBoolean()) " " else "\n") { vocabulary[random.nextInt(vocabulary.size)] }

    /** Um texto válido com um estrago: palavra a menos, a mais, trocada, cortado, pontuação... */
    private fun mutate(text: String): String {
        val words = text.split(" ").toMutableList()
        when (random.nextInt(8)) {
            0 -> if (words.size > 1) words.removeAt(random.nextInt(words.size))
            1 -> words.add(random.nextInt(words.size + 1), words[random.nextInt(words.size)])
            2 -> if (words.size > 1) {
                val i = random.nextInt(words.size)
                val j = random.nextInt(words.size)
                val t = words[i]; words[i] = words[j]; words[j] = t
            }
            3 -> return text.take(random.nextInt(text.length + 1))
            4 -> return text.substring(random.nextInt(text.length + 1))
            5 -> {
                val i = random.nextInt(text.length + 1)
                return text.substring(0, i) + "!?…\n\n:;" .random(random) + text.substring(i)
            }
            6 -> return text.uppercase()
            else -> words[random.nextInt(words.size)] = vocabulary[random.nextInt(vocabulary.size)]
        }
        return words.joinToString(" ")
    }

    private fun flipBytes(data: ByteArray): ByteArray {
        val out = data.copyOf()
        when (random.nextInt(4)) {
            0 -> repeat(random.nextInt(1, 6)) { if (out.isNotEmpty()) out[random.nextInt(out.size)] = random.nextInt(256).toByte() }
            1 -> return out.copyOf(random.nextInt(out.size + 1))
            2 -> return out.copyOfRange(random.nextInt(out.size + 1), out.size)
            else -> return out + random.nextBytes(random.nextInt(1, 64))
        }
        return out
    }

    private fun flipArmor(armored: String): String {
        val lines = armored.lines().toMutableList()
        val body = lines.indices.filter { lines[it].isNotEmpty() && !lines[it].startsWith("-----") && !lines[it].startsWith("=") }
        if (body.isEmpty()) return armored
        when (random.nextInt(4)) {
            0 -> {
                val i = body.random(random)
                val chars = lines[i].toCharArray()
                chars[random.nextInt(chars.size)] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="[random.nextInt(65)]
                lines[i] = String(chars)
            }
            1 -> lines.removeAt(body.random(random))
            2 -> return armored.take(random.nextInt(armored.length + 1))
            else -> lines.add(body.random(random), "Comment: " + junkText(20))
        }
        return lines.joinToString("\n")
    }

    // ------------------------------------------------------------------ material válido para estragar

    private val ana = Vault(MemoryStore())
    private val anaKey = Pgp.generate("Ana", "ana@exemplo.pt", pass).also { ana.addMyKey(it) }
    private val anaFpr = Pgp.fingerprint(anaKey)
    private val message = ana.encrypt("encontro às 8 no sítio do costume", listOf(anaFpr), anaFpr, true, pass)
    private val disguised: List<String> = Disguise.Style.entries.map { ana.disguise(message, it) }

    // ------------------------------------------------------------------ testes

    @Test
    fun pastedTextNeverCrashes() {
        val inputs = buildList {
            repeat(300) { add(junkText()) }
            repeat(300) { add(wordSoup()) }
            repeat(600) { add(mutate(disguised[random.nextInt(disguised.size)])) }
            repeat(200) { add(flipArmor(message)) }
            add("")
            add("-----BEGIN PGP MESSAGE-----\n\n-----END PGP MESSAGE-----")
            add("-----BEGIN PGP MESSAGE-----\n" + "A".repeat(5000) + "\n-----END PGP MESSAGE-----")
            add("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\nolá\n-----BEGIN PGP SIGNATURE-----\n\nAAAA\n-----END PGP SIGNATURE-----")
        }
        var opened = 0
        for (t in inputs) {
            probe("Disguise.reveal", t, errorsOk = false) { if (Disguise.reveal(t) != null) opened++ }
            probe("Pgp.undisguise", t, errorsOk = false) { Pgp.undisguise(t) }
            probe("Pgp.recipientKeyIds", t) { Pgp.recipientKeyIds(t) }
            probe("Vault.reveal", t, errorsOk = false) { ana.reveal(t) }
            probe("Vault.isForMe", t) { ana.isForMe(t) }
            probe("Disguise.units", t, errorsOk = false) { Disguise.Style.entries.forEach { s -> Disguise.units(t, s) } }
            probe("Pgp.dearmor", t) { Pgp.dearmor(t) }
            probe("Pgp.extractPublicKeys", t) { Pgp.extractPublicKeys(t) }
            probe("Vault.verify", t) { if (Pgp.isSignedText(t)) ana.verify(t) }
        }
        // Os estragos vão do inofensivo (maiúsculas, pontuação) ao fatal: os dois caminhos foram testados.
        assertTrue(opened in 1 until inputs.size, "abriram $opened de ${inputs.size}")
        finish(maxMs = 5_000)
    }

    @Test
    fun brokenMessagesAreRefusedCleanly() {
        // Desencriptar exige a palavra-passe (lento): menos casos, mas todos os formatos.
        val inputs = buildList {
            repeat(40) { add(mutate(disguised[random.nextInt(disguised.size)])) }
            repeat(40) { add(flipArmor(message)) }
        }
        for (t in inputs) probe("Vault.decrypt", t) { ana.decrypt(t, pass) }
        finish(maxMs = 20_000)
    }

    @Test
    fun chosenFilesNeverCrash() {
        val rui = Pgp.generate("Rui", "rui@exemplo.pt", pass, rsa = false)
        val valid = listOf(
            Pgp.armor(anaKey).toByteArray(),
            anaKey.encoded,
            Pgp.armor(Pgp.certificateOf(rui)).toByteArray(),
            Pgp.certificateOf(rui).encoded,
            ana.exportBackup("palavra-passe do backup".toCharArray()),
            Pgp.dearmor(message),
            message.toByteArray(),
        )
        val inputs = buildList {
            repeat(200) { add(random.nextBytes(random.nextInt(0, 4000))) }
            repeat(800) { add(flipBytes(valid[random.nextInt(valid.size)])) }
            repeat(200) { add(flipArmor(String(valid[random.nextInt(3)])).toByteArray()) }
            add(ByteArray(0))
            add(byteArrayOf(0x99.toByte()))
            add(byteArrayOf(0x99.toByte(), 0xff.toByte(), 0xff.toByte()))
        }
        val v = Vault(MemoryStore())
        for (b in inputs) {
            probe("Pgp.importKind", b, errorsOk = false) { Pgp.importKind(b) }
            probe("Pgp.isPasswordEncrypted", b, errorsOk = false) { Pgp.isPasswordEncrypted(b) }
            probe("Backup.isBackup", b, errorsOk = false) { Backup.isBackup(b) }
            probe("Pgp.recipientKeyIds(stream)", b) { Pgp.recipientKeyIds(ByteArrayInputStream(b)) }
            probe("Pgp.parseCertificates", b) { Pgp.parseCertificates(b) }
            probe("Pgp.parseSecretKeys", b) { Pgp.parseSecretKeys(b) }
            probe("Pgp.otherCertificates", b) { Pgp.otherCertificates(b) }
            probe("Vault.importContacts", b) { v.importContacts(Pgp.parseCertificates(b)) }
        }
        // Os que pedem palavra-passe são lentos (scrypt): uma amostra.
        for (b in inputs.shuffled(random).take(60)) {
            probe("Backup.open", b) { Backup.open(b, "palavra-passe do backup".toCharArray()) }
            probe("Pgp.openPasswordBackup", b) { Pgp.openPasswordBackup(b, "1234-5678".toCharArray()) }
        }
        finish(maxMs = 20_000)
    }

    @Test
    fun scannedQrCodesNeverCrash() {
        val parts = Qr.ofKey(anaKey).map { it.text }
        val inputs = buildList {
            repeat(300) { add(junkText(random.nextInt(0, 800))) }
            repeat(300) { add(mutate(parts.random(random))) }
            repeat(100) { add(Disguise.hide(random.nextBytes(random.nextInt(1, 300)), Disguise.Style.Code)) }
        }
        for (t in inputs) probe("Qr.Assembler.add", t) { Qr.Assembler().add(t) }
        finish(maxMs = 5_000)
    }

    @Test
    fun hugePasteDoesNotHang() {
        // Colar um texto enorme (um livro, um ficheiro errado) não pode bloquear a app.
        val big = listOf(wordSoup(60_000), junkText(400_000), mutate(disguised.last()).repeat(20))
        for (t in big) {
            probe("Disguise.reveal (grande)", t, errorsOk = false) { Disguise.reveal(t) }
            probe("Vault.reveal (grande)", t, errorsOk = false) { ana.reveal(t) }
        }
        finish(maxMs = 15_000)
    }
}
