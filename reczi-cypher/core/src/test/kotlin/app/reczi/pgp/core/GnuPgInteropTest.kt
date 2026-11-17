package app.reczi.pgp.core

import org.junit.Assume.assumeTrue
import java.io.File
import java.nio.file.Files
import java.util.concurrent.TimeUnit
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Compatibilidade com o GnuPG 2.4, configurado como pelo instalador do Debian. */
class GnuPgInteropTest {
    private lateinit var home: File
    private val appPass = "pássaro ção çé 2025 frase longa".toCharArray()
    private val gpgPass = "outra frase bem comprida 42"

    private class Out(val rc: Int, val out: ByteArray, val err: String, val status: String)

    private fun gpg(vararg args: String, input: ByteArray? = null, pass: String? = null): Out {
        val statusFile = File(home, "status-${System.nanoTime()}")
        val cmd = mutableListOf("gpg", "--homedir", home.path, "--batch", "--no-tty", "--status-file", statusFile.path)
        if (pass != null) {
            // Por ficheiro em UTF-8: nos argumentos, a JVM converteria os acentos com a codificação do sistema.
            val pf = File(home, "pass-${System.nanoTime()}").apply { writeText(pass, Charsets.UTF_8) }
            cmd += listOf("--pinentry-mode", "loopback", "--passphrase-file", pf.path)
        }
        cmd += args
        val p = ProcessBuilder(cmd).start()
        val err = StringBuilder()
        val errThread = Thread { err.append(p.errorStream.readBytes().toString(Charsets.UTF_8)) }.apply { start() }
        val outBytes = java.io.ByteArrayOutputStream()
        val outThread = Thread { p.inputStream.copyTo(outBytes) }.apply { start() }
        p.outputStream.use { if (input != null) it.write(input) }
        assertTrue(p.waitFor(120, TimeUnit.SECONDS), "gpg demorou demasiado")
        outThread.join(); errThread.join()
        val status = statusFile.takeIf { it.exists() }?.readText() ?: ""
        return Out(p.exitValue(), outBytes.toByteArray(), err.toString(), status)
    }

    @BeforeTest
    fun setUp() {
        assumeTrue("gpg não instalado", runCatching { ProcessBuilder("gpg", "--version").start().waitFor() == 0 }.getOrDefault(false))
        home = Files.createTempDirectory("gnupg").toFile()
        home.setReadable(false, false); home.setReadable(true, true)
        home.setExecutable(false, false); home.setExecutable(true, true)
        File(home, "gpg.conf").writeText(
            """
            personal-cipher-preferences AES256 AES192 AES
            personal-digest-preferences SHA512 SHA384 SHA256
            personal-compress-preferences ZLIB BZIP2 ZIP Uncompressed
            default-preference-list SHA512 SHA384 SHA256 AES256 AES192 AES ZLIB BZIP2 ZIP Uncompressed
            cert-digest-algo SHA512
            s2k-cipher-algo AES256
            s2k-digest-algo SHA512
            s2k-mode 3
            s2k-count 65011712
            keyid-format 0xlong
            with-fingerprint
            no-emit-version
            no-comments
            no-symkey-cache
            require-cross-certification
            """.trimIndent()
        )
        File(home, "gpg-agent.conf").writeText("allow-loopback-pinentry\ns2k-calibration 1000\n")
    }

    @AfterTest
    fun tearDown() {
        if (::home.isInitialized) {
            runCatching { ProcessBuilder("gpgconf", "--homedir", home.path, "--kill", "all").start().waitFor() }
            home.deleteRecursively()
        }
    }

    /** Texto assinado e ficheiro com assinatura à parte, feitos na app, verificados pelo GnuPG. */
    @Test
    fun gnuPgVerifiesAppSignatures() {
        val mine = Pgp.generate("Ana", "ana@exemplo.pt", appPass, rsa = true)
        assertEquals(0, gpg("--import", input = Pgp.armor(Pgp.certificateOf(mine)).toByteArray()).rc)
        // Espaços e tabulações no fim das linhas, linha começada por "-", acentos, linha vazia no fim.
        val texts = listOf("ola eu sou o reczi ", "linha 1  \nlinha 2\t\n\n- traço\nação ", "simples")
        for (t in texts) {
            val signed = Pgp.sign(t, mine, appPass)
            val r = gpg("--verify", input = signed.toByteArray())
            assertTrue("GOODSIG" in r.status, "GnuPG recusou: [$t]\n${r.err}")
            assertTrue(Pgp.verify(signed, listOf(Pgp.certificateOf(mine))).signature is SignatureStatus.Valid)
        }
        val data = ByteArray(50_000) { (it * 7).toByte() }
        val sig = Pgp.signDetached(data.inputStream(), mine, appPass)
        val dataFile = File(home, "dados.bin").apply { writeBytes(data) }
        val sigFile = File(home, "dados.bin.asc").apply { writeText(sig) }
        assertTrue("GOODSIG" in gpg("--verify", sigFile.path, dataFile.path).status)
        dataFile.writeBytes(data.copyOf().also { it[10] = 99 })
        assertTrue("BADSIG" in gpg("--verify", sigFile.path, dataFile.path).status)
    }

    private fun gpgFingerprint(): String =
        gpg("--with-colons", "--list-secret-keys").out.toString(Charsets.UTF_8)
            .lines().first { it.startsWith("fpr:") }.split(":")[9]

    @Test
    fun appAndGnuPgTalkBothWays() {
        // GnuPG: chave com os valores por omissão do 2.4 (ed25519 + cv25519).
        assertEquals(0, gpg("--quick-generate-key", "Gpg User <gpg@exemplo.pt>", "default", "default", "2y", pass = gpgPass).rc)
        val gFpr = gpgFingerprint()

        // App: a minha chave; troca de chaves públicas nos dois sentidos.
        val app = Vault(MemoryStore())
        val mine = Pgp.generate("App User", "app@exemplo.pt", appPass)
        app.addMyKey(mine)
        val aFpr = Pgp.fingerprint(mine)
        assertEquals(listOf(gFpr), app.importContacts(Pgp.parseCertificates(gpg("--armor", "--export", gFpr).out)).added)
        app.setVerified(gFpr, true)
        assertEquals(0, gpg("--import", input = Pgp.armor(Pgp.certificateOf(mine)).toByteArray()).rc)
        assertEquals(0, gpg("--quick-lsign-key", aFpr, pass = gpgPass).rc)

        // App -> GnuPG, assinada.
        val text = "Olá do telemóvel, ção 😀"
        val toGpg = app.encrypt(text, listOf(gFpr), aFpr, true, appPass)
        val d1 = gpg("--decrypt", input = toGpg.toByteArray(), pass = gpgPass)
        assertEquals(0, d1.rc, d1.err)
        assertEquals(text, d1.out.toString(Charsets.UTF_8))
        assertTrue(d1.status.contains("VALIDSIG") && d1.status.contains(aFpr), d1.status)
        assertTrue(d1.status.contains("DECRYPTION_OKAY"))

        // GnuPG -> App, assinada pela chave do GnuPG.
        val toApp = gpg("--armor", "--encrypt", "--sign", "--recipient", aFpr, "--local-user", gFpr,
            input = "Resposta do portátil, ção".toByteArray(), pass = gpgPass)
        assertEquals(0, toApp.rc, toApp.err)
        val r = app.decrypt(toApp.out.toString(Charsets.UTF_8), appPass)
        assertEquals("Resposta do portátil, ção", r.text)
        assertEquals(SignatureStatus.Valid(gFpr), r.signature)
        assertTrue(r.signerVerified)
    }

    /** Destinatários escondidos (ids a zeros): o GnuPG experimenta as chaves que tem, nos dois sentidos. */
    @Test
    fun hiddenRecipientsBothWays() {
        assertEquals(0, gpg("--quick-generate-key", "Gpg User <gpg@exemplo.pt>", "default", "default", "2y", pass = gpgPass).rc)
        val gFpr = gpgFingerprint()
        val app = Vault(MemoryStore())
        val mine = Pgp.generate("App User", "app@exemplo.pt", appPass)
        app.addMyKey(mine)
        val aFpr = Pgp.fingerprint(mine)
        assertEquals(listOf(gFpr), app.importContacts(Pgp.parseCertificates(gpg("--armor", "--export", gFpr).out)).added)
        app.setVerified(gFpr, true)
        assertEquals(0, gpg("--import", input = Pgp.armor(Pgp.certificateOf(mine)).toByteArray()).rc)
        assertEquals(0, gpg("--quick-lsign-key", aFpr, pass = gpgPass).rc)

        // App -> GnuPG: mensagem disfarçada; o desfazedor tira o disfarce e o GnuPG abre o que fica.
        val text = "Escondida do telemóvel, ção"
        val msg = app.encrypt(text, listOf(gFpr), aFpr, true, appPass, hideRecipients = true)
        val under = Pgp.undisguise(app.disguise(msg, Disguise.Style.Lyrics2))!!
        assertEquals(listOf(0L, 0L), Pgp.recipientKeyIds(under))
        val d = gpg("--decrypt", input = under.toByteArray(), pass = gpgPass)
        assertEquals(0, d.rc, d.err)
        assertEquals(text, d.out.toString(Charsets.UTF_8))
        assertTrue(d.status.contains("VALIDSIG") && d.status.contains(aFpr), d.status)
        assertTrue(d.status.contains("DECRYPTION_OKAY"))

        // GnuPG -> App, com --throw-keyids.
        val back = gpg("--armor", "--encrypt", "--sign", "--throw-keyids", "--recipient", aFpr, "--local-user", gFpr,
            input = "Resposta escondida, ção".toByteArray(), pass = gpgPass)
        assertEquals(0, back.rc, back.err)
        val backText = back.out.toString(Charsets.UTF_8)
        assertTrue(Pgp.recipientKeyIds(backText).all { it == 0L })
        val r = app.decrypt(backText, appPass)
        assertEquals("Resposta escondida, ção", r.text)
        assertEquals(SignatureStatus.Valid(gFpr), r.signature)
    }

    @Test
    fun keysMoveBetweenAppAndGnuPg() {
        // Chave criada no GnuPG, importada na app (backup do Debian -> telemóvel).
        assertEquals(0, gpg("--quick-generate-key", "Gpg User <gpg@exemplo.pt>", "default", "default", "2y", pass = gpgPass).rc)
        val gFpr = gpgFingerprint()
        val backup = gpg("--armor", "--export-secret-keys", gFpr, pass = gpgPass).out
        val imported = Pgp.parseSecretKeys(backup).single()
        val app = Vault(MemoryStore())
        val prepared = Pgp.prepareImported(imported, gpgPass.toCharArray())
        app.addMyKey(prepared)
        for (sk in prepared.secretKeys) assertEquals(65011712L, sk.s2K.iterationCount)

        // O GnuPG encripta para a própria chave com as preferências dela (pode usar AEAD/OCB).
        val msg = gpg("--armor", "--encrypt", "--sign", "--recipient", gFpr, "--local-user", gFpr,
            input = "mensagem do GnuPG para mim".toByteArray(), pass = gpgPass)
        assertEquals(0, msg.rc, msg.err)
        val r = app.decrypt(msg.out.toString(Charsets.UTF_8), gpgPass.toCharArray())
        assertEquals("mensagem do GnuPG para mim", r.text)
        assertEquals(SignatureStatus.Valid(gFpr), r.signature)
        assertTrue(r.signerVerified)

        // Chave criada na app, com palavra-passe com acentos, importada no GnuPG (telemóvel -> Debian).
        val mine = Pgp.generate("App User", "app@exemplo.pt", appPass)
        val aFpr = Pgp.fingerprint(mine)
        assertEquals(0, gpg("--import", input = Pgp.armor(mine).toByteArray(), pass = String(appPass)).rc)
        val sec = gpg("--with-colons", "--list-secret-keys", aFpr)
        assertEquals(0, sec.rc, sec.err)
        val fromApp = Pgp.encrypt("do telemóvel para o Debian", listOf(Pgp.certificateOf(mine)), mine, appPass)
        val d = gpg("--decrypt", input = fromApp.toByteArray(), pass = String(appPass))
        assertEquals(0, d.rc, d.err)
        assertEquals("do telemóvel para o Debian", d.out.toString(Charsets.UTF_8))
        assertTrue(d.status.contains("GOODSIG"), d.status)
    }
}
