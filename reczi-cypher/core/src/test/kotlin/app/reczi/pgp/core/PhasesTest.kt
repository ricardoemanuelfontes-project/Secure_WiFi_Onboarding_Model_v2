package app.reczi.pgp.core

import org.pgpainless.PGPainless
import org.pgpainless.key.protection.SecretKeyRingProtector
import org.pgpainless.key.util.RevocationAttributes
import org.pgpainless.util.Passphrase
import java.io.ByteArrayOutputStream
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Notas, assinar sem encriptar, ficheiros, PIN da app e códigos QR. */
class PhasesTest {
    private val pass = "cavalo bateria agrafo correto".toCharArray()

    private fun vaultWithKey(name: String, email: String): Pair<Vault, String> {
        val v = Vault(MemoryStore())
        val key = Pgp.generate(name, email, pass)
        v.addMyKey(key)
        return v to Pgp.fingerprint(key)
    }

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
    fun notesAreEncryptedAndNeedThePassphraseToRead() {
        val store = MemoryStore()
        val v = Vault(store).apply { addMyKey(Pgp.generate("Ana", "ana@exemplo.pt", pass)) }
        val id = v.saveNote(null, "  Códigos\ndo banco ", "PIN 1234\nsegunda linha ção")
        val note = v.snapshot().notes.single()
        assertEquals(id, note.id)
        assertEquals("Códigos do banco", note.label)
        val raw = String(store.read("note-$id")!!)
        assertFalse(raw.contains("1234"))
        assertTrue(raw.contains("BEGIN PGP MESSAGE"))
        assertEquals("PIN 1234\nsegunda linha ção", v.readNote(id, pass))
        assertFailsWith<WrongPassphraseError> { v.readNote(id, "palavra-passe errada".toCharArray()) }

        // Editar mantém o id; sem etiqueta fica "Nota".
        assertEquals(id, v.saveNote(id, "", "texto novo"))
        assertEquals("Nota", v.snapshot().notes.single().label)
        assertEquals("texto novo", v.readNote(id, pass))
        // Um cofre novo sobre os mesmos ficheiros lê o mesmo.
        assertEquals("texto novo", Vault(store).readNote(id, pass))

        assertFailsWith<PgpError> { v.saveNote(null, "x", "  ") }
        assertFailsWith<PgpError> { v.saveNote("../fora", "x", "y") }
        assertFailsWith<PgpError> { Vault(MemoryStore()).saveNote(null, "x", "sem chave") }
        v.deleteNote(id)
        assertTrue(v.snapshot().notes.isEmpty())
        assertFailsWith<PgpError> { v.readNote(id, pass) }
    }

    @Test
    fun signWithoutEncryptingAndVerify() {
        val (a, r) = pair()
        val (ana, anaFpr) = a
        val (rui, _) = r
        val text = "Declaro que isto é meu.\n- com um traço no início\nção ñ 😀"
        val signed = ana.sign(text, anaFpr, pass)
        assertTrue(signed.startsWith("-----BEGIN PGP SIGNED MESSAGE-----"))
        assertTrue(signed.contains("Declaro que isto é meu."), "o texto fica legível")
        assertTrue(Pgp.isSignedText("\n  $signed"))
        assertFailsWith<WrongPassphraseError> { ana.sign(text, anaFpr, "palavra-passe errada".toCharArray()) }

        val ok = rui.verify(signed)
        assertEquals(text, ok.text.trimEnd())
        assertEquals(SignatureStatus.Valid(anaFpr), ok.signature)
        assertTrue(ok.signerVerified)
        assertEquals("Ana <ana@exemplo.pt>", ok.signerName)

        // Texto alterado: assinatura inválida.
        val bad = rui.verify(signed.replace("isto é meu", "isto é teu"))
        assertEquals(SignatureStatus.Invalid, bad.signature)
        assertFalse(bad.signerVerified)

        // Quem não conhece a Ana: remetente desconhecido.
        val (eva, _) = vaultWithKey("Eva", "eva@exemplo.pt")
        assertEquals(SignatureStatus.UnknownSigner, eva.verify(signed).signature)

        // Contacto não verificado: válida, mas por confirmar.
        rui.setVerified(anaFpr, false)
        val unverified = rui.verify(signed)
        assertEquals(SignatureStatus.Valid(anaFpr), unverified.signature)
        assertFalse(unverified.signerVerified)

        assertFailsWith<PgpError> { rui.verify("texto normal") }
    }

    @Test
    fun signedTextFromRevokedKeyIsRejected() {
        val alice = Pgp.generate("Alice", "alice@exemplo.pt", pass)
        val signed = Pgp.sign("texto público", alice, pass)
        val revoked = PGPainless.modifyKeyRing(alice)
            .revoke(SecretKeyRingProtector.unlockAnyKeyWith(Passphrase(pass.copyOf())),
                RevocationAttributes.createKeyRevocation().withReason(RevocationAttributes.Reason.KEY_COMPROMISED).withoutDescription())
            .done()
        val r = Pgp.verify(signed, listOf(Pgp.certificateOf(revoked)))
        assertEquals(SignatureStatus.Rejected(Pgp.fingerprint(alice)), r.signature)
    }

    @Test
    fun fileRoundTripBetweenTwoPeople() {
        val (a, r) = pair()
        val (ana, anaFpr) = a
        val (rui, ruiFpr) = r
        val data = ByteArray(300_000) { (it * 31 + it / 7).toByte() }
        val enc = ByteArrayOutputStream()
        ana.encryptFile(data.inputStream(), enc, "férias/2026.jpg", listOf(ruiFpr), anaFpr, true, pass)
        val file = enc.toByteArray()
        assertTrue((file[0].toInt() and 0x80) != 0, "binário, não armorado")
        assertFalse(String(file, Charsets.ISO_8859_1).contains("2026.jpg"), "o nome vai dentro da parte encriptada")

        assertTrue(rui.isFileForMe(file.inputStream()))
        val out = ByteArrayOutputStream()
        val d = rui.decryptFile({ file.inputStream() }, out, pass)
        assertContentEquals(data, out.toByteArray())
        assertEquals("férias_2026.jpg", d.text)
        assertEquals(SignatureStatus.Valid(anaFpr), d.signature)
        assertTrue(d.signerVerified)
        // A Ana também o abre (encriptado sempre também para ela).
        val again = ByteArrayOutputStream()
        ana.decryptFile({ file.inputStream() }, again, pass)
        assertContentEquals(data, again.toByteArray())

        // Erros: palavra-passe errada, não é para mim, ficheiro alterado, não é PGP.
        assertFailsWith<WrongPassphraseError> { rui.decryptFile({ file.inputStream() }, ByteArrayOutputStream(), "palavra-passe errada".toCharArray()) }
        val (eva, _) = vaultWithKey("Eva", "eva@exemplo.pt")
        assertFalse(eva.isFileForMe(file.inputStream()))
        assertFailsWith<PgpError> { eva.decryptFile({ file.inputStream() }, ByteArrayOutputStream(), pass) }
        val damaged = file.copyOf().also { it[it.size / 2] = (it[it.size / 2] + 1).toByte() }
        assertFailsWith<PgpError> { rui.decryptFile({ damaged.inputStream() }, ByteArrayOutputStream(), pass) }
        assertFailsWith<PgpError> { rui.isFileForMe("isto não é pgp".toByteArray().inputStream()) }
        assertFailsWith<PgpError> { ana.encryptFile(data.inputStream(), ByteArrayOutputStream(), "x", emptyList(), anaFpr, false, null) }

        // Sem assinatura, e um ficheiro de texto armorado feito pelo encrypt normal também abre como ficheiro.
        val unsigned = ByteArrayOutputStream()
        ana.encryptFile("abc".toByteArray().inputStream(), unsigned, null, listOf(ruiFpr), anaFpr, false, null)
        val o2 = ByteArrayOutputStream()
        val d2 = rui.decryptFile({ unsigned.toByteArray().inputStream() }, o2, pass)
        assertEquals("abc", o2.toString())
        assertEquals(SignatureStatus.None, d2.signature)
        assertEquals("", d2.text)
        val armored = ana.encrypt("mensagem", listOf(ruiFpr), anaFpr, false, null).toByteArray()
        val o3 = ByteArrayOutputStream()
        rui.decryptFile({ armored.inputStream() }, o3, pass)
        assertEquals("mensagem", o3.toString())
    }

    @Test
    fun appPinAndPanicPin() {
        val store = MemoryStore()
        val v = Vault(store).apply { addMyKey(Pgp.generate("Ana", "ana@exemplo.pt", pass)) }
        assertFalse(v.hasPin())
        assertEquals(PinResult.Wrong, v.checkPin("1234".toCharArray()))
        assertFailsWith<PgpError> { v.setPanicPin("9999".toCharArray()) } // primeiro o PIN da app
        assertFailsWith<PgpError> { v.setPin("123".toCharArray()) }
        v.setPin("2468".toCharArray())
        assertTrue(v.hasPin())
        assertFalse(String(store.read("pin")!!, Charsets.ISO_8859_1).contains("2468"))
        assertEquals(PinResult.Ok, v.checkPin("2468".toCharArray()))
        assertEquals(PinResult.Wrong, v.checkPin("2469".toCharArray()))

        assertFailsWith<PgpError> { v.setPanicPin("2468".toCharArray()) } // tem de ser diferente
        v.setPanicPin("1357".toCharArray())
        assertTrue(v.hasPanicPin())
        assertFailsWith<PgpError> { v.setPin("1357".toCharArray()) }
        assertEquals(PinResult.Panic, v.checkPin("1357".toCharArray()))
        assertEquals(PinResult.Ok, v.checkPin("2468".toCharArray()))
        // Um cofre novo sobre os mesmos ficheiros (app reaberta) vê os mesmos PINs.
        assertEquals(PinResult.Panic, Vault(store).checkPin("1357".toCharArray()))

        v.clearPanicPin()
        assertEquals(PinResult.Wrong, v.checkPin("1357".toCharArray()))
        v.setPanicPin("1357".toCharArray())
        v.clearPin()
        assertFalse(v.hasPin())
        assertFalse(v.hasPanicPin())

        // Pânico: apaga tudo.
        v.saveNote(null, "n", "texto")
        v.setPin("2468".toCharArray())
        v.wipe()
        assertTrue(store.names().isEmpty())
        val s = v.snapshot()
        assertTrue(s.myKeys.isEmpty() && s.contacts.isEmpty() && s.notes.isEmpty())
        assertFalse(v.hasPin())
    }

    /** Desenha os módulos como uma imagem, [scale] píxeis por módulo. */
    private fun render(m: Array<BooleanArray>, scale: Int): Triple<IntArray, Int, Int> {
        val w = m[0].size * scale
        val h = m.size * scale
        val px = IntArray(w * h) { i -> if (m[(i / w) / scale][(i % w) / scale]) 0xFF000000.toInt() else 0xFFFFFFFF.toInt() }
        return Triple(px, w, h)
    }

    @Test
    fun qrCodesShownAreAlwaysReadable() {
        // Sem a verificação de [Qr.reliable], cerca de 1 em 10 destes códigos não se consegue ler.
        // Aqui lêem-se em tamanhos que [Qr.reliable] não experimentou, e descentrados numa imagem maior.
        val rnd = java.util.Random(7)
        var failures = 0
        repeat(60) {
            val (text, modules) = Qr.reliable { Disguise.hide(ByteArray(950).also(rnd::nextBytes)) }
            for (scale in listOf(7, 8)) {
                val (px, w, h) = render(modules, scale)
                if (Qr.decode(px, w, h) != text) failures++
            }
            val (px, w, h) = render(modules, 4)
            val big = IntArray((w + 300) * (h + 200)) { 0xFFFFFFFF.toInt() }
            for (y in 0 until h) System.arraycopy(px, y * w, big, (y + 130) * (w + 300) + 210, w)
            if (Qr.decode(big, w + 300, h + 200) != text) failures++
        }
        assertEquals(0, failures, "leituras falhadas em 180")
    }

    @Test
    fun publicAndPrivateKeysFitInAQrCodeAndComeBack() {
        val key = Pgp.generate("Ana Maria Lima Fontes", "ana.maria.lima@exemplo.pt", pass)
        val cert = Pgp.certificateOf(key)
        for ((ring, what) in listOf(cert to "PUBLIC", key to "PRIVATE")) {
            val (text, modules) = Qr.ofKey(ring)
            assertEquals(modules.size, modules[0].size)
            assertTrue(modules.size <= 177 + 8, "cabe num QR (${modules.size} módulos)")
            println("QR $what: ${ring.encoded.size} bytes, ${text.length} caracteres, ${modules.size} módulos")
            val (px, w, h) = render(modules, 4)
            assertEquals(text, Qr.decode(px, w, h))
            val armored = Pgp.undisguise(text)!!
            assertTrue(armored.contains("BEGIN PGP $what KEY BLOCK"))
        }
        // A chave privada volta inteira e ainda abre com a palavra-passe.
        val back = Pgp.parseSecretKeys(Disguise.reveal(Qr.ofKey(key).first)!!).single()
        assertEquals(Pgp.fingerprint(key), Pgp.fingerprint(back))
        assertTrue(Pgp.checkPassphrase(back, pass))
        // E a pública importa-se como contacto.
        val v = Vault(MemoryStore()).apply { addMyKey(Pgp.generate("Rui", "rui@exemplo.pt", pass)) }
        val scanned = v.reveal(Qr.ofKey(cert).first)!!.armored
        assertEquals(listOf(Pgp.fingerprint(key)), v.importContacts(Pgp.parseCertificates(scanned.toByteArray())).added)

        assertNull(Qr.decode(IntArray(100 * 100) { 0xFFFFFFFF.toInt() }, 100, 100))
        assertFailsWith<PgpError> { Qr.encode("x".repeat(5000)) }
    }
}
