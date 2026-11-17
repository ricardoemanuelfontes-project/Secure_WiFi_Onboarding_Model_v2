package app.reczi.pgp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import java.io.File
import javax.crypto.Cipher
import javax.crypto.KeyGenerator

/**
 * Versão 1.4.3: os nomes dos ficheiros do cofre não dizem nada (nem fingerprints, nem se há PIN de
 * pânico), e os cofres das versões anteriores passam para o formato novo sem perder nada.
 * (O Robolectric não tem o Keystore do Android: a chave é uma chave AES comum.)
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class SecureStoreTest {
    private val app get() = RuntimeEnvironment.getApplication()
    private val key = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
    private val base get() = app.noBackupFilesDir
    private val dir get() = File(base, "vault")
    private val fpr = "0123456789ABCDEF0123456789ABCDEF01234567"
    private val fpr2 = "89ABCDEF0123456789ABCDEF0123456789ABCDEF"

    @Before
    fun clean() {
        base.listFiles()?.forEach { it.deleteRecursively() }
    }

    private fun store() = KeystoreStore(app, key)

    /** Como guardava a 1.4.2: o ficheiro tem o nome da entrada, que também é o AAD. */
    private fun writeLegacy(name: String, data: ByteArray) {
        dir.mkdirs()
        val c = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key) }
        c.updateAAD(name.toByteArray())
        val sealed = c.doFinal(data)
        File(dir, name).writeBytes(byteArrayOf(1) + c.iv + sealed)
    }

    private fun files(): List<File> = base.walkTopDown().filter { it.isFile }.toList()

    private fun entryFiles(): List<File> = dir.listFiles()!!.filter { it.name != "v2-index" }

    @Test
    fun fileNamesSayNothing() {
        val s = store()
        s.write("pub-$fpr", "chave".toByteArray())
        s.write("code-$fpr", ByteArray(32))
        s.write("panic", "x".toByteArray())
        s.write("pin", "y".toByteArray())
        s.write("prefs", "fmt-$fpr=7".toByteArray())
        val names = files().map { it.name }
        assertTrue(names.toString(), names.all { it == "v2-index" || Regex("v2-[0-9a-f]{32}").matches(it) })
        assertEquals(6, names.size) // 5 entradas + o índice
        // Também não estão no conteúdo (cifrado).
        val bytes = files().joinToString { String(it.readBytes(), Charsets.ISO_8859_1) }
        assertFalse(bytes.contains(fpr))
        assertFalse(bytes.contains("panic"))

        // Aberto de novo (outra instância), encontra tudo.
        val again = store()
        assertEquals(listOf("code-$fpr", "panic", "pin", "prefs", "pub-$fpr"), again.names())
        assertEquals("chave", String(again.read("pub-$fpr")!!))
        again.write("pub-$fpr", "chave nova".toByteArray()) // substituir não cria outro ficheiro
        assertEquals(6, files().size)
        assertTrue(again.contains("panic"))
        again.delete("panic")
        assertFalse(store().contains("panic"))
        assertNull(store().read("panic"))
        assertEquals("chave nova", String(store().read("pub-$fpr")!!))
        assertEquals(5, files().size)
    }

    @Test
    fun oldVaultMovesToTheNewFormat() {
        writeLegacy("sec-$fpr", "privada".toByteArray())
        writeLegacy("pub-$fpr2", "publica".toByteArray())
        writeLegacy("verified", fpr2.toByteArray())
        writeLegacy("panic", "hash".toByteArray())
        File(dir, "pin.tmp").writeBytes(byteArrayOf(1, 2, 3)) // escrita interrompida
        val s = store()
        assertEquals(listOf("panic", "pub-$fpr2", "sec-$fpr", "verified"), s.names())
        assertEquals("privada", String(s.read("sec-$fpr")!!))
        val names = files().map { it.name }
        assertFalse(names.toString(), names.any { it.contains(fpr) || it.contains(fpr2) || it == "panic" || it.endsWith(".tmp") })
        assertEquals("publica", String(store().read("pub-$fpr2")!!))
    }

    @Test
    fun migrationInterruptedHalfWayLosesNothing() {
        // A app parou depois de passar o ficheiro e guardar o índice, mas antes de apagar o antigo.
        writeLegacy("pub-$fpr", "publica".toByteArray())
        store().names()
        writeLegacy("pub-$fpr", "publica".toByteArray())
        val again = store()
        assertEquals(listOf("pub-$fpr"), again.names())
        assertEquals("publica", String(again.read("pub-$fpr")!!))
        assertFalse(File(dir, "pub-$fpr").exists())
        assertEquals(2, files().size)
    }

    @Test
    fun unreadableOldFileShowsUpAsBrokenAndCanBePutAside() {
        writeLegacy("pub-$fpr", "publica".toByteArray())
        File(dir, "pub-$fpr2").writeBytes(byteArrayOf(1) + ByteArray(40)) // estragado
        val s = store()
        assertEquals(listOf("pub-$fpr", "pub-$fpr2"), s.names())
        assertThrows(Exception::class.java) { s.read("pub-$fpr2") }
        s.quarantine("pub-$fpr2")
        assertEquals(listOf("pub-$fpr"), store().names())
        // Fica de lado, com um nome que não diz nada.
        val aside = File(base, "vault-avariados").listFiles()!!.map { it.name }
        assertEquals(1, aside.size)
        assertFalse(aside.single().contains(fpr2))
    }

    @Test
    fun lostOrBrokenIndexIsRebuiltFromTheFiles() {
        val s = store()
        s.write("pub-$fpr", "a".toByteArray())
        s.write("note-$fpr2", "b".toByteArray())
        File(dir, "v2-index").writeBytes(byteArrayOf(2) + ByteArray(40)) // índice estragado
        assertEquals(listOf("note-$fpr2", "pub-$fpr"), store().names())
        File(dir, "v2-index").delete()
        val again = store()
        assertEquals(listOf("note-$fpr2", "pub-$fpr"), again.names())
        assertEquals("b", String(again.read("note-$fpr2")!!))
    }

    @Test
    fun withTheWrongKeyNothingIsMoved() {
        val s = store()
        s.write("pub-$fpr", "a".toByteArray())
        File(dir, "v2-index").delete()
        val other = KeystoreStore(app, KeyGenerator.getInstance("AES").apply { init(256) }.generateKey())
        assertThrows(Exception::class.java) { other.names() }
        assertEquals(1, entryFiles().size)
        assertEquals(listOf("pub-$fpr"), store().names())
    }

    @Test
    fun swappedFilesAreRefused() {
        val s = store()
        s.write("pin", "1".toByteArray())
        s.write("panic", "2".toByteArray())
        val (f1, f2) = entryFiles()
        val a = f1.readBytes()
        f1.writeBytes(f2.readBytes())
        f2.writeBytes(a)
        // Trocar dois ficheiros não faz o PIN de pânico passar a ser o PIN da app.
        val again = store()
        assertThrows(Exception::class.java) { again.read("pin") }
        assertThrows(Exception::class.java) { again.read("panic") }
    }

    @Test
    fun orphanFromAnInterruptedWriteIsPutAside() {
        val s = store()
        s.write("pub-$fpr", "a".toByteArray())
        // Um ficheiro que o índice não conhece: a app parou antes de guardar o índice.
        entryFiles().single().copyTo(File(dir, "v2-" + "ab".repeat(16)))
        assertEquals(listOf("pub-$fpr"), store().names())
        assertEquals(1, entryFiles().size)
        assertEquals(1, File(base, "vault-avariados").listFiles()!!.size)
    }

    @Test
    fun wipeLeavesNothing() {
        val s = store()
        s.write("pub-$fpr", "a".toByteArray())
        s.write("panic", "b".toByteArray())
        s.wipe()
        assertTrue(files().isEmpty())
        assertTrue(s.names().isEmpty())
    }
}
