package app.reczi.pgp.core

import org.bouncycastle.crypto.generators.SCrypt
import java.security.SecureRandom
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Versão 1.4.3: o que diz com quem e como comunicas fica cifrado no cofre, e não sobra nada fora dele. */
class PrivacyTest {
    private val pass = "cavalo bateria agrafo correto".toCharArray()

    @Test
    fun privatePrefsLiveInTheVault() {
        val store = MemoryStore()
        val v = Vault(store)
        val me = Pgp.generate("Ana", "ana@exemplo.pt", pass).also { v.addMyKey(it) }
        val rui = Pgp.generate("Rui", "rui@exemplo.pt", pass)
        val ruiFpr = Pgp.fingerprint(rui)
        v.importContacts(listOf(Pgp.certificateOf(rui)))
        val myFpr = Pgp.fingerprint(me)

        v.setPrefs(mapOf("fmt-$ruiFpr" to "7", "usecode-$ruiFpr" to "1", "backedup-$myFpr" to "1", "format" to "7"))
        assertEquals("7", v.prefs()["fmt-$ruiFpr"])
        // Ficam guardadas (num cofre novo sobre o mesmo armazenamento continuam lá).
        assertEquals(v.prefs(), Vault(store).prefs())
        // Valor null apaga.
        v.setPrefs(mapOf("format" to null))
        assertNull(Vault(store).prefs()["format"])

        // Não vão nos backups (são deste telemóvel) e não estragam o backup.
        val backup = v.exportBackup("palavra-passe do backup".toCharArray())
        val other = Vault(MemoryStore())
        other.importBackup(backup, "palavra-passe do backup".toCharArray())
        assertTrue(other.prefs().isEmpty())

        // Apagar o contacto apaga o que se sabia sobre ele; apagar a chave, o registo de backup.
        v.deleteContact(ruiFpr)
        assertFalse(v.prefs().keys.any { it.endsWith(ruiFpr) })
        v.deleteMyKey(myFpr)
        assertTrue(Vault(store).prefs().isEmpty())

        // Nomes e valores que não cabem no formato são recusados.
        assertFailsWith<IllegalArgumentException> { v.setPrefs(mapOf("fmt-abc" to "1")) }
        assertFailsWith<IllegalArgumentException> { v.setPrefs(mapOf("format" to "7\nfmt-X=1")) }
        assertFailsWith<IllegalArgumentException> { v.setPrefs(mapOf("x=y" to "1")) }
    }

    @Test
    fun panicWipeTakesThePrefsToo() {
        val store = MemoryStore()
        val v = Vault(store)
        v.setPin("4321".toCharArray())
        v.setPanicPin("9999".toCharArray())
        v.setPrefs(mapOf("format" to "7"))
        assertEquals(PinResult.Panic, v.checkPin("9999".toCharArray()))
        v.wipe()
        assertTrue(store.names().isEmpty())
        assertTrue(v.prefs().isEmpty())
        assertFalse(v.hasPin())
    }

    @Test
    fun pinsSavedBeforeTheChangeStillMatch() {
        // Até à 1.4.2 o PIN passava por uma String; agora não, mas os bytes são os mesmos.
        val salt = ByteArray(16).also { SecureRandom().nextBytes(it) }
        for (pin in listOf("1234", "00000000", "987654321")) {
            val old = salt + SCrypt.generate(pin.toByteArray(Charsets.UTF_8), salt, 1 shl 14, 8, 1, 32)
            assertTrue(Lock.matches(old, pin.toCharArray()), pin)
            assertFalse(Lock.matches(old, (pin + "0").toCharArray()), pin)
        }
    }

    @Test
    fun disguiseUsesACryptographicGenerator() {
        // A ordem dos moldes e o enchimento do fim não levam dados, mas também não vêm de um gerador fraco.
        val data = ByteArray(80) { it.toByte() }
        val a = Books.lyrics.write(data)
        val b = Books.lyrics.write(data)
        assertTrue(a != b, "o mesmo texto duas vezes: a aparência devia variar")
        for (t in listOf(a, b)) assertTrue(Books.lyrics.read(t)!!.any { it.contentEquals(data) })
        assertTrue(Poem.write(data) != Poem.write(data))
    }
}
