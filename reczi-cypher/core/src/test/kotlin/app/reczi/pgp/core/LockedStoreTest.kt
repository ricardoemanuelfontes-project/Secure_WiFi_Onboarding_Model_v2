package app.reczi.pgp.core

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * 1.4.6: com a chave do cofre presa ao telemóvel desbloqueado, ler pode falhar só por o telemóvel
 * ter bloqueado. Isso nunca pode passar por "ficheiro estragado", "não há" ou "lista vazia": um
 * cofre trancado não é um cofre vazio (e o que se escrevesse a seguir apagaria o que lá está).
 */
class LockedStoreTest {
    private val pass = "cavalo bateria agrafo correto".toCharArray()

    private class LockingStore : Store {
        val inner = MemoryStore()
        var locked = false
        /** Só as leituras falham: o telemóvel desbloqueou entre a leitura e a escrita. */
        var readsLocked = false
        override fun names() = inner.names()
        override fun read(name: String): ByteArray? {
            if (locked || readsLocked) throw StoreLockedException()
            return inner.read(name)
        }
        override fun write(name: String, data: ByteArray) {
            if (locked) throw StoreLockedException()
            inner.write(name, data)
        }
        override fun delete(name: String) = inner.delete(name)
    }

    @Test
    fun aLockedStoreIsNeverReadAsBrokenEmptyOrUnknown() {
        val store = LockingStore()
        val ana = Vault(store)
        val anaKey = Pgp.generate("Ana", "ana@exemplo.pt", pass).also { ana.addMyKey(it) }
        val rui = Pgp.generate("Rui", "rui@exemplo.pt", pass)
        val ruiFpr = Pgp.fingerprint(rui)
        val eva = Pgp.generate("Eva", "eva@exemplo.pt", pass)
        ana.importContacts(listOf(Pgp.certificateOf(rui), Pgp.certificateOf(eva)))
        ana.setVerified(ruiFpr, true)
        ana.setCode(ruiFpr, "o gato comeu a sardinha".toCharArray())
        ana.saveNote(null, "nota", "texto da nota")
        ana.setPrefs(mapOf("compactAlways" to "1"))
        ana.setPin("246813".toCharArray())
        val ruiVault = Vault(MemoryStore()).apply {
            addMyKey(rui)
            importContacts(listOf(Pgp.certificateOf(anaKey)))
            setVerified(Pgp.fingerprint(anaKey), true)
            setCode(Pgp.fingerprint(anaKey), "o gato comeu a sardinha".toCharArray())
        }
        val coded = ruiVault.disguise(ruiVault.encrypt("olá", listOf(Pgp.fingerprint(anaKey)), ruiFpr, false, null), Disguise.Style.Code, Pgp.fingerprint(anaKey))

        store.locked = true
        val fresh = Vault(store) // como a app acabada de abrir: nada em memória
        assertFailsWith<StoreLockedException> { fresh.snapshot() }
        assertFailsWith<StoreLockedException> { fresh.hasPin() }
        assertFailsWith<StoreLockedException> { fresh.prefs() }
        assertFailsWith<StoreLockedException> { fresh.reveal(coded) }
        assertFailsWith<StoreLockedException> { fresh.exportBackup("frase só para o backup".toCharArray()) }
        assertFailsWith<StoreLockedException> { fresh.setVerified(Pgp.fingerprint(eva), true) }
        assertFailsWith<StoreLockedException> { fresh.importContacts(listOf(Pgp.certificateOf(rui))) }

        // O pior caso: a leitura falha com o telemóvel bloqueado e a escrita a seguir já passaria.
        // Nada se pode escrever com base numa leitura que não aconteceu.
        store.locked = false
        store.readsLocked = true
        val racing = Vault(store)
        assertFailsWith<StoreLockedException> { racing.setVerified(Pgp.fingerprint(eva), true) }
        assertFailsWith<StoreLockedException> { racing.setPrefs(mapOf("otherThing" to "1")) }
        assertFailsWith<StoreLockedException> { racing.importContacts(listOf(Pgp.certificateOf(rui))) }

        store.readsLocked = false
        val after = Vault(store)
        val s = after.snapshot()
        assertTrue(s.broken.isEmpty(), s.broken.toString())
        assertEquals(mapOf(ruiFpr to true, Pgp.fingerprint(eva) to false), s.contacts.associate { it.info.fingerprint to it.verified })
        assertTrue(s.contacts.first { it.info.fingerprint == ruiFpr }.codeCheck != null)
        assertEquals(1, s.notes.size)
        assertEquals("1", after.prefs()["compactAlways"])
        assertTrue(after.hasPin())
        assertEquals("olá", after.decrypt(coded, pass).text)
    }
}
