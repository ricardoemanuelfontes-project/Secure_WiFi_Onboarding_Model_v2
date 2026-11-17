package app.reczi.pgp

import android.app.AlertDialog
import android.content.Context
import android.os.Looper
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.TextView
import app.reczi.pgp.core.Pgp
import app.reczi.pgp.core.StoreLockedException
import app.reczi.pgp.core.Vault
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.android.controller.ActivityController
import org.robolectric.annotation.Config
import org.robolectric.shadows.ShadowDialog
import java.io.File
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

/**
 * Chaves de faz-de-conta que se portam como o Keystore do Android 15: as "só com o telemóvel
 * desbloqueado" recusam-se a funcionar com ele bloqueado. [supported] a false imita o Android 14.
 */
internal class MemoryVaultKeys(var supported: Boolean = true) : VaultKeys {
    var locked = false
    /** Para imitar outra falha do Keystore (não o bloqueio). */
    var broken = false
    val keys = LinkedHashMap<String, SecretKey>()
    val unlockedOnly = HashSet<String>()

    override fun get(alias: String): SecretKey? {
        check(!broken) { "o Keystore não respondeu" }
        return keys[alias]
    }

    override fun create(alias: String, unlockedOnly: Boolean): SecretKey {
        val raw = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
        val key = if (unlockedOnly) LockableKey(raw) { locked } else raw
        if (unlockedOnly) this.unlockedOnly += alias
        keys[alias] = key
        return key
    }

    override fun delete(alias: String) {
        keys.remove(alias)
        unlockedOnly.remove(alias)
    }

    override fun aliases() = keys.keys.toList()
    override fun deviceLocked() = locked
    override val unlockedOnlySupported get() = supported
}

/** Uma chave que, como as do Keystore com setUnlockedDeviceRequired, não se usa com o telemóvel bloqueado. */
private class LockableKey(private val inner: SecretKey, private val locked: () -> Boolean) : SecretKey {
    override fun getAlgorithm() = "AES"
    override fun getFormat() = "RAW"
    override fun getEncoded(): ByteArray {
        check(!locked()) { "telemóvel bloqueado" }
        return inner.encoded
    }
}

/**
 * Versão 1.4.6: no Android 15 ou mais recente, a chave do cofre só funciona com o telemóvel
 * desbloqueado. Nas versões anteriores não se usa (tirar o bloqueio de ecrã apagava-a).
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class UnlockedKeyTest {
    private val app get() = RuntimeEnvironment.getApplication()
    private val base get() = app.noBackupFilesDir
    private val dir get() = File(base, "vault")
    private val fpr = "0123456789ABCDEF0123456789ABCDEF01234567"
    private val names = listOf("pub-$fpr", "note-$fpr", "pin", "prefs", "verified")

    @Before
    fun clean() {
        base.listFiles()?.forEach { it.deleteRecursively() }
        app.getSharedPreferences("prefs", Context.MODE_PRIVATE).edit().clear().commit()
    }

    private fun fill(s: KeystoreStore) = names.forEach { s.write(it, "dados de $it".toByteArray()) }

    private fun assertAllThere(s: KeystoreStore) {
        assertEquals(names.sorted(), s.names())
        names.forEach { assertEquals("dados de $it", String(s.read(it)!!)) }
    }

    private fun aliasFile() = File(base, "vault-alias").takeIf { it.exists() }?.readText()

    private fun nothingPutAside() = assertFalse("nada vai para o lado", File(base, "vault-avariados").exists())

    @Test
    fun newVaultOnAndroid15GetsAKeyThatNeedsTheUnlockedPhone() {
        val keys = MemoryVaultKeys()
        val s = KeystoreStore(app, keys)
        fill(s)
        assertTrue(keys.aliases().single().startsWith("reczi-pgp-vault-u"))
        assertEquals(keys.aliases().single(), aliasFile())
        assertTrue(s.isUnlockedOnly())

        keys.locked = true
        assertThrows(StoreLockedException::class.java) { s.read("pin") }
        assertThrows(StoreLockedException::class.java) { s.write("pin", "outro".toByteArray()) }
        assertThrows(StoreLockedException::class.java) { KeystoreStore(app, keys).names() }
        nothingPutAside()

        keys.locked = false
        assertAllThere(KeystoreStore(app, keys))
    }

    @Test
    fun beforeAndroid15TheKeyStaysAsItWas() {
        val keys = MemoryVaultKeys(supported = false)
        val s = KeystoreStore(app, keys)
        fill(s)
        assertFalse(keys.aliases().single().startsWith("reczi-pgp-vault-u"))
        assertFalse(s.isUnlockedOnly())
        assertTrue(keys.unlockedOnly.isEmpty())
    }

    @Test
    fun existingVaultMovesToTheNewKeyWithoutLosingAnything() {
        val keys = MemoryVaultKeys(supported = false)
        fill(KeystoreStore(app, keys))
        val oldAlias = keys.aliases().single()
        val before = dir.listFiles()!!.map { it.name }.sorted()

        // O telemóvel passa para o Android 15: na abertura seguinte, o cofre muda de chave.
        keys.supported = true
        val s = KeystoreStore(app, keys)
        assertAllThere(s)
        val newAlias = keys.aliases().single()
        assertTrue(newAlias.startsWith("reczi-pgp-vault-u"))
        assertFalse("a chave antiga é destruída", oldAlias in keys.aliases())
        assertEquals(newAlias, aliasFile())
        assertFalse(File(base, "vault-alias-next").exists())
        assertEquals("os mesmos ficheiros, agora com a chave nova", before, dir.listFiles()!!.map { it.name }.sorted())
        assertTrue(s.isUnlockedOnly())
        nothingPutAside()

        keys.locked = true
        assertThrows(StoreLockedException::class.java) { KeystoreStore(app, keys).read("pin") }
        keys.locked = false
        assertAllThere(KeystoreStore(app, keys))
    }

    @Test
    fun aChangeOfKeyInterruptedHalfWayLosesNothingAndCarriesOn() {
        val keys = MemoryVaultKeys(supported = false)
        fill(KeystoreStore(app, keys))
        val oldAlias = keys.aliases().single()
        // A app "pára" depois de reescrever as entradas e antes do índice (o último a ser reescrito):
        // no lugar do ficheiro temporário do índice está uma pasta.
        val blocker = File(dir, "v2-index.tmp").apply { mkdirs(); File(this, "x").writeText("x") }

        keys.supported = true
        val first = KeystoreStore(app, keys)
        assertEquals(names.sorted(), first.names()) // a mudança falhou, mas lê-se tudo
        assertTrue("a mudança fica a meio", File(base, "vault-alias-next").exists())
        assertEquals(oldAlias, aliasFile() ?: "reczi-pgp-vault") // (um cofre antigo usa o nome por omissão)
        assertEquals(2, keys.aliases().size)
        assertAllThere(first)
        // A meio, com o telemóvel bloqueado, o cofre está bloqueado (não estragado).
        keys.locked = true
        assertThrows(StoreLockedException::class.java) { KeystoreStore(app, keys).read("pin") }
        nothingPutAside()
        keys.locked = false

        // Na abertura seguinte, continua e acaba.
        blocker.deleteRecursively()
        val again = KeystoreStore(app, keys)
        assertAllThere(again)
        assertFalse(File(base, "vault-alias-next").exists())
        assertEquals(listOf(aliasFile()), keys.aliases())
        assertTrue(again.isUnlockedOnly())
        nothingPutAside()
    }

    @Test
    fun aLockedPhoneIsNeverABrokenVault() {
        val keys = MemoryVaultKeys()
        val v = Vault(KeystoreStore(app, keys))
        val key = Pgp.generate("Ana", "ana@exemplo.pt", "cavalo bateria agrafo correto".toCharArray())
        v.addMyKey(key)
        v.importContacts(listOf(Pgp.certificateOf(Pgp.generate("Rui", "rui@exemplo.pt", "cavalo bateria agrafo correto".toCharArray()))))
        v.setVerified(v.contacts().single().info.fingerprint, true)
        v.setPin("246813".toCharArray())
        v.setPrefs(mapOf("compactAlways" to "1"))

        keys.locked = true
        val locked = Vault(KeystoreStore(app, keys))
        // Nada disto pode passar por "ficheiro estragado", "não há PIN" ou "lista vazia".
        assertThrows(StoreLockedException::class.java) { locked.snapshot() }
        assertThrows(StoreLockedException::class.java) { locked.hasPin() }
        assertThrows(StoreLockedException::class.java) { locked.prefs() }
        assertThrows(StoreLockedException::class.java) { locked.exportBackup("frase do backup comprida".toCharArray()) }
        // Sem o índice, também não se refaz nada às cegas.
        File(dir, "v2-index").delete()
        assertThrows(StoreLockedException::class.java) { Vault(KeystoreStore(app, keys)).snapshot() }
        nothingPutAside()

        keys.locked = false
        val open = Vault(KeystoreStore(app, keys))
        val s = open.snapshot()
        assertTrue(s.broken.isEmpty())
        assertEquals(1, s.myKeys.size)
        assertTrue(s.contacts.single().verified)
        assertTrue(open.hasPin())
        assertEquals("1", open.prefs()["compactAlways"])
    }

    // ------------------------------------------------------------------ a app

    private lateinit var controller: ActivityController<MainActivity>
    private val activity get() = controller.get()

    private fun idle() = shadowOf(Looper.getMainLooper()).idle()

    private fun waitIdle() {
        val end = System.currentTimeMillis() + 60_000
        while (true) {
            idle()
            Thread.sleep(30)
            idle()
            val busy = ShadowDialog.getShownDialogs().any { d -> d.isShowing && all(d.window!!.decorView).any { it is android.widget.ProgressBar } }
            if (!busy) return
            check(System.currentTimeMillis() < end) { "Demorou demasiado" }
        }
    }

    private fun all(v: View): List<View> =
        if (v is ViewGroup) listOf(v) + (0 until v.childCount).flatMap { all(v.getChildAt(it)) } else listOf(v)

    private fun dialogs(): List<AlertDialog> = ShadowDialog.getShownDialogs().filterIsInstance<AlertDialog>().filter { it.isShowing }

    private fun visibleText(): String =
        (all(activity.window.decorView).filter { it.isShown } + dialogs().flatMap { all(it.window!!.decorView) })
            .filterIsInstance<TextView>().joinToString("\n") { it.text.toString() }

    private fun click(text: String) {
        val v = (all(activity.window.decorView).filter { it.isShown } + dialogs().flatMap { all(it.window!!.decorView) })
            .filterIsInstance<TextView>().firstOrNull { it.text.toString() == text }
        assertNotNull("Não encontrei \"$text\"", v)
        v!!.performClick()
        idle()
        waitIdle()
    }

    private fun appWithPin(keys: MemoryVaultKeys) {
        shadowOf(app).grantPermissions("android.permission.HIDE_OVERLAY_WINDOWS")
        Vaults.useForTests(app, keys)
        val v = Vaults.vault(app)
        v.addMyKey(Pgp.generate("Anastácia Ferreirinha", "ana@exemplo.pt", "cavalo bateria agrafo correto".toCharArray()))
        v.setPin("246813".toCharArray())
        Vaults.useForTests(app, keys) // como uma app acabada de abrir: nada em memória
    }

    private fun pinScreen() = visibleText().contains("Reczi cypher bloqueada")

    /**
     * Ataque: abrir a app com o telemóvel bloqueado (p. ex. quando roda o ecrã por trás do bloqueio)
     * para ela não conseguir ler o PIN. Até à 1.4.5, não conseguir ler o PIN era o mesmo que não haver
     * PIN, e depois de desbloquear o telemóvel o cofre abria sem o pedir.
     */
    @Test
    fun openingWhileThePhoneIsLockedDoesNotSkipTheAppPin() {
        val keys = MemoryVaultKeys()
        appWithPin(keys)
        keys.locked = true
        controller = Robolectric.buildActivity(MainActivity::class.java).setup()
        waitIdle()
        assertTrue(visibleText(), visibleText().contains("Desbloqueia o telemóvel"))
        assertFalse(visibleText().contains("Anastácia"))

        // Desbloqueia o telemóvel e volta à app: pede o PIN da app, não abre o cofre.
        keys.locked = false
        controller.pause().stop()
        controller.start().resume()
        waitIdle()
        assertTrue(visibleText(), pinScreen())
        assertFalse(visibleText().contains("Anastácia"))
    }

    @Test
    fun aKeystoreErrorWhileReadingThePinDoesNotOpenTheVault() {
        val keys = MemoryVaultKeys()
        appWithPin(keys)
        keys.broken = true
        controller = Robolectric.buildActivity(MainActivity::class.java).setup()
        waitIdle()
        assertTrue(visibleText(), visibleText().contains("Não é possível abrir o cofre"))
        assertFalse(visibleText().contains("Anastácia"))
        keys.broken = false
        click("Tentar de novo")
        assertTrue(visibleText(), pinScreen())
    }

    @Test
    fun lockingThePhoneInTheMiddleOfAnOperationSaysSo() {
        val keys = MemoryVaultKeys()
        shadowOf(app).grantPermissions("android.permission.HIDE_OVERLAY_WINDOWS")
        Vaults.useForTests(app, keys)
        Vaults.vault(app).addMyKey(Pgp.generate("Ana", "ana@exemplo.pt", "cavalo bateria agrafo correto".toCharArray()))
        controller = Robolectric.buildActivity(MainActivity::class.java).setup()
        waitIdle()
        keys.locked = true
        Vaults.vault(app).clearCache()
        activity.change("…", { Vaults.vault(app).snapshot() })
        waitIdle()
        assertTrue(visibleText(), visibleText().contains("O telemóvel bloqueou a meio da operação"))
        nothingPutAside()
    }
}
