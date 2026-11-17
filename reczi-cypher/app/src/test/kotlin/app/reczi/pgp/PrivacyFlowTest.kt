package app.reczi.pgp

import android.app.AlertDialog
import android.content.Context
import android.os.Looper
import android.view.View
import android.view.ViewGroup
import android.widget.CheckBox
import android.widget.EditText
import android.widget.Spinner
import android.widget.TextView
import app.reczi.pgp.core.Pgp
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
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

/**
 * Versão 1.4.3, na app: o que estava em claro nas preferências do Android passa para o cofre, o
 * que se escolhe ao encriptar para alguém fica no cofre, e o ecrã fica escondido dos serviços de
 * acessibilidade que não são ferramentas de acessibilidade (Android 14+).
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class PrivacyFlowTest {
    private lateinit var controller: ActivityController<MainActivity>
    private val activity get() = controller.get()
    private val app get() = RuntimeEnvironment.getApplication()
    private val pass = "cavalo bateria agrafo correto".toCharArray()
    private lateinit var ruiFpr: String
    private lateinit var myFpr: String

    @Before
    fun setUp() {
        val key = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
        shadowOf(app).grantPermissions("android.permission.HIDE_OVERLAY_WINDOWS")
        app.noBackupFilesDir.listFiles()?.forEach { it.deleteRecursively() }
        Vaults.useForTests(app, key)
        val v = Vaults.vault(app)
        val me = Pgp.generate("Ana", "ana@exemplo.pt", pass).also { v.addMyKey(it) }
        val rui = Pgp.generate("Rui", "rui@exemplo.pt", pass)
        v.importContacts(listOf(Pgp.certificateOf(rui)))
        myFpr = Pgp.fingerprint(me)
        ruiFpr = Pgp.fingerprint(rui)
        v.setVerified(ruiFpr, true)
    }

    private fun prefs() = app.getSharedPreferences("prefs", Context.MODE_PRIVATE)

    private fun launch() {
        controller = Robolectric.buildActivity(MainActivity::class.java).setup()
        waitIdle()
    }

    private fun idle() = shadowOf(Looper.getMainLooper()).idle()

    private fun waitIdle(timeoutMs: Long = 60_000) {
        val end = System.currentTimeMillis() + timeoutMs
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

    private fun screen(): List<View> = all(activity.window.decorView).filter { it.isShown }

    private fun dialogs(): List<AlertDialog> = ShadowDialog.getShownDialogs().filterIsInstance<AlertDialog>().filter { it.isShowing }

    private fun click(text: String) {
        val v = screen().filterIsInstance<TextView>().firstOrNull { it.text.toString() == text }
        assertNotNull("Não encontrei \"$text\" no ecrã", v)
        assertTrue(v!!.performClick())
        idle()
    }

    private fun dismissAlerts() {
        repeat(5) {
            val d = dialogs().lastOrNull() ?: return
            (d.getButton(AlertDialog.BUTTON_POSITIVE) ?: return).performClick()
            idle()
        }
    }

    private fun formatSpinner(): Spinner =
        screen().filterIsInstance<Spinner>().first { s -> (0 until s.adapter.count).any { s.adapter.getItem(it).toString() == LYRICS } }

    private fun selectedFormat(): String = formatSpinner().selectedItem.toString()

    @Test
    fun oldPlainPrefsMoveIntoTheVault() {
        prefs().edit()
            .putInt("fmt-$ruiFpr", 7).putBoolean("usecode-$ruiFpr", true)
            .putStringSet("backedUp", setOf(myFpr))
            .putInt("format", 7).putBoolean("useCode", false)
            .putBoolean("welcomed", true)
            .commit()
        launch()
        // Nas preferências do Android já não fica nenhum fingerprint nem a escolha do formato.
        val left = prefs().all
        assertEquals(setOf("welcomed"), left.keys)
        val p = Vaults.vault(app).prefs()
        assertEquals("7", p["fmt-$ruiFpr"])
        assertEquals("1", p["usecode-$ruiFpr"])
        assertEquals("1", p["backedup-$myFpr"])
        assertEquals("7", p["format"])
        assertFalse(p.containsKey("useCode"))
        // E a app continua a saber que a chave tem backup e que o formato era a letra de rap.
        dismissAlerts()
        click("☰")
        click("✉  Escrever (encriptar)")
        assertEquals(LYRICS, selectedFormat())
    }

    @Test
    fun choicesForAContactStayInTheVault() {
        launch()
        dismissAlerts()
        click("☰")
        click("✉  Escrever (encriptar)")
        screen().filterIsInstance<CheckBox>().first { it.text.startsWith("Rui") }.performClick()
        screen().filterIsInstance<CheckBox>().first { it.text.toString() == "Assinar com a minha chave" }.performClick() // sem palavra-passe
        val spinner = formatSpinner()
        spinner.setSelection((0 until spinner.adapter.count).first { spinner.adapter.getItem(it).toString() == LYRICS })
        idle()
        screen().filterIsInstance<EditText>().first { it.hint?.toString() == "Mensagem" }.setText("encontro às 8")
        click("Encriptar")
        waitIdle()
        assertTrue(screen().filterIsInstance<EditText>().any { it.text.lines().size > 20 })

        val p = Vaults.vault(app).prefs()
        assertEquals("7", p["fmt-$ruiFpr"])
        assertEquals("7", p["format"])
        // Nada sobre o Rui fora do cofre: nem nas preferências do Android nem nos nomes dos ficheiros.
        assertFalse(prefs().all.toString().contains(ruiFpr))
        val files = app.noBackupFilesDir.walkTopDown().filter { it.isFile }.map { it.name }.toList()
        assertFalse(files.toString(), files.any { it.contains(ruiFpr) || it.contains(myFpr) || it == "panic" || it == "pin" })

        // A app aberta de novo lembra-se da escolha (vinda do cofre).
        controller.pause().stop().destroy()
        launch()
        dismissAlerts()
        click("☰")
        click("✉  Escrever (encriptar)")
        assertEquals(LYRICS, selectedFormat())
    }

    @Test
    fun panicPinLeavesNothingBehind() {
        val v = Vaults.vault(app)
        v.setPin("1234".toCharArray())
        v.setPanicPin("9999".toCharArray())
        v.setPrefs(mapOf("fmt-$ruiFpr" to "7", "format" to "7"))
        prefs().edit().putBoolean("welcomed", true).putBoolean("compact", true).commit()
        launch()
        assertTrue(screen().filterIsInstance<TextView>().any { it.text.toString() == "Reczi cypher bloqueada" })
        screen().filterIsInstance<EditText>().first { it.hint?.toString() == "PIN" }.setText("9999")
        click("Entrar")
        waitIdle()
        // Nada no armazenamento da app: nem ficheiros do cofre, nem preferências.
        val files = app.noBackupFilesDir.walkTopDown().filter { it.isFile }.map { it.name }.toList()
        assertEquals(emptyList<String>(), files)
        assertTrue(prefs().all.toString(), prefs().all.isEmpty() || prefs().all.keys == setOf("welcomed"))
        assertTrue(Vaults.vault(app).prefs().isEmpty())
        assertTrue(Vaults.vault(app).snapshot().myKeys.isEmpty())
        // E o ecrã de encriptar não guarda a escolha de antes.
        dismissAlerts()
        click("☰")
        click("✉  Escrever (encriptar)")
        assertEquals("PGP normal", selectedFormat())
        assertFalse(screen().filterIsInstance<CheckBox>().first { it.text.startsWith("Modo compacto") }.isChecked)
    }

    @Test
    fun screenIsHiddenFromAccessibilitySpyware() {
        launch()
        assertTrue(activity.window.decorView.isAccessibilityDataSensitive)
        // Os diálogos são janelas à parte: também.
        click("? Ajuda")
        val d = dialogs().last()
        assertTrue(d.window!!.decorView.isAccessibilityDataSensitive)
        // O conteúdo herda (as vistas ficam em "automático" e seguem a janela).
        assertTrue(screen().filterIsInstance<TextView>().first().isAccessibilityDataSensitive)
    }

    private companion object {
        const val LYRICS = "Disfarçado: letra de rap"
    }
}
