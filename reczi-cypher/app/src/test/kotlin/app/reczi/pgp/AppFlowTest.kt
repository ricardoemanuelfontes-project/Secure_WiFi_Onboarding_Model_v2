package app.reczi.pgp

import android.app.AlertDialog
import android.os.Looper
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.TextView
import app.reczi.pgp.core.Pgp
import org.junit.Assert.assertEquals
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
import javax.crypto.KeyGenerator

/**
 * Percursos principais da app, como um utilizador: criar a chave, encriptar para si próprio,
 * ler, assinar e verificar, e navegar pelo menu lateral. Corre no computador (Robolectric).
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class AppFlowTest {
    private lateinit var controller: ActivityController<MainActivity>
    private val activity get() = controller.get()
    private val pass = "cavalo bateria agrafo correto"

    @Before
    fun setUp() {
        val key = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
        val app = RuntimeEnvironment.getApplication()
        // Declarada no manifesto; o Robolectric não a concede sozinho.
        shadowOf(app).grantPermissions("android.permission.HIDE_OVERLAY_WINDOWS")
        Vaults.useForTests(app, key)
        controller = Robolectric.buildActivity(MainActivity::class.java).setup()
        waitIdle()
    }

    // ------------------------------------------------------------------ ajudas

    private fun idle() = shadowOf(Looper.getMainLooper()).idle()

    /** Espera que o trabalho em segundo plano acabe (o diálogo de progresso fecha-se). */
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

    private fun field(hint: String): EditText =
        screen().filterIsInstance<EditText>().first { it.hint?.toString() == hint }

    private fun textOnScreen(): String = screen().filterIsInstance<TextView>().joinToString("\n") { it.text.toString() }

    /** Fecha os avisos abertos (boas-vindas, chave criada...) carregando em OK. */
    private fun dismissAlerts() {
        repeat(5) {
            val d = dialogs().lastOrNull() ?: return
            (d.getButton(AlertDialog.BUTTON_POSITIVE) ?: return).performClick()
            idle()
        }
    }

    /** Escreve a palavra-passe no diálogo aberto e carrega em OK. */
    private fun typePassphrase(p: String = pass) {
        waitIdle() // a app pode estar a ver para que chave é a mensagem
        val d = dialogs().last()
        val f = all(d.window!!.decorView).filterIsInstance<EditText>().first()
        f.setText(p)
        d.getButton(AlertDialog.BUTTON_POSITIVE).performClick()
        idle()
        waitIdle()
    }

    private fun menu(item: String) {
        click("☰")
        click(item)
    }

    private fun createKey() {
        dismissAlerts()
        field("Nome").setText("Ana")
        field("Email").setText("ana@exemplo.pt")
        field("Palavra-passe (mín. 12 caracteres)").setText(pass)
        field("Repete a palavra-passe").setText(pass)
        click("Criar chave")
        waitIdle()
        assertTrue(dialogs().any { d -> all(d.window!!.decorView).filterIsInstance<TextView>().any { it.text.toString() == "Chave criada" } })
        dismissAlerts()
    }

    // ------------------------------------------------------------------ testes

    @Test
    fun withoutKeyWriteExplainsWhereToGo() {
        dismissAlerts()
        menu("✉  Escrever (encriptar)")
        assertTrue(textOnScreen().contains("Ainda não tens a tua chave nesta app"))
        click("Ir para Chaves")
        assertTrue(textOnScreen().contains("Criar uma chave nova"))
    }

    @Test
    fun createKeyEncryptToSelfAndRead() {
        createKey()
        menu("✉  Escrever (encriptar)")
        val me = screen().filterIsInstance<CheckBox>().first { it.text.startsWith("Eu: Ana") }
        me.performClick()
        assertTrue(me.isChecked)
        field("Mensagem").setText("olá, isto é um teste")
        click("Encriptar")
        typePassphrase() // assinar
        val out = screen().filterIsInstance<EditText>().map { it.text.toString() }.first { it.contains("BEGIN PGP MESSAGE") }
        assertTrue(!out.contains("Version:"))

        menu("📥  Ler (desencriptar)")
        field("Cola aqui a mensagem (normal ou disfarçada)").setText(out)
        click("Desencriptar")
        typePassphrase()
        val shown = textOnScreen()
        assertTrue(shown, shown.contains("olá, isto é um teste"))
        assertTrue(shown, shown.contains("VERIFICADA"))
    }

    @Test
    fun disguisedAsRapLyricsAndReadBack() {
        createKey()
        menu("✉  Escrever (encriptar)")
        screen().filterIsInstance<CheckBox>().first { it.text.startsWith("Eu: Ana") }.performClick()
        val label = "Disfarçado: letra de rap"
        val spinner = screen().filterIsInstance<android.widget.Spinner>().first { s -> (0 until s.adapter.count).any { s.adapter.getItem(it).toString() == label } }
        spinner.setSelection((0 until spinner.adapter.count).first { spinner.adapter.getItem(it).toString() == label })
        idle()
        assertTrue(textOnScreen().contains("barras rimadas"))
        field("Mensagem").setText("encontro às 8")
        click("Encriptar")
        typePassphrase() // assinar
        val out = screen().filterIsInstance<EditText>().map { it.text.toString() }.first { it.lines().size > 20 }
        assertTrue(!out.contains("PGP"))
        val shown = textOnScreen()
        assertTrue(shown, shown.contains(Regex("Tamanho: \\d+ barras, cerca de \\d+ palavras")))

        menu("📥  Ler (desencriptar)")
        field("Cola aqui a mensagem (normal ou disfarçada)").setText(out)
        click("Desencriptar")
        typePassphrase()
        assertTrue(textOnScreen().contains("encontro às 8"))
    }

    /**
     * Mensagem sem ids (como vêm os disfarces) para a segunda de duas chaves: a palavra-passe da
     * primeira abre a chave errada, a app explica e pede a da outra, em vez de dizer só "errada".
     */
    @Test
    fun hiddenRecipientWithTwoKeysAsksForTheOtherPassphrase() {
        createKey()
        val pass2 = "a segunda chave tem outra frase"
        val second = Pgp.generate("Ana pessoal", "ana@pessoal.pt", pass2.toCharArray())
        activity.vault.addMyKey(second)
        val msg = Pgp.encrypt("para a chave pessoal", listOf(Pgp.certificateOf(second)), null, null, hideRecipients = true)
        assertTrue(Pgp.recipientKeyIds(msg).all { it == 0L })

        menu("📥  Ler (desencriptar)")
        field("Cola aqui a mensagem (normal ou disfarçada)").setText(msg)
        click("Desencriptar")
        typePassphrase() // a da primeira chave
        val explained = dialogs().last()
        val words = all(explained.window!!.decorView).filterIsInstance<TextView>().joinToString("\n") { it.text.toString() }
        assertTrue(words, words.contains("escreve a palavra-passe da outra chave"))
        explained.getButton(AlertDialog.BUTTON_POSITIVE).performClick()
        idle()
        typePassphrase(pass2)
        assertTrue(textOnScreen().contains("para a chave pessoal"))
    }

    @Test
    fun signAndVerifyText() {
        createKey()
        menu("✍  Assinar e verificar")
        field("Texto a assinar").setText("ola eu sou o reczi")
        click("Assinar")
        typePassphrase()
        val signed = screen().filterIsInstance<EditText>().map { it.text.toString() }.first { it.contains("BEGIN PGP SIGNED MESSAGE") }
        assertTrue(!signed.contains("Version:"))
        field("Cola aqui o texto assinado que recebeste").setText(signed)
        click("Verificar")
        waitIdle()
        assertTrue(textOnScreen().contains("✔ VERIFICADA"))
        // Texto alterado: inválida.
        field("Cola aqui o texto assinado que recebeste").setText(signed.replace("reczi", "outro"))
        click("Verificar")
        waitIdle()
        assertTrue(textOnScreen().contains("ASSINATURA INVÁLIDA"))
    }

    @Test
    fun everyMenuEntryOpensItsScreen() {
        createKey()
        val expected = listOf(
            "✉  Escrever (encriptar)" to "Escrever (encriptar)",
            "📥  Ler (desencriptar)" to "Ler (desencriptar)",
            "✍  Assinar e verificar" to "Assinar e verificar",
            "👥  Contactos" to "Contactos",
            "🔑  As minhas chaves" to "Chaves",
            "📝  Notas" to "Notas",
            "⚙  Definições, bloqueio e backup" to "Definições",
        )
        for ((item, title) in expected) {
            menu(item)
            val bar = screen().filterIsInstance<TextView>().first { it.text.toString() == title }
            assertEquals(title, bar.text.toString())
        }
    }

    @Test
    fun keyMenusOpen() {
        createKey()
        menu("🔑  As minhas chaves")
        click("Mais opções…")
        val more = dialogs().last()
        val items = (0 until more.listView.adapter.count).map { more.listView.adapter.getItem(it).toString() }
        assertTrue(items.toString(), items.containsAll(listOf("Mudar a palavra-passe", "Revogar esta chave…", "Apagar esta chave…")))
        more.dismiss()
        idle()
        click("Backup…")
        val backup = dialogs().last()
        val b = (0 until backup.listView.adapter.count).map { backup.listView.adapter.getItem(it).toString() }
        assertTrue(b.toString(), b.any { it.startsWith("Certificado de revogação") })
    }
}
