package app.reczi.pgp

import android.graphics.Typeface
import android.view.View
import android.view.ViewGroup
import android.widget.FrameLayout
import android.widget.LinearLayout
import app.reczi.pgp.MainActivity.Companion.TAB_MESSAGES

/**
 * Mensagens: junta "Escrever" (encriptar) e "Ler" (desencriptar) num só separador, com o
 * "Colar e detetar" por cima. Numa conversa, fica virado para um contacto.
 */
internal class MessagesScreen(a: MainActivity) : Screen(a, "Mensagens") {
    /** Abre em Escrever: o que se recebe chega a Ler sozinho (Colar e detetar, partilha, Conversa). */
    var writing = true
        private set
    /** Contacto da conversa aberta (botão "Conversa" nos Contactos), se houver. */
    private var conversation: String? = null
    private val banner = column(0)
    private val readTab = button("Ler (desencriptar)") { open(write = false) }
    private val writeTab = button("Escrever (encriptar)") { open(write = true) }
    private val body = FrameLayout(a)
    override val view: View = LinearLayout(a).apply {
        orientation = LinearLayout.VERTICAL
        val top = column().apply { setPadding(dp(16), dp(8), dp(16), 0) }
        // A largura fica curta para não ficar por baixo do botão "? Ajuda".
        top.addView(button("Colar e detetar") { a.pasteAndRoute() }, LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT))
        top.addView(banner)
        top.addView(buttonRow(readTab, writeTab))
        addView(top)
        addView(body, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))
    }
    override val help get() =
        "\"Colar e detetar\" vê o que copiaste noutra app: uma mensagem vai para Ler, uma chave para os Contactos, um texto normal para Escrever.\n\n" +
            (if (writing) "ESCREVER\n" + a.enc.help else "LER\n" + a.dec.help)

    fun open(write: Boolean) {
        writing = write
        a.show(TAB_MESSAGES)
    }

    /** Abre uma conversa: Escrever já com este contacto, e um atalho para colar o que ele enviou. */
    fun converse(fingerprint: String) {
        conversation = fingerprint
        a.enc.replyTo(fingerprint)
        open(write = true)
    }

    override fun refresh() {
        banner.removeAllViews()
        val c = a.snap.contacts.firstOrNull { it.info.fingerprint == conversation && it.verified }
        if (c == null) {
            conversation = null
        } else {
            banner.addView(nameView("Conversa com ${c.info.userId}"))
            banner.addView(buttonRow(
                button("Colar o que recebi") {
                    val text = a.pasteText().trim()
                    if (text.isEmpty()) return@button a.alert("Colar", "A área de transferência está vazia. Copia primeiro a mensagem na outra app.")
                    a.dec.setMessage(text)
                    open(write = false)
                    a.dec.decrypt()
                },
                button("Responder") { a.enc.replyTo(c.info.fingerprint); open(write = true) },
                button("Sair") { conversation = null; refresh() },
            ))
        }
        a.titleView.text = if (writing) "Escrever (encriptar)" else "Ler (desencriptar)"
        val active = if (writing) a.enc else a.dec
        if (body.getChildAt(0) !== active.view) {
            body.removeAllViews()
            body.addView(active.view)
        }
        active.refresh()
        for ((b, on) in listOf(readTab to !writing, writeTab to writing)) {
            b.setTypeface(null, if (on) Typeface.BOLD else Typeface.NORMAL)
            b.alpha = if (on) 1f else 0.6f
        }
    }

    override fun clearSensitive() {
        a.enc.clearSensitive()
        a.dec.clearSensitive()
    }
}
