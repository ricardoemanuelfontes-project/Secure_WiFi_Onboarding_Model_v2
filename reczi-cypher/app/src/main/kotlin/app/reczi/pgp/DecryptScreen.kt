package app.reczi.pgp

import android.net.Uri
import android.text.Editable
import android.text.TextUtils
import android.text.TextWatcher
import android.view.View
import android.widget.ScrollView
import android.widget.TextView
import app.reczi.pgp.core.DecryptResult
import app.reczi.pgp.core.OtherKeyError
import app.reczi.pgp.core.Pgp
import app.reczi.pgp.core.SignatureStatus
import app.reczi.pgp.MainActivity.Companion.KIND_FILE_DEC
import app.reczi.pgp.MainActivity.Companion.KIND_MESSAGE

internal class DecryptScreen(a: MainActivity) : Screen(a, "Desencriptar") {
    /** As tuas chaves para as quais o ficheiro a desencriptar foi feito. */
    var fileKeys: List<String>? = null
    private val input = textArea("Cola aqui a mensagem (normal ou disfarçada)", 5, mono = true)
    private val fileLabel = label("").apply { visibility = View.GONE }
    private var fileMessage: String? = null
    private val status = TextView(a).apply { setPadding(0, dp(8), 0, dp(8)) }
    // Não selecionável: copiar só pelo botão, que marca o texto como sensível e o limpa depois.
    private val output = TextView(a).apply { setTextIsSelectable(false); textSize = 16f }
    private var replyFpr: String? = null
    private val reply = button("Responder") {
        replyFpr?.let { fpr -> a.enc.replyTo(fpr); a.messages.open(write = true) }
    }.apply { visibility = View.GONE }
    private val outBox = column(0)
    private val col = column()
    override val view: View = scroll(col)
    override val help get() =
        "Cola aqui o que recebeste (ou partilha-o da outra app para o Reczi cypher) e carrega em Desencriptar. " +
            "A app pede a palavra-passe da tua chave e mostra a mensagem.\n\n" +
            "Por cima da mensagem aparece quem a assinou:\n" +
            "• ✔ VERIFICADA: veio de um contacto que verificaste.\n" +
            "• NÃO VERIFICADA / REMETENTE DESCONHECIDO: não há certeza de quem a enviou.\n" +
            "• ASSINATURA INVÁLIDA: foi alterada ou é falsa. Não confies.\n\n" +
            "Copiar apaga o texto da área de transferência ao fim de ~45 s. A mensagem desaparece do ecrã depois de 5 minutos fora da app.\n\n" +
            "Se disser que não reconhece a mensagem, pode ter vindo com código secreto: confirma os algarismos com o remetente, em Contactos."

    init {
        col.addView(heading("Mensagem encriptada"))
        col.addView(input)
        col.addView(fileLabel)
        col.addView(buttonRow(
            button("Colar") { setMessage(a.pasteText()) },
            button("De ficheiro…") { a.openFile(KIND_MESSAGE) },
            primaryButton("Desencriptar") { decrypt() },
        ))
        col.addView(label("Um texto só assinado (sem encriptar) também se verifica aqui."))
        col.addView(button("Desencriptar um ficheiro ou fotografia…") { a.openFile(KIND_FILE_DEC) })
        outBox.addView(heading("Mensagem original"))
        outBox.addView(status)
        outBox.addView(output)
        outBox.addView(buttonRow(
            button("Copiar (limpa após ~45 s)") { a.copy(output.text.toString(), sensitive = true) },
            button("Limpar") { clearSensitive() },
        ))
        outBox.addView(reply)
        outBox.visibility = View.GONE
        col.addView(outBox)
        input.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, n: Int, m: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, n: Int, m: Int) {}
            override fun afterTextChanged(s: Editable?) {
                if (!s.isNullOrEmpty()) { fileMessage = null; fileLabel.visibility = View.GONE }
            }
        })
    }

    override fun refresh() {}

    fun setMessage(text: String) {
        fileMessage = null
        fileLabel.visibility = View.GONE
        input.setText(text)
    }

    /** Mensagem de um ficheiro (armorada ou binária .gpg/.pgp); fica fora do campo de texto. */
    fun loadFile(bytes: ByteArray) {
        a.work("A ler a mensagem…", { Pgp.ensureArmored(bytes) }) { armored ->
            input.setText("")
            fileMessage = armored
            fileLabel.text = "Mensagem carregada do ficheiro (${bytes.size / 1024 + 1} KB)."
            fileLabel.visibility = View.VISIBLE
        }
    }

    override fun clearSensitive() {
        output.text = ""
        status.text = ""
        replyFpr = null
        reply.visibility = View.GONE
        outBox.visibility = View.GONE
    }

    fun decrypt() {
        val msg = fileMessage ?: input.text.toString().trim()
        if (msg.isEmpty()) return
        clearSensitive()
        if (Pgp.isSignedText(msg)) return a.work("A verificar a assinatura…", { a.vault.verify(msg) }) { showResult(it, signedOnly = true) }
        a.work("A verificar…", { a.vault.myKeysFor(msg) }) { forKeys ->
            if (forKeys.isEmpty()) return@work a.alert("Desencriptar", "Esta mensagem não foi encriptada para nenhuma das tuas chaves.")
            open(msg, forKeys, allowStored = true)
        }
    }

    /**
     * Com o destinatário escondido e várias chaves, a palavra-passe guardada (impressão digital) pode
     * abrir a chave errada: nesse caso pede-se a palavra-passe escrita, da outra chave.
     */
    private fun open(msg: String, forKeys: List<String>, allowStored: Boolean) {
        a.keyPassphrase("Desencriptar", "Palavra-passe da tua chave:", candidates = forKeys, allowStored = allowStored) { chars ->
            a.work("A desencriptar…", {
                try { runCatching { a.vault.decrypt(msg, chars) } } finally { chars.fill('\u0000') }
            }) { r ->
                val e = r.exceptionOrNull()
                when {
                    e == null -> showResult(r.getOrThrow())
                    e is OtherKeyError -> a.alert("Desencriptar", e.message.orEmpty()) { open(msg, forKeys, allowStored = false) }
                    else -> a.showError(e)
                }
            }
        }
    }

    /** Desencripta um ficheiro já escolhido para o destino já escolhido. */
    fun decryptFile(input: Uri, out: Uri) {
        a.keyPassphrase(
            "Desencriptar ficheiro", "Palavra-passe da tua chave:", onCancel = { a.work("…", { a.deleteDocument(out) }) {} }, candidates = fileKeys,
        ) { chars ->
            a.work("A desencriptar o ficheiro…", {
                try {
                    // Se falhar (ficheiro alterado, palavra-passe errada...), o que já foi escrito é apagado.
                    a.writeTo(out) { o -> a.vault.decryptFile({ a.contentResolver.openInputStream(input)!! }, o, chars) }
                } finally {
                    chars.fill('\u0000')
                }
            }) { r ->
                val original = if (r.text.isEmpty()) "" else "\n\nNome original: ${r.text}"
                a.alert("Ficheiro desencriptado", "Ficou guardado onde escolheste.$original\n\n${a.signatureText(r).first}")
            }
        }
    }

    private fun showResult(r: DecryptResult, signedOnly: Boolean = false) {
        val (text, color) = a.signatureText(r)
        status.text = when {
            signedOnly -> "$text\nEste texto não estava encriptado, só assinado."
            r.secretCodeWith == null -> text
            else -> "$text\n🔒 Veio fechada com o código secreto combinado com ${r.secretCodeWith}."
        }
        status.setTextColor(color)
        // Responder: só a quem assinou com uma chave que já verificaste e que ainda serve para encriptar.
        val signer = (r.signature as? SignatureStatus.Valid)?.fingerprint?.takeIf { r.signerVerified }
        val known = a.snap.contacts.firstOrNull { it.info.fingerprint == signer && it.verified && it.info.canEncrypt }?.info
            ?: a.snap.myKeys.firstOrNull { it.info.fingerprint == signer && it.info.canEncrypt }?.info
        replyFpr = known?.fingerprint
        reply.text = "Responder a ${known?.userId ?: ""}"
        reply.maxLines = 1
        reply.ellipsize = TextUtils.TruncateAt.END
        reply.visibility = if (known != null) View.VISIBLE else View.GONE
        output.text = r.text
        outBox.visibility = View.VISIBLE
        output.post { (view as ScrollView).smoothScrollTo(0, outBox.top) }
    }
}
