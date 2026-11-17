package app.reczi.pgp

import android.net.Uri
import android.view.View
import android.widget.ArrayAdapter
import android.widget.ScrollView
import android.widget.Spinner
import android.widget.TextView
import app.reczi.pgp.core.Pgp
import app.reczi.pgp.MainActivity.Companion.KIND_SIGN_FILE
import app.reczi.pgp.MainActivity.Companion.KIND_VERIFY_DATA
import app.reczi.pgp.MainActivity.Companion.KIND_VERIFY_SIG
import app.reczi.pgp.MainActivity.Companion.MAX_SIGNATURE

/**
 * Assinar e verificar, sem encriptar: texto (p. ex. um email ao CERT) e ficheiros com a
 * assinatura à parte (.asc). Quem recebe vê o conteúdo; a assinatura prova que é teu e que
 * não foi alterado.
 */
internal class SignScreen(a: MainActivity) : Screen(a, "Assinar e verificar") {
    private val draft = textArea("Texto a assinar", 5)
    private val keySpinner = Spinner(a)
    private var signers = listOf<String>()
    private val output = textArea("", 5, mono = true).apply { keyListener = null; setTextIsSelectable(true) }
    private val outBox = column(0)
    private val check = textArea("Cola aqui o texto assinado que recebeste", 5, mono = true)
    private val checkResult = TextView(a).apply { setPadding(0, dp(8), 0, dp(8)); visibility = View.GONE }
    /** Verificar ficheiro: o ficheiro já escolhido, à espera da assinatura. */
    private var verifyData: Uri? = null
    private val col = column()
    override val view: View = scroll(col)
    override val help get() =
        "Aqui assinas SEM encriptar: quem recebe lê tudo, e a assinatura prova que foste tu e que nada foi alterado. " +
            "É o que se usa para emails a uma equipa de segurança (CERT), avisos públicos ou anexos.\n\n" +
            "• Assinar texto: escreve, carrega em Assinar e envia por email em texto simples (não em HTML). " +
            "Não mexas no texto depois de assinado, nem num espaço.\n" +
            "• Verificar texto: cola um texto assinado que recebeste. Só fica VERIFICADA se tiveres a chave da pessoa nos Contactos e a tiveres verificado.\n" +
            "• Assinar ficheiro: o ficheiro não muda; é criado um ficheiro à parte (nome.asc) que envias junto com ele.\n" +
            "• Verificar ficheiro: escolhe o ficheiro e depois a assinatura (.asc ou .sig).\n\n" +
            "Para quem recebe sem o Reczi cypher: no GnuPG, gpg --verify nome.asc nome."

    init {
        col.addView(heading("Assinar texto"))
        col.addView(draft)
        col.addView(keySpinner)
        col.addView(primaryButton("Assinar") { signText() })
        outBox.addView(label("Texto assinado (não está encriptado):"))
        outBox.addView(output)
        outBox.addView(buttonRow(
            button("Copiar") { a.copy(output.text.toString(), sensitive = false) },
            button("Partilhar") { a.share(output.text.toString()) },
        ))
        outBox.addView(button("Enviar por email…") { a.email(output.text.toString()) })
        outBox.visibility = View.GONE
        col.addView(outBox)

        col.addView(heading("Verificar texto assinado"))
        col.addView(check)
        col.addView(buttonRow(
            button("Colar") { check.setText(a.pasteText()) },
            primaryButton("Verificar") { verifyText() },
        ))
        col.addView(checkResult)

        col.addView(heading("Ficheiros"))
        col.addView(label("A assinatura fica num ficheiro à parte (.asc); o original não é alterado."))
        col.addView(button("Assinar um ficheiro…") { if (myKey() != null) a.openFile(KIND_SIGN_FILE) })
        col.addView(button("Verificar um ficheiro…") {
            a.alert("Verificar ficheiro", "Escolhe primeiro o ficheiro e depois a assinatura (.asc ou .sig).") { a.openFile(KIND_VERIFY_DATA) }
        })
    }

    override fun refresh() {
        val mine = a.snap.myKeys.map { it.info }.filter { it.canSign }
        signers = mine.map { it.fingerprint }
        val selected = keySpinner.selectedItemPosition
        keySpinner.adapter = ArrayAdapter(a, android.R.layout.simple_spinner_dropdown_item, mine.map { "Assinar como: ${it.userId}" })
        if (selected in mine.indices) keySpinner.setSelection(selected)
        keySpinner.visibility = if (mine.size > 1) View.VISIBLE else View.GONE
    }

    override fun clearSensitive() {
        draft.setText("")
        output.setText("")
        outBox.visibility = View.GONE
        check.setText("")
        checkResult.visibility = View.GONE
    }

    private fun myKey(): String? {
        val me = signers.getOrNull(keySpinner.selectedItemPosition.coerceAtLeast(0))
        if (me == null) {
            a.alert(
                "Assinar",
                if (a.snap.myKeys.isEmpty()) "Cria ou importa primeiro a tua chave em ☰ > As minhas chaves."
                else "A tua chave expirou ou foi revogada: já não pode assinar. Vê em ☰ > As minhas chaves.",
            )
        }
        return me
    }

    private fun signText() {
        val text = draft.text.toString()
        if (text.isBlank()) return a.alert("Assinar", "Escreve primeiro o texto.")
        val me = myKey() ?: return
        a.keyPassphrase("Assinar", "O texto NÃO fica encriptado: qualquer pessoa o consegue ler.\n\nPalavra-passe da tua chave:", me) { chars ->
            a.work("A assinar…", { try { a.vault.sign(text, me, chars) } finally { chars.fill('\u0000') } }) {
                output.setText(it)
                outBox.visibility = View.VISIBLE
                output.post { (view as ScrollView).smoothScrollTo(0, outBox.top) }
            }
        }
    }

    private fun verifyText() {
        val text = check.text.toString().trim()
        if (text.isEmpty()) return a.alert("Verificar", "Cola primeiro o texto assinado.")
        if (!Pgp.isSignedText(text)) {
            return a.alert("Verificar", "Isto não é um texto assinado (falta \"-----BEGIN PGP SIGNED MESSAGE-----\"). Se for uma mensagem encriptada, abre-a em ☰ > Ler.")
        }
        a.work("A verificar…", { a.vault.verify(text) }) { r ->
            val (msg, color) = a.signatureText(r)
            checkResult.text = msg
            checkResult.setTextColor(color)
            checkResult.visibility = View.VISIBLE
        }
    }

    /** Escolhido o ficheiro: pede a palavra-passe, assina e pergunta onde guardar a assinatura. */
    fun signFile(input: Uri) {
        val me = myKey() ?: return
        a.work("…", { a.fileName(input) }) { name ->
            a.keyPassphrase("Assinar ficheiro", "$name\n\nPalavra-passe da tua chave:", me) { chars ->
                a.work("A assinar o ficheiro…", {
                    try { a.contentResolver.openInputStream(input)!!.use { a.vault.signDetached(it, me, chars) } } finally { chars.fill('\u0000') }
                }) { sig -> a.saveText("$name.asc", sig) }
            }
        }
    }

    fun verifyPickSignature(data: Uri) {
        verifyData = data
        a.openFile(KIND_VERIFY_SIG)
    }

    fun verifyFile(signature: Uri) {
        val data = verifyData ?: return a.alert("Verificar ficheiro", "Escolhe primeiro o ficheiro e depois a assinatura.")
        verifyData = null
        a.work("A verificar o ficheiro…", {
            val sig = a.readUri(signature, MAX_SIGNATURE)
            a.fileName(data) to a.vault.verifyDetached({ a.contentResolver.openInputStream(data)!! }, sig)
        }) { (name, r) ->
            val (msg, _) = a.signatureText(r)
            a.alert("Verificar ficheiro", "$name\n\n$msg")
        }
    }
}
