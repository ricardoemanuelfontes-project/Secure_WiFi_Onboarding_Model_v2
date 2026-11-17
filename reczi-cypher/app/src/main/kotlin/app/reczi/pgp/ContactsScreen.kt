package app.reczi.pgp

import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.TextView
import app.reczi.pgp.core.Contact
import app.reczi.pgp.core.Pgp
import app.reczi.pgp.MainActivity.Companion.KIND_PUBLIC
import app.reczi.pgp.MainActivity.Companion.KIND_QR_PUBLIC

/** Chaves públicas de outras pessoas. */
internal class ContactsScreen(a: MainActivity) : Screen(a, "Contactos") {
    val input = textArea("Cola aqui a chave pública de alguém (normal ou disfarçada)", 4, mono = true)
    private val list = column(0)
    private val col = column()
    override val view: View = scroll(col)
    override val help get() =
        "Aqui guardas as chaves PÚBLICAS das pessoas a quem queres escrever.\n\n" +
            "Convidar: envia a tua chave pública com instruções para quem ainda não usa a app.\n" +
            "1. Importa a chave: cola o texto que te enviaram, abre um ficheiro, ou lê o QR do telemóvel da pessoa. " +
            "Se a chave dela for grande (RSA), o QR vem em vários códigos: lê-os um a um, a app diz quais faltam.\n" +
            "2. Verifica: comparem a impressão digital (as letras e números) em pessoa ou por chamada. Serve para teres a certeza de que " +
            "a chave é mesmo dela e não de alguém a meio. Só depois podes encriptar para esse contacto.\n\n" +
            "Conversa: abre as Mensagens já viradas para esse contacto, com o formato e o código secreto que usaste da última vez.\n\n" +
            "Código secreto (opcional): uma frase combinada entre os dois, que fecha as mensagens disfarçadas com uma segunda camada. " +
            "Os algarismos de confirmação têm de ser iguais nos dois telemóveis. Se mudarem a frase, as mensagens antigas com código deixam de abrir."

    init {
        col.addView(heading("Adicionar destinatário"))
        col.addView(button("Convidar alguém (envia a tua chave com instruções)…") { invite() })
        col.addView(input)
        col.addView(buttonRow(
            button("Colar") { input.setText(a.pasteText()) },
            button("De ficheiro…") { a.openFile(KIND_PUBLIC) },
            guard(primaryButton("Importar") { importPublic(input.text.toString().toByteArray()) }),
        ))
        col.addView(button("Ler QR do telemóvel do contacto") { a.scanQr(KIND_QR_PUBLIC) })
        col.addView(heading("Destinatários"))
        col.addView(list)
    }

    override fun refresh() {
        list.removeAllViews()
        val contacts = a.snap.contacts.sortedBy { it.info.userId.lowercase() }
        if (contacts.isEmpty()) list.addView(label("Ainda não tens destinatários."))
        contacts.forEach { list.addView(contactCard(it)) }
    }

    /** Partilha a tua chave pública com um texto que explica à outra pessoa o que fazer. */
    private fun invite() {
        val mine = a.snap.myKeys.firstOrNull { it.info.canEncrypt }
            ?: return a.alert("Convidar", "Cria primeiro a tua chave em ☰ > As minhas chaves.")
        a.share(
            "Olá! Quero trocar mensagens encriptadas contigo com a app Reczi cypher.\n\n" +
                "1. Instala o Reczi cypher (eu envio-te a app).\n" +
                "2. Em ☰ > As minhas chaves, cria a tua chave.\n" +
                "3. Partilha esta mensagem inteira para o Reczi cypher (ou copia-a e usa \"Colar e detetar\") e carrega em Importar: " +
                "a minha chave fica nos teus Contactos.\n" +
                "4. Envia-me a tua chave: Chaves > Partilhar pública.\n" +
                "5. Depois confirmamos as impressões digitais por chamada ou em pessoa.\n\n" +
                "A minha chave (${mine.info.userId}):\n\n" + Pgp.armor(Pgp.certificateOf(mine.ring))
        )
    }

    private fun contactCard(c: Contact): View {
        val v = card()
        v.addView(nameView(c.info.userId))
        v.addView(fingerprintView(c.info.fingerprint))
        val (validText, validColor) = a.validity(c.info)
        v.addView(TextView(a).apply { text = validText; validColor?.let { setTextColor(it) } })
        v.addView(TextView(a).apply {
            text = if (c.verified) "✔ Verificada" else "NÃO verificada - ainda não podes encriptar para esta chave"
            setTextColor(if (c.verified) green else orange)
        })
        if (c.codeCheck != null) v.addView(TextView(a).apply {
            text = if (c.codeIsOld) {
                "Código secreto combinado com uma versão antiga (confirmação: ${c.codeCheck}). Funciona, mas é mais fraco: " +
                    "combinem-no de novo, os dois com a versão 1.4.6 ou mais recente (pode ser a mesma frase)."
            } else {
                "✔ Código secreto combinado (confirmação: ${c.codeCheck})"
            }
            setTextColor(if (c.codeIsOld) orange else green)
        })
        if (c.verified && c.info.canEncrypt) v.addView(primaryButton("Conversa") { a.messages.converse(c.info.fingerprint) })
        if (c.verified) v.addView(buttonRow(*listOfNotNull(
            button(if (c.codeCheck == null) "Código secreto…" else "Mudar código…") { a.askSecretCode(c) },
            if (c.codeCheck == null) null else button("Tirar código") {
                a.confirm("Tirar código secreto", "Deixas de conseguir abrir as mensagens de ${c.info.userId} enviadas com código secreto.", "Tirar") {
                    a.change("A guardar…", { a.vault.clearCode(c.info.fingerprint) })
                }
            },
        ).toTypedArray()))
        val row = LinearLayout(a).apply { orientation = LinearLayout.HORIZONTAL }
        if (!c.verified) row.addView(button("Verificar…") { a.showFingerprintAndVerify(c.info) },
            LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        row.addView(button("Remover") {
            a.confirm("Remover", "Remover a chave pública de ${c.info.userId}?", "Remover") {
                a.change("A remover…", { a.vault.deleteContact(c.info.fingerprint) })
            }
        }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        v.addView(row)
        return v
    }

    fun importPublic(data: ByteArray) {
        if (data.isEmpty()) return
        a.change("A importar…", {
            // Uma chave disfarçada pela app volta primeiro a PGP normal.
            // Uma chave no meio de outro texto (um convite com instruções): fica só a chave.
            val text = String(data, Charsets.UTF_8)
            val plain = a.vault.reveal(text)?.armored?.toByteArray()
                ?: if ("BEGIN PGP PUBLIC KEY BLOCK" in text) Pgp.extractPublicKeys(text).toByteArray() else data
            a.vault.importContacts(Pgp.parseCertificates(plain))
        }) { r ->
            input.setText("")
            val first = r.added.firstNotNullOfOrNull { fpr -> a.snap.contacts.firstOrNull { it.info.fingerprint == fpr } }
            val verify = { if (first != null) a.showFingerprintAndVerify(first.info) }
            when {
                r.rejected.isNotEmpty() -> a.alert("Algumas chaves foram recusadas", r.rejected.joinToString("\n"), verify)
                first != null -> verify()
                else -> a.alert("Importar", "A chave já existia e foi atualizada (ou era uma chave tua).")
            }
        }
    }
}
