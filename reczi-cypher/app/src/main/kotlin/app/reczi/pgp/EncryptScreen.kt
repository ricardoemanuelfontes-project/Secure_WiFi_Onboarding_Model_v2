package app.reczi.pgp

import android.net.Uri
import android.text.TextUtils
import android.view.View
import android.widget.AdapterView
import android.widget.ArrayAdapter
import android.widget.CheckBox
import android.widget.ScrollView
import android.widget.Spinner
import app.reczi.pgp.core.Disguise
import app.reczi.pgp.MainActivity.Companion.FORMATS
import app.reczi.pgp.MainActivity.Companion.FORMAT_PGP
import app.reczi.pgp.MainActivity.Companion.KIND_FILE_ENC
import app.reczi.pgp.MainActivity.Companion.PREF_COMPACT
import app.reczi.pgp.MainActivity.Companion.TAB_KEYS
import app.reczi.pgp.MainActivity.Companion.VP_CONTACT_CODE
import app.reczi.pgp.MainActivity.Companion.VP_CONTACT_FORMAT
import app.reczi.pgp.MainActivity.Companion.VP_FORMAT
import app.reczi.pgp.MainActivity.Companion.VP_USE_CODE
import app.reczi.pgp.MainActivity.Companion.formatPosition

internal class EncryptScreen(a: MainActivity) : Screen(a, "Encriptar") {
    val draft = textArea("Mensagem", 5)
    private val recipients = column(0)
    private val boxes = mutableListOf<Pair<CheckBox, String>>()
    /** Destinatários a deixar escolhidos na próxima vez que o ecrã for mostrado (botão "Responder"). */
    private var preselect: Set<String>? = null
    private val myKeySpinner = Spinner(a)
    private var myFprs = listOf<String>()
    private val ownWarning = label("").apply { visibility = View.GONE }
    private val sign = CheckBox(a).apply { text = "Assinar com a minha chave"; isChecked = true }
    /** Modo compacto: sem assinatura e sem cópia para ti, para a mensagem (e o poema) ficar mais curta. */
    private val compact = CheckBox(a).apply {
        text = "Modo compacto: mensagem com cerca de metade do tamanho, mas sem assinatura e sem a conseguires reler"
        isChecked = a.prefs.getBoolean(PREF_COMPACT, false)
    }
    private val format = Spinner(a)
    private val formatHint = label("")
    /** Contacto cujo código secreto pode fechar a camada de fora (um só destinatário, com código). */
    private var codeFpr: String? = null
    private val useCode = CheckBox(a)
    /** O formato e o código escolhidos da última vez vêm do cofre, que só se lê depois de aberto. */
    private var choicesRestored = false
    private val output = textArea("", 5, mono = true).apply { keyListener = null; setTextIsSelectable(true) }
    private val outTitle = heading("Mensagem encriptada")
    private val outNote = label("").apply { visibility = View.GONE }
    private val outBox = column(0)
    /** Encriptar um ficheiro: o que estava escolhido quando se carregou no botão. */
    private var fileJob: Triple<List<String>, String, Boolean>? = null
    private val col = column()
    override val view: View = scroll(col)
    override val help get() =
        "Escreve a mensagem, escolhe para quem é e carrega em Encriptar. Depois copia ou partilha o resultado por onde quiseres " +
            "(mensagens, email...): só os destinatários o conseguem abrir.\n\n" +
            "• Para: só aparecem contactos verificados. \"Eu\" serve para guardares algo só para ti.\n" +
            "• Assinar: prova que foste tu a escrever; pede a tua palavra-passe.\n" +
            "• Formato: \"PGP normal\" abre em qualquer programa mas vê-se que é PGP; os \"Disfarçados\" não parecem PGP e só abrem no Reczi cypher. " +
            "Por baixo são todos iguais (a mesma encriptação); só muda a aparência: código (curto, parece um token), poema, crónica (as novidades da semana), " +
            "diário de viagem, relato de futebol ou letra de rap (a 2 é mais variada). Os textos corridos lêem-se como texto normal, mas são compridos: " +
            "depois de encriptar vês quantas frases ficou. Quem recebe não escolhe nada: a app reconhece o formato.\n" +
            "• Modo compacto: a mensagem fica com cerca de metade do tamanho, o que encurta muito o poema. Em troca não leva a tua assinatura " +
            "(o destinatário não confirma que é tua) e não fica encriptada para ti (não a consegues reler depois).\n" +
            "• Código secreto: opção desligada por omissão. Só aparece com um formato disfarçado e um só destinatário com quem combinaste " +
            "um código; marca-a quando a quiseres usar (fica lembrada para esse contacto).\n" +
            "• Palavra-passe: se a ligaste à impressão digital (☰ > As minhas chaves), basta o dedo ou o PIN do telemóvel.\n" +
            "• Só assinar (sem encriptar): está em ☰ > Assinar e verificar.\n" +
            "• Ficheiros e fotografias: usa os destinatários escolhidos acima e guarda um ficheiro .pgp."

    init {
        col.addView(heading("Mensagem"))
        col.addView(draft)
        col.addView(heading("Para"))
        col.addView(recipients)
        col.addView(label("A mensagem também é sempre encriptada para a tua chave, para a conseguires reler."))
        col.addView(ownWarning)
        col.addView(myKeySpinner)
        col.addView(sign)
        sign.isEnabled = !compact.isChecked
        compact.setOnClickListener {
            a.prefs.edit().putBoolean(PREF_COMPACT, compact.isChecked).apply()
            sign.isEnabled = !compact.isChecked
        }
        col.addView(compact)
        col.addView(heading("Formato"))
        format.adapter = ArrayAdapter(a, android.R.layout.simple_spinner_dropdown_item, FORMATS.map { it.label })
        format.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>?, v: View?, position: Int, id: Long) {
                // Só se guarda o que muda (o "PGP normal" é não ter nada guardado).
                val want = FORMATS[position].id.takeIf { it != FORMAT_PGP }?.toString()
                if (a.loaded && a.vaultPrefs()[VP_FORMAT] != want) a.setVaultPrefs(listOf(VP_FORMAT to want))
                updateCode()
                formatHint.text = FORMATS[position].hint
            }
            override fun onNothingSelected(parent: AdapterView<*>?) {}
        }
        col.addView(format)
        col.addView(formatHint)
        useCode.setOnClickListener { a.setVaultPrefs(listOf(VP_USE_CODE to if (useCode.isChecked) "1" else null)) }
        col.addView(useCode)
        col.addView(primaryButton("Encriptar") { encrypt() })
        col.addView(button("Encriptar um ficheiro ou fotografia…") { pickFile() })
        col.addView(label("Para assinar sem encriptar (por exemplo, um email ao CERT), usa ☰ > Assinar e verificar."))
        outBox.addView(outTitle)
        outBox.addView(outNote)
        outBox.addView(output)
        outBox.addView(buttonRow(
            button("Copiar") { a.copy(output.text.toString(), sensitive = false) },
            button("Partilhar") { a.share(output.text.toString()) },
            button("Limpar") { clearSensitive() },
        ))
        outBox.addView(button("Enviar por email…") { a.email(output.text.toString()) })
        outBox.visibility = View.GONE
        col.addView(outBox)
    }

    /**
     * A opção do código secreto só aparece quando faz sentido: formato disfarçado e um único
     * contacto escolhido (além de ti) com quem tens um código combinado.
     */
    private fun updateCode() {
        val mine = a.snap.myKeys.map { it.info.fingerprint }.toSet()
        val others = boxes.filter { it.first.isChecked }.map { it.second }.filterNot { it in mine }
        val c = others.singleOrNull()?.let { fpr -> a.snap.contacts.firstOrNull { it.info.fingerprint == fpr && it.codeCheck != null } }
        codeFpr = c?.info?.fingerprint?.takeIf { selectedFormat().id != FORMAT_PGP }
        useCode.text = "Fechar com o código secreto de ${c?.info?.userId ?: ""}"
        useCode.visibility = if (codeFpr != null) View.VISIBLE else View.GONE
    }

    /** O formato e o código escolhidos da última vez (uma vez, depois de o cofre abrir). */
    private fun restoreChoices() {
        if (choicesRestored || !a.loaded) return
        choicesRestored = true
        val p = a.vaultPrefs()
        format.setSelection(formatPosition(p[VP_FORMAT]?.toIntOrNull() ?: FORMAT_PGP))
        useCode.isChecked = p[VP_USE_CODE] == "1"
    }

    /** PIN de pânico: volta às escolhas de uma app nova (nada do que estava escolhido fica à vista). */
    fun forgetChoices() {
        choicesRestored = false
        format.setSelection(formatPosition(FORMAT_PGP))
        useCode.isChecked = false
        compact.isChecked = false
        sign.isEnabled = true
        preselect = null
    }

    /** Prepara uma resposta: fica escolhido só este destinatário. */
    fun replyTo(fingerprint: String) {
        restoreChoices()
        // O formato e a opção do código secreto usados da última vez com este contacto.
        val p = a.vaultPrefs()
        p[VP_CONTACT_FORMAT + fingerprint]?.toIntOrNull()?.let { format.setSelection(formatPosition(it)) }
        useCode.isChecked = p[VP_CONTACT_CODE + fingerprint] == "1"
        preselect = setOf(fingerprint)
        draft.setText("")
        output.setText("")
        outBox.visibility = View.GONE
    }

    override fun refresh() {
        restoreChoices()
        val checked = preselect ?: boxes.filter { it.first.isChecked }.map { it.second }.toSet()
        preselect = null
        recipients.removeAllViews()
        boxes.clear()
        fun add(name: String, fpr: String, usable: Boolean, why: String) {
            val cb = CheckBox(a).apply {
                text = if (usable) name else "$name ($why)"
                isEnabled = usable
                isChecked = usable && fpr in checked
                maxLines = 1
                ellipsize = TextUtils.TruncateAt.END
                setOnClickListener { updateCode() }
            }
            if (usable) boxes += cb to fpr
            recipients.addView(cb)
        }
        // As tuas próprias chaves: para guardares uma nota só para ti, ou enviares entre as tuas chaves.
        val mine = a.snap.myKeys.map { it.info }.filter { it.canEncrypt }
        mine.forEach { add("Eu: ${it.userId}", it.fingerprint, true, "") }
        val verified = a.snap.contacts.filter { it.verified }.sortedBy { it.info.userId.lowercase() }
        verified.forEach { c -> add(c.info.userId, c.info.fingerprint, c.info.canEncrypt, if (c.info.revoked) "revogada" else "expirada") }
        if (a.snap.myKeys.isEmpty()) {
            // Sem chave tua não há "Eu" nem se pode encriptar: diz porquê e leva lá.
            recipients.addView(label("Ainda não tens a tua chave nesta app, por isso não há destinatários (nem \"Eu\"). Cria-a ou importa-a em ☰ > As minhas chaves."))
            recipients.addView(button("Ir para Chaves") { a.show(TAB_KEYS) })
        } else if (verified.isEmpty()) {
            recipients.addView(label("Para escrever a outras pessoas, adiciona-as e verifica-as em ☰ > Contactos. Para testar, escolhe \"Eu\"."))
        }
        myFprs = mine.map { it.fingerprint }
        val selected = myKeySpinner.selectedItemPosition
        myKeySpinner.adapter = ArrayAdapter(a, android.R.layout.simple_spinner_dropdown_item, mine.map { "De: ${it.userId}" })
        if (selected in mine.indices) myKeySpinner.setSelection(selected)
        myKeySpinner.visibility = if (mine.size > 1) View.VISIBLE else View.GONE
        if (a.snap.myKeys.isNotEmpty() && mine.isEmpty()) {
            ownWarning.text = "A tua chave expirou ou foi revogada. Usa Mais opções > \"Prolongar validade\" em ☰ > As minhas chaves."
            ownWarning.setTextColor(red)
            ownWarning.visibility = View.VISIBLE
        } else {
            ownWarning.visibility = View.GONE
        }
        updateCode()
    }

    override fun clearSensitive() {
        draft.setText("")
        output.setText("")
        outBox.visibility = View.GONE
    }

    private fun encrypt() {
        val text = draft.text.toString()
        val to = boxes.filter { it.first.isChecked }.map { it.second }
        val me = myFprs.getOrNull(myKeySpinner.selectedItemPosition.coerceAtLeast(0))
        val fmt = selectedFormat()
        updateCode()
        val code = codeFpr?.takeIf { useCode.isChecked }
        val small = compact.isChecked
        when {
            text.isEmpty() -> return a.alert("Encriptar", "Escreve primeiro a mensagem.")
            me == null && a.snap.myKeys.isNotEmpty() -> return a.alert("Encriptar", "A tua chave expirou ou foi revogada. Usa Mais opções > \"Prolongar validade\" em ☰ > As minhas chaves.")
            me == null -> return a.alert("Encriptar", "Cria primeiro a tua chave em ☰ > As minhas chaves.")
            to.isEmpty() -> return a.alert("Encriptar", "Escolhe pelo menos um destinatário (podes escolher-te a ti).")
        }
        // Com um só contacto (além de ti), lembra o formato e o código para a próxima conversa com ele.
        val mine = a.snap.myKeys.map { it.info.fingerprint }.toSet()
        to.filterNot { it in mine }.singleOrNull()?.let { other ->
            a.setVaultPrefs(listOf(VP_CONTACT_FORMAT + other to fmt.id.toString(), VP_CONTACT_CODE + other to if (useCode.isChecked) "1" else null))
        }
        val run = { chars: CharArray? ->
            a.work("A encriptar…", {
                try { a.formatted(a.vault.encrypt(text, to, me!!, chars != null, chars, toSelf = !small), fmt.id, code) } finally { chars?.fill('\u0000') }
            }) { out ->
                showOutput(if (small) "Mensagem encriptada (compacta: não a consegues reler)" else "Mensagem encriptada", out)
                outNote.text = sizeNote(out, fmt, small)
                outNote.visibility = if (outNote.text.isEmpty()) View.GONE else View.VISIBLE
            }
        }
        if (sign.isChecked && !small) a.keyPassphrase("Assinar", "Palavra-passe da tua chave:", me) { run(it) } else run(null)
    }

    private fun selectedFormat(): Format = FORMATS[format.selectedItemPosition.coerceIn(0, FORMATS.size - 1)]

    /** Quanto ficou o texto disfarçado, para veres antes de enviar se ficou comprido de mais. */
    private fun sizeNote(text: String, fmt: Format, small: Boolean): String {
        val style = fmt.style ?: return ""
        val units = Disguise.units(text, style) ?: return ""
        val words = text.split(Regex("\\s+")).count { it.isNotEmpty() }
        val size = "Tamanho: $units ${fmt.unit}, cerca de $words palavras."
        return when {
            words < 1500 -> size
            small -> "$size Ficou comprido (as chaves RSA e as mensagens longas dão textos maiores); " +
                "o código ou o poema ficam mais curtos."
            else -> "$size Ficou comprido: o modo compacto (acima) encurta para cerca de metade, " +
                "e o código ou o poema ficam mais curtos."
        }
    }

    private fun showOutput(title: String, text: String) {
        outNote.visibility = View.GONE
        outTitle.text = title
        output.setText(text)
        outBox.visibility = View.VISIBLE
        output.post { (view as ScrollView).smoothScrollTo(0, outBox.top) }
    }

    private fun myKey(): String? {
        val me = myFprs.getOrNull(myKeySpinner.selectedItemPosition.coerceAtLeast(0))
        when {
            me != null -> {}
            a.snap.myKeys.isNotEmpty() -> a.alert("Chave", "A tua chave expirou ou foi revogada. Usa Mais opções > \"Prolongar validade\" em ☰ > As minhas chaves.")
            else -> a.alert("Chave", "Cria primeiro a tua chave em ☰ > As minhas chaves.")
        }
        return me
    }

    /** Encriptar um ficheiro: usa os destinatários, a chave e a opção "Assinar" deste ecrã. */
    private fun pickFile() {
        val to = boxes.filter { it.first.isChecked }.map { it.second }
        val me = myKey() ?: return
        if (to.isEmpty()) return a.alert("Encriptar ficheiro", "Escolhe primeiro, em \"Para\", pelo menos um destinatário (podes escolher-te a ti).")
        fileJob = Triple(to, me, sign.isChecked)
        a.openFile(KIND_FILE_ENC)
    }

    fun runFileJob(input: Uri, out: Uri) {
        val job = fileJob
        fileJob = null
        if (job == null) return a.work("…", { a.deleteDocument(out) }) { a.alert("Ficheiro", "Não ficou nada guardado. Repete a operação.") }
        val (to, me, signed) = job
        val run = { chars: CharArray? ->
            a.work("A encriptar o ficheiro…", {
                try {
                    val name = a.fileName(input)
                    a.writeTo(out) { o -> a.contentResolver.openInputStream(input)!!.use { i -> a.vault.encryptFile(i, o, name, to, me, signed, chars) } }
                } finally {
                    chars?.fill('\u0000')
                }
            }) {
                a.alert(
                    "Ficheiro encriptado",
                    "Ficou guardado onde escolheste (.pgp). Abre em qualquer programa OpenPGP e no Reczi cypher " +
                        "(Mensagens > Ler > Desencriptar um ficheiro). O ficheiro original não foi apagado."
                )
            }
        }
        if (signed) {
            // Se desistires aqui, o ficheiro de destino (ainda vazio) é apagado.
            a.keyPassphrase("Assinar o ficheiro", "Palavra-passe da tua chave:", me, onCancel = { a.work("…", { a.deleteDocument(out) }) {} }) { run(it) }
        } else {
            run(null)
        }
    }
}
