package app.reczi.pgp

import android.app.Activity
import android.app.AlertDialog
import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.ContentResolver
import android.content.Context
import android.content.Intent
import android.content.res.ColorStateList
import android.content.res.Configuration
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import android.os.SystemClock
import android.provider.DocumentsContract
import android.text.Editable
import android.text.InputType
import android.text.TextUtils
import android.text.TextWatcher
import android.view.Gravity
import android.view.MotionEvent
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.view.inputmethod.EditorInfo
import android.widget.AdapterView
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.Spinner
import android.widget.TextView
import android.widget.Toast
import app.reczi.pgp.core.BrokenEntry
import app.reczi.pgp.core.Contact
import app.reczi.pgp.core.DecryptResult
import app.reczi.pgp.core.Disguise
import app.reczi.pgp.core.KeyInfo
import app.reczi.pgp.core.MyKey
import app.reczi.pgp.core.Pgp
import app.reczi.pgp.core.PgpError
import app.reczi.pgp.core.SignatureStatus
import app.reczi.pgp.core.Snapshot
import app.reczi.pgp.core.Vault
import org.bouncycastle.openpgp.PGPSecretKeyRing
import java.text.DateFormat
import java.util.Date
import java.util.Locale

class MainActivity : Activity() {
    private lateinit var store: KeystoreStore
    private lateinit var vault: Vault
    private var snap = Snapshot(emptyList(), emptyList(), emptyList())
    private var loaded = false

    private val worker get() = Vaults.worker
    private val main = Handler(Looper.getMainLooper())
    private var progress: AlertDialog? = null
    private var running = 0

    private lateinit var content: FrameLayout
    private val tabButtons = mutableListOf<Button>()
    private lateinit var screens: List<Screen>
    private var current = 0

    // Pedidos ao seletor de ficheiros: guardados no estado para sobreviverem à recriação da atividade.
    private var pendingOpen: String? = null
    private var pendingBackupFpr: String? = null
    private var stoppedAt = 0L

    // ------------------------------------------------------------------ ciclo de vida

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        secureWindow(window)
        store = Vaults.store(this)
        vault = Vaults.vault(this)
        pendingOpen = savedInstanceState?.getString(STATE_OPEN)
        pendingBackupFpr = savedInstanceState?.getString(STATE_BACKUP)

        screens = listOf(KeysScreen(), ContactsScreen(), EncryptScreen(), DecryptScreen())
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
            fitsSystemWindows = true
        }
        val bar = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; setBackgroundColor(BRAND_BLACK) }
        screens.forEachIndexed { i, s ->
            val b = Button(this, null, android.R.attr.buttonBarButtonStyle).apply {
                text = s.title
                isAllCaps = false
                setTextColor(Color.WHITE)
                setOnClickListener { if (loaded) show(i) }
            }
            tabButtons += b
            bar.addView(b, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        }
        content = FrameLayout(this)
        root.addView(bar)
        root.addView(content, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))
        setContentView(root)

        val fromHistory = (intent.flags and Intent.FLAG_ACTIVITY_LAUNCHED_FROM_HISTORY) != 0
        val share = if (savedInstanceState == null && !fromHistory) intent else null
        load(firstTime = true) { handleShare(share) }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        if (loaded) handleShare(intent)
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putString(STATE_OPEN, pendingOpen)
        outState.putString(STATE_BACKUP, pendingBackupFpr)
    }

    override fun onStop() {
        super.onStop()
        stoppedAt = SystemClock.elapsedRealtime()
    }

    override fun onStart() {
        super.onStart()
        // Ao fim de 5 minutos fora da app, apaga do ecrã as mensagens em claro.
        if (stoppedAt != 0L && SystemClock.elapsedRealtime() - stoppedAt > 5 * 60_000) {
            screens.forEach { it.clearSensitive() }
        }
    }

    override fun onDestroy() {
        progress?.dismiss()
        super.onDestroy()
    }

    /** Lê o cofre em segundo plano; se não for possível abri-lo, mostra o ecrã de recuperação. */
    private fun load(firstTime: Boolean = false, then: () -> Unit = {}) {
        work("A abrir o cofre…", {
            try {
                if (store.isKeyLost()) Result.failure(VaultKeyLostException()) else Result.success(vault.snapshot())
            } catch (e: Exception) {
                Result.failure<Snapshot>(e)
            }
        }) { r ->
            r.fold({ s ->
                snap = s
                loaded = true
                if (firstTime) show(if (s.myKeys.isEmpty()) 0 else 3) else screens[current].refresh()
                if (firstTime) warnExpiring(s)
                then()
            }) { showOpenFailed(it) }
        }
    }

    /** Ao abrir a app, avisa das chaves (tuas e de contactos verificados) que expiram em breve. */
    private fun warnExpiring(s: Snapshot) {
        val lines = s.myKeys.map { "A tua chave" to it.info }
            .plus(s.contacts.filter { it.verified }.map { "Contacto" to it.info })
            .mapNotNull { (who, info) -> daysLeft(info)?.takeIf { it in 0..EXPIRY_WARN_DAYS }?.let { "$who ${info.userId}: faltam $it dia(s)" } }
        if (lines.isEmpty()) return
        alert(
            "Chaves quase a expirar",
            lines.joinToString("\n") + "\n\nAs tuas: usa \"Prolongar validade\" no separador Chaves e volta a enviar a chave pública. " +
                "As dos contactos: pede-lhes a chave atualizada."
        )
    }

    /** Dias até a chave expirar (negativo se já expirou); null se não tem data ou foi revogada. */
    private fun daysLeft(info: KeyInfo): Long? {
        val expires = info.expires ?: return null
        if (info.revoked) return null
        return Math.floorDiv(expires.time - System.currentTimeMillis(), 24 * 3600_000L)
    }

    /** Altera o cofre em segundo plano e volta a mostrar o separador com os dados novos. */
    private fun <T> change(label: String, task: () -> T, done: (T) -> Unit = {}) {
        work(label, { task() to vault.snapshot() }) { (r, s) ->
            snap = s
            screens[current].refresh()
            done(r)
        }
    }

    /** Texto partilhado de outra app (email, mensagens...). */
    private fun handleShare(intent: Intent?) {
        if (intent?.action != Intent.ACTION_SEND) return
        val text = runCatching { intent.getCharSequenceExtra(Intent.EXTRA_TEXT)?.toString()?.trim() }.getOrNull()
        setIntent(Intent(this, MainActivity::class.java))
        if (text.isNullOrEmpty()) return alert("Partilha", "Não recebi texto. Partilha a mensagem ou a chave como texto.")
        // Texto disfarçado (pela app ou com um código secreto): vê-se primeiro o que está por baixo.
        work("A ler…", { vault.reveal(text)?.armored }) { plain -> routeShared(plain ?: text, text) }
    }

    private fun routeShared(text: String, original: String) {
        when {
            // A mensagem fica como chegou: o cofre tira o disfarce ao desencriptar.
            "BEGIN PGP MESSAGE" in text -> { show(3); (screens[3] as DecryptScreen).setMessage(original) }
            "BEGIN PGP PUBLIC KEY BLOCK" in text -> { show(1); (screens[1] as ContactsScreen).input.setText(text) }
            "BEGIN PGP PRIVATE KEY BLOCK" in text -> alert("Partilha", "Por segurança, importa chaves privadas a partir de um ficheiro, no separador Chaves.")
            else -> { show(2); (screens[2] as EncryptScreen).draft.setText(text) }
        }
    }

    private fun show(i: Int) {
        current = i
        content.removeAllViews()
        content.addView(screens[i].view)
        screens[i].refresh()
        tabButtons.forEachIndexed { j, b ->
            b.setTypeface(null, if (j == i) Typeface.BOLD else Typeface.NORMAL)
            b.setTextColor(if (j == i) BRAND_RED_LIGHT else Color.WHITE)
            b.alpha = if (j == i) 1f else 0.75f
        }
    }

    private fun showOpenFailed(e: Throwable) {
        loaded = false
        content.removeAllViews()
        val col = column()
        col.addView(heading("Não é possível abrir o cofre"))
        col.addView(label(
            if (e is VaultKeyLostException) {
                "A chave de proteção que este telemóvel guardava para o cofre desapareceu (por exemplo, depois de " +
                    "uma reposição ou atualização do sistema). As chaves guardadas nesta app já não podem ser lidas."
            } else {
                "O sistema de segurança do telemóvel não respondeu (${e.javaClass.simpleName}). " +
                    "Pode ser temporário: tenta de novo, ou reinicia o telemóvel."
            } + "\n\nSe tens um backup das tuas chaves privadas, também podes começar um cofre novo e importá-lo. " +
                "Nada é apagado: os ficheiros e a chave antiga ficam postos de lado."
        ))
        col.addView(button("Tentar de novo") { load(firstTime = true) })
        col.addView(button("Começar um cofre novo…") {
            typedConfirm("Cofre novo", "Vais começar um cofre vazio. Escreve NOVO para confirmar:", "NOVO") {
                work("A preparar…", { store.resetVault(); vault.clearCache() }) { load(firstTime = true) }
            }
        })
        content.addView(scroll(col))
    }

    // ------------------------------------------------------------------ trabalho em segundo plano

    private fun <T> work(label: String, task: () -> T, done: (T) -> Unit) {
        if (running++ == 0) showProgress(label)
        worker.execute {
            val r = runCatching(task)
            main.post {
                if (--running == 0) {
                    progress?.dismiss()
                    progress = null
                }
                if (isDestroyed) return@post
                r.fold(done) { showError(it) }
            }
        }
    }

    private fun showProgress(label: String) {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(24), dp(24), dp(24), dp(24))
            addView(ProgressBar(context))
            addView(TextView(context).apply { text = label; setPadding(dp(16), 0, 0, 0) })
        }
        progress = AlertDialog.Builder(this).setView(row).setCancelable(false).showSecure()
    }

    private fun showError(e: Throwable) {
        val msg = when (e) {
            is PgpError -> e.message ?: "Erro."
            is VaultKeyLostException -> return showOpenFailed(e)
            is OutOfMemoryError -> "Não há memória suficiente para esta operação."
            else -> "Erro inesperado (${e.javaClass.simpleName})."
        }
        alert("Erro", msg)
    }

    // ------------------------------------------------------------------ janelas e diálogos

    /** Sem capturas de ecrã e, no Android 12+, sem janelas de outras apps por cima. */
    private fun secureWindow(w: android.view.Window?) {
        w ?: return
        w.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        if (Build.VERSION.SDK_INT >= 31) w.setHideOverlayWindows(true)
    }

    private fun AlertDialog.Builder.showSecure(): AlertDialog {
        val d = create()
        secureWindow(d.window)
        d.show()
        return d
    }

    /**
     * Protege um botão importante contra "tapjacking": ignora toques quando outra app desenha por
     * cima da janela (mesmo só em parte) e explica porquê, em vez de a app parecer bloqueada.
     */
    private fun <V : View> guard(v: V): V {
        v.setOnTouchListener { _, ev ->
            val obscured = ev.flags and (MotionEvent.FLAG_WINDOW_IS_OBSCURED or FLAG_PARTIALLY_OBSCURED) != 0
            if (obscured && ev.action == MotionEvent.ACTION_UP) {
                Toast.makeText(this, "Há outra app a desenhar por cima do ecrã (filtro de luz, bolha de chat...). Desliga-a para continuar.", Toast.LENGTH_LONG).show()
            }
            obscured
        }
        return v
    }

    private fun alert(title: String, text: String, then: (() -> Unit)? = null) {
        AlertDialog.Builder(this).setTitle(title).setMessage(text)
            .setPositiveButton("OK") { _, _ -> then?.invoke() }
            .setCancelable(then == null)
            .showSecure()
    }

    private fun confirm(title: String, text: String, yes: String, onYes: () -> Unit) {
        AlertDialog.Builder(this).setTitle(title).setMessage(text)
            .setPositiveButton(yes) { _, _ -> onYes() }
            .setNegativeButton("Cancelar", null)
            .showSecure()
    }

    /** Confirmação que obriga a escrever uma palavra. */
    private fun typedConfirm(title: String, text: String, word: String, onYes: () -> Unit) {
        val box = column(dp(20))
        box.addView(TextView(this).apply { this.text = text })
        val typed = field(word)
        box.addView(typed)
        val d = AlertDialog.Builder(this).setTitle(title).setView(box)
            .setPositiveButton("Confirmar") { _, _ -> onYes() }
            .setNegativeButton("Cancelar", null).showSecure()
        val ok = d.getButton(AlertDialog.BUTTON_POSITIVE)
        ok.isEnabled = false
        typed.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
            override fun onTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
            override fun afterTextChanged(s: Editable?) { ok.isEnabled = s.toString() == word }
        })
    }

    /** Pede a palavra-passe; o CharArray entregue a [onOk] tem de ser apagado por quem o usa. */
    private fun askPassphrase(
        title: String, hint: String, repeat: Boolean = false, fieldHint: String = "Palavra-passe", onOk: (CharArray) -> Unit,
    ) {
        val box = column(dp(20))
        if (hint.isNotEmpty()) box.addView(TextView(this).apply { text = hint })
        val p1 = passwordField(fieldHint)
        val p2 = passwordField("Repete")
        box.addView(p1)
        if (repeat) box.addView(p2)
        val dialog = AlertDialog.Builder(this).setTitle(title).setView(box)
            .setPositiveButton("OK", null).setNegativeButton("Cancelar") { _, _ -> p1.setText(""); p2.setText("") }
            .showSecure()
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
            if (repeat && p1.text.toString() != p2.text.toString()) {
                p2.error = "Não coincidem."
                return@setOnClickListener
            }
            val chars = p1.takeChars()
            p2.setText("")
            dialog.dismiss()
            onOk(chars)
        }
        guard(dialog.getButton(AlertDialog.BUTTON_POSITIVE))
        p1.requestFocus()
        dialog.window?.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_VISIBLE)
    }

    /** Mostra a impressão digital (primeiro, em grande) e pede a confirmação de que coincide. */
    private fun showFingerprintAndVerify(info: KeyInfo) {
        val box = column(dp(20))
        box.addView(TextView(this).apply {
            text = Pgp.prettyFingerprint(info.fingerprint).replace("  ", "\n")
            typeface = Typeface.MONOSPACE
            textSize = 20f
            setPadding(0, 0, 0, dp(12))
        })
        box.addView(nameView(info.userId))
        box.addView(TextView(this).apply {
            text = "\nConfirma esta impressão digital com o dono da chave por outro meio " +
                "(em pessoa, chamada de voz...). Só carrega em \"Coincide\" se for exatamente igual."
        })
        val d = AlertDialog.Builder(this).setTitle("Verificar destinatário").setView(scroll(box))
            .setPositiveButton("Coincide") { _, _ ->
                change("A guardar…", { vault.setVerified(info.fingerprint, true) })
            }
            .setNegativeButton("Agora não", null)
            .showSecure()
        guard(d.getButton(AlertDialog.BUTTON_POSITIVE))
    }

    // ------------------------------------------------------------------ ficheiros e área de transferência

    private fun openFile(kind: String) {
        pendingOpen = kind
        startActivityForResult(
            Intent(Intent.ACTION_OPEN_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType("*/*"), REQ_OPEN
        )
    }

    private fun saveBackup(fingerprint: String) {
        pendingBackupFpr = fingerprint
        startActivityForResult(
            Intent(Intent.ACTION_CREATE_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE)
                .setType("application/pgp-keys")
                .putExtra(Intent.EXTRA_TITLE, "chave-privada-${fingerprint.takeLast(16)}.asc")
                .putExtra(Intent.EXTRA_LOCAL_ONLY, true), // só armazenamento local (não cloud)
            REQ_SAVE
        )
    }

    @Deprecated("API da framework; não usamos AndroidX")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        val kind = pendingOpen
        val backupFpr = pendingBackupFpr
        pendingOpen = null
        pendingBackupFpr = null
        val uri: Uri = data?.data?.takeIf { resultCode == RESULT_OK } ?: return
        if (uri.scheme != ContentResolver.SCHEME_CONTENT) return alert("Erro", "Local de ficheiro não suportado.")
        when (requestCode) {
            REQ_OPEN -> work("A ler o ficheiro…", { readUri(uri) }) { bytes ->
                when (kind) {
                    KIND_PRIVATE -> (screens[0] as KeysScreen).importPrivate(bytes)
                    KIND_PUBLIC -> (screens[1] as ContactsScreen).importPublic(bytes)
                    KIND_MESSAGE -> (screens[3] as DecryptScreen).loadFile(bytes)
                }
            }
            REQ_SAVE -> {
                if (backupFpr == null) {
                    work("…", { runCatching { DocumentsContract.deleteDocument(contentResolver, uri) } }) {
                        alert("Backup", "A cópia NÃO foi guardada. Repete o backup.")
                    }
                    return
                }
                work("A guardar a cópia…", {
                    val bytes = Pgp.armor(vault.backupRing(backupFpr)).toByteArray()
                    contentResolver.openOutputStream(uri, "wt")!!.use { it.write(bytes) }
                    // Confirma que ficou bem escrito.
                    if (!readUri(uri).contentEquals(bytes)) throw PgpError("A cópia ficou incompleta. Repete o backup.")
                }) { alert("Backup", "Cópia da chave privada guardada. Guarda-a num local seguro e offline.") }
            }
        }
    }

    private fun readUri(uri: Uri): ByteArray = contentResolver.openInputStream(uri)!!.use { input ->
        val bytes = input.readUpTo(MAX_FILE + 1)
        if (bytes.size > MAX_FILE) throw PgpError("O ficheiro é demasiado grande.")
        bytes
    }

    private fun copy(text: String, sensitive: Boolean) {
        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = ClipData.newPlainText("texto", text)
        if (sensitive) {
            // Pede ao teclado/sistema para não mostrar o conteúdo na pré-visualização (Android 13+).
            val key = if (Build.VERSION.SDK_INT >= 33) ClipDescription.EXTRA_IS_SENSITIVE else "android.content.extra.IS_SENSITIVE"
            clip.description.extras = PersistableBundle().apply { putBoolean(key, true) }
        }
        cm.setPrimaryClip(clip)
        if (sensitive) {
            ClipboardClearReceiver.schedule(this) // funciona mesmo que a app seja fechada
            main.postDelayed({ ClipboardClearReceiver.clear(applicationContext) }, ClipboardClearReceiver.DELAY_MS)
        }
        if (Build.VERSION.SDK_INT < 33) {
            Toast.makeText(this, if (sensitive) "Copiado. Limpo após ~45 s." else "Copiado.", Toast.LENGTH_SHORT).show()
        }
    }

    private fun pasteText(): String {
        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        return cm.primaryClip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.coerceToText(this)?.toString() ?: ""
    }

    private fun clearClipboard() = ClipboardClearReceiver.clear(applicationContext)

    private fun share(text: String) {
        startActivity(Intent.createChooser(Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, text), "Partilhar"))
    }

    /** Pergunta em que formato partilhar um texto PGP: normal ou disfarçado (ver Disguise no núcleo). */
    private fun pickFormat(armored: String, then: (String) -> Unit) {
        AlertDialog.Builder(this).setTitle("Formato")
            .setItems(FORMATS) { _, i -> then(formatted(armored, i, null)) }
            .setNegativeButton("Cancelar", null)
            .showSecure()
    }

    /** [codeFpr]: contacto cujo código secreto fecha a camada de fora (só nos formatos disfarçados). */
    private fun formatted(armored: String, format: Int, codeFpr: String?): String = when (format) {
        FORMAT_CODE -> vault.disguise(armored, words = false, codeFpr = codeFpr)
        FORMAT_WORDS -> vault.disguise(armored, words = true, codeFpr = codeFpr)
        else -> armored
    }

    /** Combinar (ou mudar) o código secreto com um contacto. */
    private fun askSecretCode(c: Contact) {
        askPassphrase(
            "Código secreto",
            "Combina uma frase com ${c.info.userId}, em pessoa ou por chamada (nunca por mensagem). " +
                "Têm os dois de escrever exatamente a mesma frase, cada um na sua app (mín. ${Disguise.MIN_CODE} caracteres; " +
                "maiúsculas e minúsculas contam).\n\nSe um dia a mudarem, as mensagens antigas com código deixam de abrir.",
            repeat = true,
            fieldHint = "Frase combinada",
        ) { chars ->
            change("A guardar…", {
                try { vault.setCode(c.info.fingerprint, chars) } finally { chars.fill('\u0000') }
            }) { check ->
                alert(
                    "Código secreto guardado",
                    "Confirmação: $check\n\nNa app de ${c.info.userId} têm de aparecer os mesmos algarismos. " +
                        "Se forem diferentes, um dos dois escreveu a frase de outra maneira.\n\n" +
                        "Para o usar: em Encriptar, escolhe um formato disfarçado e só este destinatário."
                )
            }
        }
    }

    private val prefs get() = getSharedPreferences("prefs", Context.MODE_PRIVATE)

    // ------------------------------------------------------------------ ajudas de interface

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()

    private val isNight get() = (resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK) == Configuration.UI_MODE_NIGHT_YES
    private val green get() = if (isNight) 0xFF81C784.toInt() else 0xFF2E7D32.toInt()
    private val orange get() = if (isNight) 0xFFFFB74D.toInt() else 0xFFB45309.toInt()
    private val red get() = if (isNight) 0xFFEF9A9A.toInt() else 0xFFC62828.toInt()

    private fun column(padding: Int = dp(16)) = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(padding, padding, padding, padding)
    }

    private fun scroll(child: View) = ScrollView(this).apply { isFillViewport = true; addView(child) }

    private fun heading(text: String) = TextView(this).apply {
        this.text = text
        textSize = 18f
        setTypeface(null, Typeface.BOLD)
        setPadding(0, dp(16), 0, dp(8))
    }

    private fun label(text: String) = TextView(this).apply { this.text = text; setPadding(0, dp(4), 0, dp(4)) }

    /** Nome de uma chave: numa só linha, para um nome enorme não esconder o resto. */
    private fun nameView(name: String) = TextView(this).apply {
        text = name
        setTypeface(null, Typeface.BOLD)
        maxLines = 1
        ellipsize = TextUtils.TruncateAt.END
    }

    private fun fingerprintView(fpr: String) = TextView(this).apply {
        text = Pgp.prettyFingerprint(fpr); typeface = Typeface.MONOSPACE; textSize = 12f
    }

    private fun button(text: String, onClick: () -> Unit) = Button(this).apply {
        this.text = text
        isAllCaps = false
        setOnClickListener { onClick() }
    }

    /** Botão da ação principal do ecrã, na cor da marca. */
    private fun primaryButton(text: String, onClick: () -> Unit) = button(text, onClick).apply {
        backgroundTintList = ColorStateList.valueOf(BRAND_RED)
        setTextColor(Color.WHITE)
    }

    private fun buttonRow(vararg buttons: Button) = LinearLayout(this).apply {
        orientation = LinearLayout.HORIZONTAL
        buttons.forEach { addView(it, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)) }
    }

    private fun field(hint: String, type: Int = InputType.TYPE_CLASS_TEXT) = EditText(this).apply {
        this.hint = hint
        inputType = type
        imeOptions = EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
        importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO
    }

    private fun passwordField(hint: String) =
        field(hint, InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD)

    /** Campo de várias linhas sem sugestões nem aprendizagem do teclado. */
    private fun textArea(hint: String, lines: Int, mono: Boolean = false) = field(
        hint,
        InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
    ).apply {
        minLines = lines
        maxLines = lines * 3
        gravity = Gravity.TOP or Gravity.START
        if (mono) { typeface = Typeface.MONOSPACE; textSize = 12f }
    }

    /** Tira o texto do campo como CharArray; setText("") também apaga o histórico de "anular". */
    private fun EditText.takeChars(): CharArray {
        val e = text
        val chars = CharArray(e.length)
        e.getChars(0, e.length, chars, 0)
        setText("")
        return chars
    }

    private fun card() = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(dp(12), dp(12), dp(12), dp(12))
        background = GradientDrawable().apply {
            cornerRadius = dp(8).toFloat()
            setStroke(dp(1), if (isNight) 0x40FFFFFF else 0x30000000)
        }
        layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
            .apply { bottomMargin = dp(8) }
    }

    private fun validity(info: KeyInfo): Pair<String, Int?> {
        val fmt = DateFormat.getDateInstance(DateFormat.MEDIUM, Locale.forLanguageTag("pt-PT"))
        val expires = info.expires
        return when {
            info.revoked -> "REVOGADA - não uses esta chave" to red
            expires != null && expires.before(Date()) -> "EXPIRADA em ${fmt.format(expires)}" to red
            expires != null && (daysLeft(info) ?: Long.MAX_VALUE) <= EXPIRY_WARN_DAYS ->
                "Expira em ${daysLeft(info)} dia(s), a ${fmt.format(expires)}" to orange
            expires != null -> "Válida até ${fmt.format(expires)}" to null
            else -> "Sem data de validade" to null
        }
    }

    // ------------------------------------------------------------------ separadores

    private abstract inner class Screen(val title: String) {
        abstract val view: View
        abstract fun refresh()
        open fun clearSensitive() {}
    }

    /** As minhas chaves: criar, importar, partilhar a pública, backup, prolongar, apagar. */
    private inner class KeysScreen : Screen("Chaves") {
        private val name = field("Nome", InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PERSON_NAME)
        private val email = field("Email", InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS)
        private val pass1 = passwordField("Palavra-passe (mín. ${Pgp.MIN_PASSPHRASE} caracteres)")
        private val pass2 = passwordField("Repete a palavra-passe")
        private val problems = column(0)
        private val list = column(0)
        private val col = column()
        override val view: View = scroll(col)

        init {
            col.addView(problems)
            col.addView(heading("As tuas chaves"))
            col.addView(list)
            col.addView(heading("Criar uma chave nova"))
            col.addView(label("Usa uma frase longa como palavra-passe (5 ou mais palavras ao acaso). Sem ela ninguém consegue usar a tua chave, nem tu."))
            listOf(name, email, pass1, pass2).forEach { col.addView(it) }
            col.addView(guard(primaryButton("Criar chave") { create() }))
            col.addView(heading("Importar a tua chave privada"))
            col.addView(label("Por exemplo, o ficheiro criado no computador com \"cofre backup\"."))
            col.addView(buttonRow(
                button("De ficheiro…") { openFile(KIND_PRIVATE) },
                button("Colar") {
                    val text = pasteText()
                    importPrivate(text.toByteArray(), fromClipboard = true)
                },
            ))
        }

        override fun refresh() {
            problems.removeAllViews()
            if (snap.broken.isNotEmpty()) problems.addView(brokenCard(snap.broken))
            list.removeAllViews()
            if (snap.myKeys.isEmpty()) list.addView(label("Ainda não tens nenhuma chave."))
            snap.myKeys.forEach { list.addView(keyCard(it)) }
        }

        private fun brokenCard(broken: List<BrokenEntry>): View {
            val c = card()
            c.addView(TextView(this@MainActivity).apply {
                text = "⚠ ${broken.size} ficheiro(s) do cofre não podem ser lidos"
                setTypeface(null, Typeface.BOLD)
                setTextColor(red)
            })
            broken.forEach { b ->
                c.addView(label((if (b.isPrivateKey) "Chave privada: " else "Contactos: ") + b.reason))
                val readable = b.readable
                if (readable != null) {
                    c.addView(button("Backup desta chave…") { backup(Pgp.fingerprint(readable)) })
                }
                c.addView(button(if (b.isPrivateKey) "Pôr de lado…" else "Remover") {
                    val msg = when {
                        readable != null -> "Esta chave lê-se mas não pode ser usada agora (confirma a data e a hora do telemóvel). " +
                            "Faz primeiro um backup. Se a puseres de lado, deixa de aparecer na app."
                        b.isPrivateKey -> "Esta chave privada não pode ser lida. O ficheiro é posto de lado na pasta da app (não é apagado). Se tens backup, volta a importá-la."
                        else -> "Remover este ficheiro ilegível?"
                    }
                    confirm("Ficheiro com problemas", msg, "Continuar") { change("A arrumar…", { vault.discardBroken(b.name) }) }
                })
            }
            return c
        }

        private fun keyCard(k: MyKey): View {
            val info = k.info
            val c = card()
            c.addView(nameView(info.userId))
            c.addView(fingerprintView(info.fingerprint))
            val (v, color) = validity(info)
            c.addView(TextView(this@MainActivity).apply { text = v; color?.let { setTextColor(it) } })
            val pub = Pgp.armor(Pgp.certificateOf(k.ring))
            c.addView(buttonRow(
                button("Partilhar pública") { pickFormat(pub) { share(it) } },
                button("Copiar pública") { pickFormat(pub) { copy(it, sensitive = false) } },
            ))
            c.addView(buttonRow(
                button("Backup da privada…") { backup(info.fingerprint) },
                button("Prolongar validade") { extend(k.ring) },
            ))
            c.addView(button("Apagar esta chave…") { delete(info) })
            return c
        }

        private fun create() {
            if (pass1.text.toString() != pass2.text.toString()) {
                pass2.error = "As palavras-passe não coincidem."
                return
            }
            val n = name.text.toString()
            val e = email.text.toString()
            val chars = pass1.takeChars()
            pass2.setText("")
            change("A criar a chave…", {
                try {
                    Pgp.generate(n, e, chars).also { vault.addMyKey(it) }
                } finally {
                    chars.fill('\u0000')
                }
            }) { key ->
                name.setText(""); email.setText("")
                alert(
                    "Chave criada",
                    "Impressão digital:\n${Pgp.prettyFingerprint(Pgp.fingerprint(key))}\n\n" +
                        "Faz já um backup da chave privada (botão \"Backup da privada\") para um local seguro. " +
                        "Se desinstalares a app ou perderes o telemóvel sem backup, perdes o acesso às tuas mensagens."
                )
            }
        }

        fun importPrivate(data: ByteArray, fromClipboard: Boolean = false) {
            if (data.isEmpty()) return
            work("A ler a chave…", {
                Pgp.parseSecretKeys(data).map { ring -> ring to runCatching { Pgp.info(ring) } }
            }) { keys ->
                if (fromClipboard) clearClipboard() // não deixar a chave privada na área de transferência
                val ok = keys.mapNotNull { (ring, info) -> info.getOrNull()?.let { ring to it } }
                val bad = keys.filter { it.second.isFailure }.map { (ring, info) ->
                    "${Pgp.fingerprint(ring).takeLast(16)}: ${(info.exceptionOrNull() as? PgpError)?.message ?: "chave inválida"}"
                }
                val go = { importNext(ok.toMutableList()) }
                if (bad.isNotEmpty()) alert("Chaves ignoradas", bad.joinToString("\n"), go) else go()
            }
        }

        private fun importNext(queue: MutableList<Pair<PGPSecretKeyRing, KeyInfo>>) {
            val (key, info) = queue.removeFirstOrNull() ?: return
            val prot = Pgp.isProtected(key)
            askPassphrase(
                "Importar chave",
                if (prot) "${info.userId}\n\nPalavra-passe desta chave:"
                else "${info.userId}\n\nEsta chave não tem palavra-passe. Define uma agora (mín. ${Pgp.MIN_PASSPHRASE} caracteres):",
                repeat = !prot,
            ) { chars ->
                change("A importar…", {
                    try { vault.addMyKey(Pgp.prepareImported(key, chars)) } finally { chars.fill('\u0000') }
                }) {
                    alert("Chave importada", "${info.userId}\n${Pgp.prettyFingerprint(info.fingerprint)}") { importNext(queue) }
                }
            }
        }

        fun backup(fingerprint: String) {
            confirm(
                "Backup da chave privada",
                "O ficheiro continua protegido pela tua palavra-passe, mas guarda-o só num local offline " +
                    "(pen USB, cartão SD guardado). Nunca na cloud, email ou mensagens.",
                "Continuar",
            ) { saveBackup(fingerprint) }
        }

        private fun extend(key: PGPSecretKeyRing) {
            askPassphrase("Prolongar validade", "A chave fica válida por mais 2 anos a partir de hoje.") { chars ->
                change("A atualizar…", {
                    try { vault.addMyKey(Pgp.extendExpiry(key, chars)) } finally { chars.fill('\u0000') }
                }) {
                    alert("Validade prolongada", "Volta a enviar a tua chave pública aos teus contactos, para eles também a atualizarem.")
                }
            }
        }

        private fun delete(info: KeyInfo) {
            typedConfirm(
                "Apagar chave",
                "Vais apagar a chave PRIVADA de ${info.userId}. Sem backup, deixas de conseguir ler as mensagens enviadas para ela.\n\nEscreve APAGAR para confirmar:",
                "APAGAR",
            ) { change("A apagar…", { vault.deleteMyKey(info.fingerprint) }) }
        }
    }

    /** Chaves públicas de outras pessoas. */
    private inner class ContactsScreen : Screen("Contactos") {
        val input = textArea("Cola aqui a chave pública de alguém (normal ou disfarçada)", 4, mono = true)
        private val list = column(0)
        private val col = column()
        override val view: View = scroll(col)

        init {
            col.addView(heading("Adicionar destinatário"))
            col.addView(input)
            col.addView(buttonRow(
                button("Colar") { input.setText(pasteText()) },
                button("De ficheiro…") { openFile(KIND_PUBLIC) },
                guard(primaryButton("Importar") { importPublic(input.text.toString().toByteArray()) }),
            ))
            col.addView(heading("Destinatários"))
            col.addView(list)
        }

        override fun refresh() {
            list.removeAllViews()
            val contacts = snap.contacts.sortedBy { it.info.userId.lowercase() }
            if (contacts.isEmpty()) list.addView(label("Ainda não tens destinatários."))
            contacts.forEach { list.addView(contactCard(it)) }
        }

        private fun contactCard(c: Contact): View {
            val v = card()
            v.addView(nameView(c.info.userId))
            v.addView(fingerprintView(c.info.fingerprint))
            val (validText, validColor) = validity(c.info)
            v.addView(TextView(this@MainActivity).apply { text = validText; validColor?.let { setTextColor(it) } })
            v.addView(TextView(this@MainActivity).apply {
                text = if (c.verified) "✔ Verificada" else "NÃO verificada - ainda não podes encriptar para esta chave"
                setTextColor(if (c.verified) green else orange)
            })
            if (c.codeCheck != null) v.addView(TextView(this@MainActivity).apply {
                text = "✔ Código secreto combinado (confirmação: ${c.codeCheck})"
                setTextColor(green)
            })
            if (c.verified) v.addView(buttonRow(*listOfNotNull(
                button(if (c.codeCheck == null) "Código secreto…" else "Mudar código…") { askSecretCode(c) },
                if (c.codeCheck == null) null else button("Tirar código") {
                    confirm("Tirar código secreto", "Deixas de conseguir abrir as mensagens de ${c.info.userId} enviadas com código secreto.", "Tirar") {
                        change("A guardar…", { vault.clearCode(c.info.fingerprint) })
                    }
                },
            ).toTypedArray()))
            val row = LinearLayout(this@MainActivity).apply { orientation = LinearLayout.HORIZONTAL }
            if (!c.verified) row.addView(button("Verificar…") { showFingerprintAndVerify(c.info) },
                LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
            row.addView(button("Remover") {
                confirm("Remover", "Remover a chave pública de ${c.info.userId}?", "Remover") {
                    change("A remover…", { vault.deleteContact(c.info.fingerprint) })
                }
            }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
            v.addView(row)
            return v
        }

        fun importPublic(data: ByteArray) {
            if (data.isEmpty()) return
            change("A importar…", {
                // Uma chave disfarçada pela app volta primeiro a PGP normal.
                val plain = vault.reveal(String(data, Charsets.UTF_8))?.armored?.toByteArray() ?: data
                vault.importContacts(Pgp.parseCertificates(plain))
            }) { r ->
                input.setText("")
                val first = r.added.firstNotNullOfOrNull { fpr -> snap.contacts.firstOrNull { it.info.fingerprint == fpr } }
                val verify = { if (first != null) showFingerprintAndVerify(first.info) }
                when {
                    r.rejected.isNotEmpty() -> alert("Algumas chaves foram recusadas", r.rejected.joinToString("\n"), verify)
                    first != null -> verify()
                    else -> alert("Importar", "A chave já existia e foi atualizada (ou era uma chave tua).")
                }
            }
        }
    }

    private inner class EncryptScreen : Screen("Encriptar") {
        val draft = textArea("Mensagem", 5)
        private val recipients = column(0)
        private val boxes = mutableListOf<Pair<CheckBox, String>>()
        /** Destinatários a deixar escolhidos na próxima vez que o ecrã for mostrado (botão "Responder"). */
        private var preselect: Set<String>? = null
        private val myKeySpinner = Spinner(this@MainActivity)
        private var myFprs = listOf<String>()
        private val ownWarning = label("").apply { visibility = View.GONE }
        private val sign = CheckBox(this@MainActivity).apply { text = "Assinar com a minha chave"; isChecked = true }
        private val format = Spinner(this@MainActivity)
        private val formatHint = label("")
        /** Contacto cujo código secreto pode fechar a camada de fora (um só destinatário, com código). */
        private var codeFpr: String? = null
        private val useCode = CheckBox(this@MainActivity).apply { isChecked = prefs.getBoolean(PREF_USE_CODE, true) }
        private val output = textArea("", 5, mono = true).apply { keyListener = null; setTextIsSelectable(true) }
        private val outBox = column(0)
        private val col = column()
        override val view: View = scroll(col)

        init {
            col.addView(heading("Mensagem"))
            col.addView(draft)
            col.addView(heading("Para"))
            col.addView(recipients)
            col.addView(label("A mensagem também é sempre encriptada para a tua chave, para a conseguires reler."))
            col.addView(ownWarning)
            col.addView(myKeySpinner)
            col.addView(sign)
            col.addView(heading("Formato"))
            format.adapter = ArrayAdapter(this@MainActivity, android.R.layout.simple_spinner_dropdown_item, FORMATS)
            format.setSelection(prefs.getInt(PREF_FORMAT, FORMAT_PGP).coerceIn(0, FORMATS.size - 1))
            format.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
                override fun onItemSelected(parent: AdapterView<*>?, v: View?, position: Int, id: Long) {
                    prefs.edit().putInt(PREF_FORMAT, position).apply()
                    updateCode()
                    formatHint.text = when (position) {
                        FORMAT_CODE -> "Parece um código ao acaso; não se vê que é PGP. Só quem usa o Reczi cypher o consegue abrir."
                        FORMAT_WORDS -> "Parece uma lista de palavras soltas (fica bem mais comprido). Só quem usa o Reczi cypher o consegue abrir."
                        else -> "Mensagem PGP normal: abre em qualquer programa OpenPGP (GnuPG, etc.), mas vê-se logo que é PGP."
                    }
                }
                override fun onNothingSelected(parent: AdapterView<*>?) {}
            }
            col.addView(format)
            col.addView(formatHint)
            useCode.setOnClickListener { prefs.edit().putBoolean(PREF_USE_CODE, useCode.isChecked).apply() }
            col.addView(useCode)
            col.addView(primaryButton("Encriptar") { encrypt() })
            outBox.addView(heading("Mensagem encriptada"))
            outBox.addView(output)
            outBox.addView(buttonRow(
                button("Copiar") { copy(output.text.toString(), sensitive = false) },
                button("Partilhar") { share(output.text.toString()) },
                button("Limpar") { clearSensitive() },
            ))
            outBox.visibility = View.GONE
            col.addView(outBox)
        }

        /**
         * A opção do código secreto só aparece quando faz sentido: formato disfarçado e um único
         * contacto escolhido (além de ti) com quem tens um código combinado.
         */
        private fun updateCode() {
            val mine = snap.myKeys.map { it.info.fingerprint }.toSet()
            val others = boxes.filter { it.first.isChecked }.map { it.second }.filterNot { it in mine }
            val c = others.singleOrNull()?.let { fpr -> snap.contacts.firstOrNull { it.info.fingerprint == fpr && it.codeCheck != null } }
            codeFpr = c?.info?.fingerprint?.takeIf { format.selectedItemPosition != FORMAT_PGP }
            useCode.text = "Fechar com o código secreto de ${c?.info?.userId ?: ""}"
            useCode.visibility = if (codeFpr != null) View.VISIBLE else View.GONE
        }

        /** Prepara uma resposta: fica escolhido só este destinatário. */
        fun replyTo(fingerprint: String) {
            preselect = setOf(fingerprint)
            draft.setText("")
            output.setText("")
            outBox.visibility = View.GONE
        }

        override fun refresh() {
            val checked = preselect ?: boxes.filter { it.first.isChecked }.map { it.second }.toSet()
            preselect = null
            recipients.removeAllViews()
            boxes.clear()
            fun add(name: String, fpr: String, usable: Boolean, why: String) {
                val cb = CheckBox(this@MainActivity).apply {
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
            val mine = snap.myKeys.map { it.info }.filter { it.canEncrypt }
            mine.forEach { add("Eu: ${it.userId}", it.fingerprint, true, "") }
            val verified = snap.contacts.filter { it.verified }.sortedBy { it.info.userId.lowercase() }
            verified.forEach { c -> add(c.info.userId, c.info.fingerprint, c.info.canEncrypt, if (c.info.revoked) "revogada" else "expirada") }
            if (verified.isEmpty()) {
                recipients.addView(label("Ainda não tens destinatários verificados. Adiciona-os no separador Contactos."))
            }
            myFprs = mine.map { it.fingerprint }
            val selected = myKeySpinner.selectedItemPosition
            myKeySpinner.adapter = ArrayAdapter(this@MainActivity, android.R.layout.simple_spinner_dropdown_item, mine.map { "De: ${it.userId}" })
            if (selected in mine.indices) myKeySpinner.setSelection(selected)
            myKeySpinner.visibility = if (mine.size > 1) View.VISIBLE else View.GONE
            if (snap.myKeys.isNotEmpty() && mine.isEmpty()) {
                ownWarning.text = "A tua chave expirou ou foi revogada. Usa \"Prolongar validade\" no separador Chaves."
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
            val fmt = format.selectedItemPosition
            updateCode()
            val code = codeFpr?.takeIf { useCode.isChecked }
            when {
                text.isEmpty() -> return alert("Encriptar", "Escreve primeiro a mensagem.")
                me == null && snap.myKeys.isNotEmpty() -> return alert("Encriptar", "A tua chave expirou ou foi revogada. Usa \"Prolongar validade\" no separador Chaves.")
                me == null -> return alert("Encriptar", "Cria primeiro a tua chave no separador Chaves.")
                to.isEmpty() -> return alert("Encriptar", "Escolhe pelo menos um destinatário (podes escolher-te a ti).")
            }
            val run = { chars: CharArray? ->
                work("A encriptar…", {
                    try { formatted(vault.encrypt(text, to, me!!, chars != null, chars), fmt, code) } finally { chars?.fill('\u0000') }
                }) {
                    output.setText(it)
                    outBox.visibility = View.VISIBLE
                    output.post { (view as ScrollView).smoothScrollTo(0, outBox.top) }
                }
            }
            if (sign.isChecked) askPassphrase("Assinar", "Palavra-passe da tua chave:") { run(it) } else run(null)
        }
    }

    private inner class DecryptScreen : Screen("Desencriptar") {
        private val input = textArea("Cola aqui a mensagem (normal ou disfarçada)", 5, mono = true)
        private val fileLabel = label("").apply { visibility = View.GONE }
        private var fileMessage: String? = null
        private val status = TextView(this@MainActivity).apply { setPadding(0, dp(8), 0, dp(8)) }
        // Não selecionável: copiar só pelo botão, que marca o texto como sensível e o limpa depois.
        private val output = TextView(this@MainActivity).apply { setTextIsSelectable(false); textSize = 16f }
        private var replyFpr: String? = null
        private val reply = button("Responder") {
            replyFpr?.let { fpr -> (screens[2] as EncryptScreen).replyTo(fpr); show(2) }
        }.apply { visibility = View.GONE }
        private val outBox = column(0)
        private val col = column()
        override val view: View = scroll(col)

        init {
            col.addView(heading("Mensagem encriptada"))
            col.addView(input)
            col.addView(fileLabel)
            col.addView(buttonRow(
                button("Colar") { setMessage(pasteText()) },
                button("De ficheiro…") { openFile(KIND_MESSAGE) },
                primaryButton("Desencriptar") { decrypt() },
            ))
            outBox.addView(heading("Mensagem original"))
            outBox.addView(status)
            outBox.addView(output)
            outBox.addView(buttonRow(
                button("Copiar (limpa após ~45 s)") { copy(output.text.toString(), sensitive = true) },
                button("Limpar") { clearSensitive() },
            ))
            outBox.addView(reply)
            outBox.visibility = View.GONE
            col.addView(outBox)
            input.addTextChangedListener(object : TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
                override fun onTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
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
            work("A ler a mensagem…", { Pgp.ensureArmored(bytes) }) { armored ->
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

        private fun decrypt() {
            val msg = fileMessage ?: input.text.toString().trim()
            if (msg.isEmpty()) return
            clearSensitive()
            work("A verificar…", { vault.isForMe(msg) }) { forMe ->
                if (!forMe) return@work alert("Desencriptar", "Esta mensagem não foi encriptada para nenhuma das tuas chaves.")
                askPassphrase("Desencriptar", "Palavra-passe da tua chave:") { chars ->
                    work("A desencriptar…", {
                        try { vault.decrypt(msg, chars) } finally { chars.fill('\u0000') }
                    }) { showResult(it) }
                }
            }
        }

        private fun showResult(r: DecryptResult) {
            val who = r.signerName ?: "chave desconhecida"
            val (text, color) = when (val s = r.signature) {
                SignatureStatus.Invalid ->
                    "⚠ ASSINATURA INVÁLIDA - a mensagem foi alterada ou é falsa!" to red
                is SignatureStatus.Valid ->
                    if (r.signerVerified) "✔ VERIFICADA - assinada por $who." to green
                    else "NÃO VERIFICADA - assinada por $who, mas ainda não confirmaste esta chave (${s.fingerprint.takeLast(16)})." to orange
                is SignatureStatus.Rejected ->
                    "⚠ ASSINATURA RECUSADA - assinada por $who, mas essa chave foi revogada, expirou ou usa algoritmos fracos. Não confies no remetente." to red
                SignatureStatus.UnknownSigner -> "REMETENTE DESCONHECIDO - assinada por uma chave que não tens." to orange
                SignatureStatus.None -> "SEM ASSINATURA - não é possível confirmar quem a enviou." to orange
            }
            status.text = if (r.secretCodeWith == null) text else "$text\n🔒 Veio fechada com o código secreto combinado com ${r.secretCodeWith}."
            status.setTextColor(color)
            // Responder: só a quem assinou com uma chave que já verificaste e que ainda serve para encriptar.
            val signer = (r.signature as? SignatureStatus.Valid)?.fingerprint?.takeIf { r.signerVerified }
            val known = snap.contacts.firstOrNull { it.info.fingerprint == signer && it.verified && it.info.canEncrypt }?.info
                ?: snap.myKeys.firstOrNull { it.info.fingerprint == signer && it.info.canEncrypt }?.info
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

    private companion object {
        const val REQ_OPEN = 1
        const val REQ_SAVE = 2
        const val MAX_FILE = 1 shl 20
        const val STATE_OPEN = "pendingOpen"
        const val STATE_BACKUP = "pendingBackup"
        const val KIND_PRIVATE = "private"
        const val KIND_PUBLIC = "public"
        const val KIND_MESSAGE = "message"
        const val PREF_FORMAT = "format"
        const val PREF_USE_CODE = "useCode"
        const val FORMAT_PGP = 0
        const val FORMAT_CODE = 1
        const val FORMAT_WORDS = 2
        val FORMATS = arrayOf("PGP normal", "Disfarçado: código", "Disfarçado: palavras")
        const val EXPIRY_WARN_DAYS = 30L
        /** Cores da marca Reczi: o preto e o vermelho do ícone. */
        const val BRAND_BLACK = 0xFF121212.toInt()
        const val BRAND_RED = 0xFFE53935.toInt()
        const val BRAND_RED_LIGHT = 0xFFFF6F60.toInt()
        /** MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED (API 29), também enviado em versões anteriores. */
        const val FLAG_PARTIALLY_OBSCURED = 0x2
    }
}

private fun java.io.InputStream.readUpTo(limit: Int): ByteArray {
    val out = java.io.ByteArrayOutputStream()
    val buf = ByteArray(8192)
    while (out.size() < limit) {
        val n = read(buf, 0, minOf(buf.size, limit - out.size()))
        if (n < 0) break
        out.write(buf, 0, n)
    }
    return out.toByteArray()
}
