package app.reczi.pgp

import android.Manifest
import android.app.Activity
import android.app.AlertDialog
import android.app.KeyguardManager
import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.ContentResolver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.res.ColorStateList
import android.content.res.Configuration
import android.graphics.BitmapFactory
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.CancellationSignal
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import android.os.SystemClock
import android.provider.DocumentsContract
import android.provider.OpenableColumns
import android.text.Editable
import android.text.InputType
import android.text.TextUtils
import android.text.TextWatcher
import android.util.TypedValue
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
import android.widget.ImageView
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
import app.reczi.pgp.core.Lock
import app.reczi.pgp.core.MyKey
import app.reczi.pgp.core.Note
import app.reczi.pgp.core.Pgp
import app.reczi.pgp.core.PgpError
import app.reczi.pgp.core.PinResult
import app.reczi.pgp.core.Qr
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
    private lateinit var messages: MessagesScreen
    private lateinit var contacts: ContactsScreen
    private lateinit var notes: NotesScreen
    private lateinit var keys: KeysScreen
    private lateinit var enc: EncryptScreen
    private lateinit var dec: DecryptScreen
    private var current = 0

    // Pedidos ao seletor de ficheiros: guardados no estado para sobreviverem à recriação da atividade.
    private var pendingOpen: String? = null
    private var pendingBackupFpr: String? = null
    /** Encriptar/desencriptar ficheiros: o ficheiro de entrada já escolhido e o que fazer com ele. */
    private var pendingIn: String? = null
    private var pendingSave: String? = null
    /** Leitura de QR à espera da permissão da câmara. */
    private var pendingScan: String? = null
    private var stoppedAt = 0L

    // Bloqueio da app (PIN próprio e/ou impressão digital / bloqueio do telemóvel).
    private var locked = false
    private var hasPin = false
    private var hasPanic = false
    private var everLoaded = false
    private var pendingShare: Intent? = null

    // ------------------------------------------------------------------ ciclo de vida

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        secureWindow(window)
        store = Vaults.store(this)
        vault = Vaults.vault(this)
        pendingOpen = savedInstanceState?.getString(STATE_OPEN)
        pendingBackupFpr = savedInstanceState?.getString(STATE_BACKUP)
        pendingIn = savedInstanceState?.getString(STATE_IN)
        pendingSave = savedInstanceState?.getString(STATE_SAVE)
        pendingScan = savedInstanceState?.getString(STATE_SCAN)

        enc = EncryptScreen()
        dec = DecryptScreen()
        messages = MessagesScreen()
        contacts = ContactsScreen()
        notes = NotesScreen()
        keys = KeysScreen()
        // Encriptar e Desencriptar vivem dentro de "Mensagens"; o último separador (⚙) são as definições.
        screens = listOf(messages, contacts, notes, keys, SettingsScreen())
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
            fitsSystemWindows = true
        }
        val bar = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; setBackgroundColor(BRAND_BLACK) }
        screens.forEachIndexed { i, s ->
            val b = Button(this, null, android.R.attr.buttonBarButtonStyle).apply {
                text = s.tab
                contentDescription = s.title
                isAllCaps = false
                setTextColor(Color.WHITE)
                // O texto encolhe para caber numa linha em ecrãs estreitos.
                maxLines = 1
                minWidth = 0
                minimumWidth = 0
                setPadding(dp(2), paddingTop, dp(2), paddingBottom)
                setAutoSizeTextTypeUniformWithConfiguration(8, 14, 1, TypedValue.COMPLEX_UNIT_SP)
                setOnClickListener { if (loaded && !locked) show(i) }
            }
            tabButtons += b
            bar.addView(b, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, if (s.tab.length <= 2) 0.5f else 1f))
        }
        content = FrameLayout(this)
        root.addView(bar)
        root.addView(content, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))
        setContentView(root)

        val fromHistory = (intent.flags and Intent.FLAG_ACTIVITY_LAUNCHED_FROM_HISTORY) != 0
        val share = if (savedInstanceState == null && !fromHistory) intent else null
        startup(share)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        if (loaded && !locked) handleShare(intent) else pendingShare = intent
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putString(STATE_OPEN, pendingOpen)
        outState.putString(STATE_BACKUP, pendingBackupFpr)
        outState.putString(STATE_IN, pendingIn)
        outState.putString(STATE_SAVE, pendingSave)
        outState.putString(STATE_SCAN, pendingScan)
    }

    override fun onStop() {
        super.onStop()
        stoppedAt = SystemClock.elapsedRealtime()
    }

    override fun onStart() {
        super.onStart()
        // Ao fim de 5 minutos fora da app, apaga do ecrã as mensagens em claro.
        val away = if (stoppedAt == 0L) 0L else SystemClock.elapsedRealtime() - stoppedAt
        if (away > 5 * 60_000) screens.forEach { it.clearSensitive() }
        // Volta a bloquear ao fim de um minuto fora da app (mas não a meio de escolher um ficheiro).
        val picking = pendingOpen != null || pendingBackupFpr != null || pendingSave != null
        if (away > LOCK_AFTER_MS && loaded && !locked && !picking && lockEnabled()) showLock()
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
                everLoaded = true
                if (firstTime) show(if (s.myKeys.isEmpty()) TAB_KEYS else TAB_MESSAGES) else screens[current].refresh()
                if (firstTime) warnExpiring(s)
                if (firstTime) welcome(s)
                then()
            }) { showOpenFailed(it) }
        }
    }

    // ------------------------------------------------------------------ bloqueio da app

    private fun lockEnabled() = hasPin || prefs.getBoolean(PREF_LOCK_BIO, false)

    /** Ao abrir: vê se há PIN da app e mostra o ecrã de bloqueio, ou abre logo o cofre. */
    private fun startup(share: Intent?) {
        pendingShare = share
        work("A abrir…", {
            // Se o cofre não se consegue ler, segue para o ecrã de recuperação (sem bloqueio).
            runCatching { if (store.isKeyLost()) false to false else vault.hasPin() to vault.hasPanicPin() }.getOrDefault(false to false)
        }) { (pin, panic) ->
            hasPin = pin
            hasPanic = panic
            if (lockEnabled()) showLock() else unlocked()
        }
    }

    private fun unlocked() {
        locked = false
        val share = pendingShare
        pendingShare = null
        if (everLoaded) {
            loaded = true
            show(current)
            handleShare(share)
        } else {
            load(firstTime = true) { handleShare(share) }
        }
    }

    private fun showLock() {
        locked = true
        content.removeAllViews()
        tabButtons.forEach { it.alpha = 0.4f }
        val bio = prefs.getBoolean(PREF_LOCK_BIO, false)
        val col = column(dp(24))
        col.addView(heading("Reczi cypher bloqueada"))
        if (hasPin) {
            val pin = field("PIN", InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_VARIATION_PASSWORD)
            val msg = label("")
            col.addView(pin)
            col.addView(msg)
            col.addView(guard(primaryButton("Entrar") { tryPin(pin, msg) }))
        }
        if (bio) col.addView(button("Impressão digital / bloqueio do telemóvel") { systemUnlock() })
        content.addView(scroll(col))
        if (bio) systemUnlock()
    }

    private fun tryPin(pin: EditText, msg: TextView) {
        val wait = (prefs.getLong(PREF_PIN_UNTIL, 0) - System.currentTimeMillis()).coerceAtMost(MAX_PIN_WAIT_MS)
        if (wait > 0) {
            pin.setText("")
            msg.text = "Demasiadas tentativas. Espera ${wait / 1000 + 1} s."
            return
        }
        val chars = pin.takeChars()
        if (chars.isEmpty()) return
        work("A abrir…", { try { vault.checkPin(chars) } finally { chars.fill('\u0000') } }) { r ->
            when (r) {
                PinResult.Ok -> {
                    prefs.edit().remove(PREF_PIN_FAILS).remove(PREF_PIN_UNTIL).apply()
                    unlocked()
                }
                PinResult.Panic -> panic()
                PinResult.Wrong -> {
                    // A partir da 5.ª tentativa errada, cada erro obriga a esperar o dobro (30 s, 1 min, ... até 1 h).
                    val fails = prefs.getInt(PREF_PIN_FAILS, 0) + 1
                    val edit = prefs.edit().putInt(PREF_PIN_FAILS, fails)
                    if (fails >= 5) {
                        edit.putLong(PREF_PIN_UNTIL, System.currentTimeMillis() + (30_000L shl (fails - 5).coerceAtMost(7)).coerceAtMost(MAX_PIN_WAIT_MS))
                    }
                    edit.apply()
                    msg.text = "PIN errado."
                    msg.setTextColor(red)
                }
            }
        }
    }

    /**
     * PIN de pânico: apaga tudo (chaves, contactos, notas, códigos, PINs e a chave do Keystore) e
     * abre a app vazia, como se fosse nova. O rótulo do progresso é o mesmo de uma abertura normal.
     */
    private fun panic() {
        work("A abrir…", {
            runCatching { vault.wipe() }
            store.wipe()
            vault.clearCache()
            clearClipboard()
            prefs.edit().clear().commit()
        }) {
            hasPin = false
            hasPanic = false
            everLoaded = false
            loaded = false
            snap = Snapshot(emptyList(), emptyList(), emptyList())
            screens.forEach { it.clearSensitive() }
            unlocked()
        }
    }

    /** Desbloqueia com a impressão digital ou com o PIN/padrão do próprio telemóvel. */
    private fun systemUnlock() {
        val km = getSystemService(Context.KEYGUARD_SERVICE) as? KeyguardManager
        // Sem bloqueio de ecrã no telemóvel não há com que confirmar. Só o dono o consegue tirar
        // (o Android pede o PIN atual), por isso deixa-se entrar e avisa-se.
        if (km == null || !km.isDeviceSecure) {
            if (hasPin) return alert("Bloqueio", "O telemóvel já não tem bloqueio de ecrã. Usa o PIN da app.")
            unlocked()
            return alert("Bloqueio", "O telemóvel já não tem bloqueio de ecrã, por isso a app abriu sem pedir nada. Define um bloqueio nas definições do Android.")
        }
        if (Build.VERSION.SDK_INT >= 30) {
            BiometricPrompt.Builder(this)
                .setTitle("Reczi cypher")
                .setSubtitle("Desbloquear a app")
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_WEAK or BiometricManager.Authenticators.DEVICE_CREDENTIAL)
                .build()
                .authenticate(CancellationSignal(), mainExecutor, object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult?) {
                        if (locked && !isDestroyed) unlocked()
                    }
                })
        } else {
            // Android 8 a 10: o ecrã do sistema que confirma o bloqueio do telemóvel.
            @Suppress("DEPRECATION")
            val intent = km.createConfirmDeviceCredentialIntent("Reczi cypher", "Desbloquear a app")
            if (intent == null) unlocked() else startActivityForResult(intent, REQ_UNLOCK)
        }
    }

    /** Pede um PIN novo (duas vezes). */
    private fun askNewPin(title: String, hint: String, onOk: (CharArray) -> Unit) =
        askPassphrase(title, hint, repeat = true, fieldHint = "PIN (mín. ${Lock.MIN_PIN} algarismos)", numeric = true, onOk = onOk)

    /** Antes de mudar ou tirar o bloqueio, confirma o PIN atual. */
    private fun withCurrentPin(then: () -> Unit) {
        if (!hasPin) return then()
        askPassphrase("PIN atual", "", fieldHint = "PIN", numeric = true) { chars ->
            work("A verificar…", { try { vault.checkPin(chars) } finally { chars.fill('\u0000') } }) { r ->
                if (r == PinResult.Ok) then() else alert("PIN", "PIN errado.")
            }
        }
    }

    /** Guarda uma alteração aos PINs e atualiza o que o ecrã mostra. */
    private fun changePins(task: () -> Unit, done: () -> Unit = {}) {
        work("A guardar…", { task(); vault.hasPin() to vault.hasPanicPin() }) { (pin, panic) ->
            hasPin = pin
            hasPanic = panic
            screens[current].refresh()
            done()
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
        route(text, "Partilha")
    }

    /** "Colar e detetar": vê o que está na área de transferência e leva-o para o sítio certo. */
    private fun pasteAndRoute() {
        val text = pasteText().trim()
        if (text.isEmpty()) return alert("Colar", "A área de transferência está vazia. Copia primeiro a mensagem ou a chave na outra app.")
        route(text, "Colar")
    }

    /** Leva um texto recebido (partilhado ou colado) para o ecrã certo: mensagem, chave ou texto por encriptar. */
    private fun route(original: String, title: String) {
        // Texto disfarçado (pela app ou com um código secreto): vê-se primeiro o que está por baixo.
        work("A ler…", { vault.reveal(original)?.armored }) { plain ->
            val text = plain ?: original
            when {
                // A mensagem fica como chegou: o cofre tira o disfarce ao desencriptar.
                "BEGIN PGP MESSAGE" in text || "BEGIN PGP SIGNED MESSAGE" in text -> { dec.setMessage(original); messages.open(write = false) }
                "BEGIN PGP PUBLIC KEY BLOCK" in text -> { show(TAB_CONTACTS); contacts.input.setText(text) }
                "BEGIN PGP PRIVATE KEY BLOCK" in text -> alert(title, "Por segurança, importa chaves privadas a partir de um ficheiro, no separador Chaves.")
                else -> { enc.draft.setText(text); messages.open(write = true) }
            }
        }
    }

    // ------------------------------------------------------------------ ajuda e primeiros passos

    /** Botão "? Ajuda", no canto de cima de cada separador. */
    private val helpButton by lazy {
        Button(this, null, android.R.attr.borderlessButtonStyle).apply {
            text = "? Ajuda"
            isAllCaps = false
            setTextColor(if (isNight) BRAND_RED_LIGHT else BRAND_RED)
            setOnClickListener {
                AlertDialog.Builder(this@MainActivity).setTitle("Ajuda: ${screens[current].title}").setMessage(screens[current].help)
                    .setPositiveButton("OK", null)
                    .setNeutralButton("Como funciona") { _, _ -> alert("Como funciona", HOW_IT_WORKS) }
                    .showSecure()
            }
        }
    }

    /** Na primeira vez que a app abre sem chaves, explica por onde começar. */
    private fun welcome(s: Snapshot) {
        if (prefs.getBoolean(PREF_WELCOMED, false)) return
        prefs.edit().putBoolean(PREF_WELCOMED, true).apply()
        if (s.myKeys.isNotEmpty()) return // já usavas a app: não precisas da apresentação
        alert("Bem-vindo ao Reczi cypher", "$HOW_IT_WORKS\n\nNo separador Chaves tens os primeiros passos, por ordem. O bloqueio da app está no separador ⚙. Em cada separador há um botão \"? Ajuda\".")
    }

    /** Chaves privadas de que há registo de backup (ficheiro, papel, ou importadas de um backup). */
    private fun backedUp(): Set<String> = prefs.getStringSet(PREF_BACKED_UP, emptySet()) ?: emptySet()

    private fun markBackedUp(fingerprint: String) {
        prefs.edit().putStringSet(PREF_BACKED_UP, backedUp() + fingerprint).apply()
        if (loaded && !locked) screens[current].refresh()
    }

    private fun show(i: Int) {
        current = i
        content.removeAllViews()
        content.addView(screens[i].view)
        content.addView(helpButton, FrameLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT, Gravity.TOP or Gravity.END))
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
        title: String, hint: String, repeat: Boolean = false, fieldHint: String = "Palavra-passe", numeric: Boolean = false,
        onCancel: () -> Unit = {}, onOk: (CharArray) -> Unit,
    ) {
        val box = column(dp(20))
        if (hint.isNotEmpty()) box.addView(TextView(this).apply { text = hint })
        val type = if (numeric) InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_VARIATION_PASSWORD
        else InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        val p1 = field(fieldHint, type)
        val p2 = field("Repete", type)
        box.addView(p1)
        if (repeat) box.addView(p2)
        val dialog = AlertDialog.Builder(this).setTitle(title).setView(box)
            .setPositiveButton("OK", null).setNegativeButton("Cancelar") { _, _ -> p1.setText(""); p2.setText(""); onCancel() }
            .setOnCancelListener { onCancel() }
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

    /** A impressão digital em palavras, cinco por linha. */
    private fun wordsOf(fingerprint: String) = Pgp.fingerprintWords(fingerprint).chunked(5).joinToString("\n") { it.joinToString(" ") }

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
            text = "\nA mesma impressão digital em palavras (mais fácil de ler em voz alta):\n\n${wordsOf(info.fingerprint)}\n\n" +
                "Confirma-a com o dono da chave por outro meio (em pessoa, chamada de voz...): as letras e números ou as palavras, " +
                "tanto faz, mas todas. Ele vê as dele em Chaves > Mostrar QR. Só carrega em \"Coincide\" se for exatamente igual."
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

    /** Segundo passo de encriptar/desencriptar um ficheiro: escolher onde guardar o resultado. */
    private fun pickOutput(input: Uri, kind: String, name: String) {
        pendingIn = input.toString()
        pendingSave = kind
        val ext = name.substringAfterLast('.', "").lowercase(Locale.ROOT)
        val mime = android.webkit.MimeTypeMap.getSingleton().getMimeTypeFromExtension(ext) ?: "application/octet-stream"
        startActivityForResult(
            Intent(Intent.ACTION_CREATE_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType(mime).putExtra(Intent.EXTRA_TITLE, name),
            REQ_SAVE_FILE
        )
    }

    /** Nome do ficheiro escolhido, como o seletor o mostra. */
    private fun fileName(uri: Uri): String = runCatching {
        contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
            if (c.moveToFirst()) c.getString(0) else null
        }
    }.getOrNull()?.takeIf { it.isNotBlank() } ?: "ficheiro"

    private fun deleteDocument(uri: Uri) {
        runCatching { DocumentsContract.deleteDocument(contentResolver, uri) }
    }

    /** Escreve em [out]; se [task] falhar, apaga o ficheiro incompleto antes de mostrar o erro. */
    private fun <T> writeTo(out: Uri, task: (java.io.OutputStream) -> T): T = try {
        contentResolver.openOutputStream(out, "wt")!!.use(task)
    } catch (e: Throwable) {
        deleteDocument(out)
        throw e
    }

    @Deprecated("API da framework; não usamos AndroidX")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        // Voltar de um seletor de ficheiros (ou do ecrã de desbloqueio) não conta como tempo fora da app.
        stoppedAt = 0L
        if (requestCode == REQ_UNLOCK) {
            if (resultCode == RESULT_OK && locked) unlocked()
            return
        }
        val kind = pendingOpen
        val backupFpr = pendingBackupFpr
        val input = pendingIn?.let(Uri::parse)
        val saveKind = pendingSave
        pendingOpen = null
        pendingBackupFpr = null
        pendingIn = null
        pendingSave = null
        val uri: Uri = data?.data?.takeIf { resultCode == RESULT_OK } ?: return
        if (uri.scheme != ContentResolver.SCHEME_CONTENT) return alert("Erro", "Local de ficheiro não suportado.")
        when (requestCode) {
            REQ_OPEN -> when (kind) {
                KIND_FILE_ENC -> work("…", { fileName(uri) }) { name -> pickOutput(uri, KIND_FILE_ENC, "$name.pgp") }
                KIND_FILE_DEC -> work("A ver o ficheiro…", {
                    contentResolver.openInputStream(uri)!!.use { vault.isFileForMe(it) } to fileName(uri)
                }) { (forMe, name) ->
                    if (!forMe) return@work alert("Desencriptar", "Este ficheiro não foi encriptado para nenhuma das tuas chaves.")
                    val plain = Regex("\\.(pgp|gpg|asc)$", RegexOption.IGNORE_CASE).replace(name, "")
                    pickOutput(uri, KIND_FILE_DEC, if (plain != name && plain.isNotEmpty()) plain else "$name.aberto")
                }
                KIND_QR_PUBLIC, KIND_QR_PRIVATE -> work("A ler o código QR…", { readQrImage(uri) }) { text ->
                    if (text == null) alert("QR", "Não encontrei nenhum código QR nesta imagem. Tenta uma fotografia mais nítida e de frente.")
                    else handleQr(kind, text)
                }
                else -> work("A ler o ficheiro…", { readUri(uri) }) { bytes ->
                    when (kind) {
                        KIND_PRIVATE -> keys.importPrivate(bytes)
                        KIND_PUBLIC -> contacts.importPublic(bytes)
                        KIND_MESSAGE -> dec.loadFile(bytes)
                    }
                }
            }
            REQ_SAVE -> {
                if (backupFpr == null) {
                    work("…", { deleteDocument(uri) }) {
                        alert("Backup", "A cópia NÃO foi guardada. Repete o backup.")
                    }
                    return
                }
                work("A guardar a cópia…", {
                    val bytes = Pgp.armor(vault.backupRing(backupFpr)).toByteArray()
                    contentResolver.openOutputStream(uri, "wt")!!.use { it.write(bytes) }
                    // Confirma que ficou bem escrito.
                    if (!readUri(uri).contentEquals(bytes)) throw PgpError("A cópia ficou incompleta. Repete o backup.")
                }) {
                    markBackedUp(backupFpr)
                    alert("Backup", "Cópia da chave privada guardada. Guarda-a num local seguro e offline.")
                }
            }
            REQ_SAVE_FILE -> when {
                input == null -> work("…", { deleteDocument(uri) }) { alert("Ficheiro", "Não ficou nada guardado. Repete a operação.") }
                saveKind == KIND_FILE_ENC -> enc.runFileJob(input, uri)
                else -> dec.decryptFile(input, uri)
            }
        }
    }

    // ------------------------------------------------------------------ códigos QR

    /** Mostra uma chave como código QR. */
    private fun showQr(title: String, key: org.bouncycastle.openpgp.PGPKeyRing, note: String) {
        val side = minOf(resources.displayMetrics.widthPixels, resources.displayMetrics.heightPixels) - dp(96)
        work("A desenhar o QR…", { QrScanner.render(Qr.ofKey(key).second, side) }) { bmp ->
            val box = column(dp(20))
            box.setBackgroundColor(Color.WHITE)
            box.addView(ImageView(this).apply {
                setImageBitmap(bmp)
                // Sem suavizar: os quadrados têm de ficar nítidos para a câmara os ler.
                (drawable as? android.graphics.drawable.BitmapDrawable)?.setFilterBitmap(false)
                adjustViewBounds = true
            }, LinearLayout.LayoutParams(side, side))
            box.addView(TextView(this).apply { this.text = note; setTextColor(Color.BLACK); setPadding(0, dp(12), 0, 0) })
            AlertDialog.Builder(this).setTitle(title).setView(scroll(box)).setPositiveButton("Fechar", null).showSecure()
        }
    }

    /** Lê um QR com a câmara (pedindo a permissão na primeira vez) ou, em alternativa, de uma fotografia. */
    private fun scanQr(kind: String) {
        if (checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
            pendingScan = kind
            return requestPermissions(arrayOf(Manifest.permission.CAMERA), REQ_CAMERA)
        }
        QrScanner(
            this,
            if (kind == KIND_QR_PRIVATE) "Ler o backup em papel" else "Ler a chave de um contacto",
            accept = { Disguise.isDisguised(it) },
            onPhoto = { openFile(kind) },
            onResult = { handleQr(kind, it) },
        ).show()
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode != REQ_CAMERA) return
        val kind = pendingScan ?: return
        pendingScan = null
        if (grantResults.firstOrNull() == PackageManager.PERMISSION_GRANTED) return scanQr(kind)
        confirm(
            "Câmara", "Sem acesso à câmara não consigo ler o código diretamente. Podes tirar uma fotografia ao código " +
                "com a app da câmara e escolhê-la aqui.", "Escolher fotografia",
        ) { openFile(kind) }
    }

    /** Lê um QR de uma imagem escolhida, reduzindo-a primeiro se for muito grande. */
    private fun readQrImage(uri: Uri): String? {
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        contentResolver.openInputStream(uri)!!.use { BitmapFactory.decodeStream(it, null, bounds) }
        var sample = 1
        while (maxOf(bounds.outWidth, bounds.outHeight) / sample > 3200) sample *= 2
        val bmp = contentResolver.openInputStream(uri)!!.use {
            BitmapFactory.decodeStream(it, null, BitmapFactory.Options().apply { inSampleSize = sample })
        } ?: throw PgpError("Não consigo abrir esta imagem.")
        return try { QrScanner.decodeBitmap(bmp) } finally { bmp.recycle() }
    }

    private fun handleQr(kind: String?, text: String) {
        val bytes = Disguise.reveal(text) ?: return alert("QR", "Este código QR não é do Reczi cypher.")
        if (kind == KIND_QR_PRIVATE) {
            show(TAB_KEYS)
            keys.importPrivate(bytes)
        } else {
            show(TAB_CONTACTS)
            contacts.importPublic(bytes)
        }
    }

    /** Texto e cor para mostrar o estado da assinatura de uma mensagem, texto assinado ou ficheiro. */
    private fun signatureText(r: DecryptResult): Pair<String, Int> {
        val who = r.signerName ?: "chave desconhecida"
        return when (val s = r.signature) {
            SignatureStatus.Invalid ->
                "⚠ ASSINATURA INVÁLIDA - o conteúdo foi alterado ou é falso!" to red
            is SignatureStatus.Valid ->
                if (r.signerVerified) "✔ VERIFICADA - assinada por $who." to green
                else "NÃO VERIFICADA - assinada por $who, mas ainda não confirmaste esta chave (${s.fingerprint.takeLast(16)})." to orange
            is SignatureStatus.Rejected ->
                "⚠ ASSINATURA RECUSADA - assinada por $who, mas essa chave foi revogada, expirou ou usa algoritmos fracos. Não confies no remetente." to red
            SignatureStatus.UnknownSigner -> "REMETENTE DESCONHECIDO - assinada por uma chave que não tens." to orange
            SignatureStatus.None -> "SEM ASSINATURA - não é possível confirmar quem a enviou." to orange
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
                        "Para o usar: em Mensagens > Escrever, escolhe um formato disfarçado e só este destinatário."
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
        /** O que aparece no separador (por omissão, o título). */
        open val tab: String get() = title
        /** Explicação curta deste separador, mostrada pelo botão "? Ajuda". */
        abstract val help: String
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
        private val steps = column(0)
        private val list = column(0)
        private val col = column()
        override val view: View = scroll(col)
        override val help get() =
            "Aqui estão as TUAS chaves. Cada chave tem duas partes: a pública, que dás aos outros para te escreverem, e a privada, " +
                "que nunca sai do teu telemóvel e abre o que te enviam.\n\n" +
                "• Partilhar/Copiar pública e Mostrar QR: para dares a tua chave a alguém.\n" +
                "• Backup da privada / Backup em papel: uma cópia fora do telemóvel. Sem ela, se perderes o telemóvel ou desinstalares a app, " +
                "perdes tudo o que te enviaram.\n" +
                "• Prolongar validade: a chave vale 2 anos; prolonga-a e volta a enviar a pública aos contactos.\n" +
                "• Mostrar QR também mostra a impressão digital em palavras, para a confirmares com os teus contactos.\n\n" +
                "A palavra-passe da chave não se recupera: se a esqueceres, a chave fica inútil."

        init {
            col.addView(problems)
            col.addView(steps)
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
                button("Ler QR") { scanQr(KIND_QR_PRIVATE) },
            ))
        }

        override fun refresh() {
            problems.removeAllViews()
            if (snap.broken.isNotEmpty()) problems.addView(brokenCard(snap.broken))
            list.removeAllViews()
            if (snap.myKeys.isEmpty()) list.addView(label("Ainda não tens nenhuma chave."))
            snap.myKeys.forEach { list.addView(keyCard(it)) }
            refreshSteps()
        }

        /** Primeiros passos: uma lista que se vai riscando sozinha, até estar tudo feito (ou a esconderes). */
        private fun refreshSteps() {
            steps.removeAllViews()
            if (prefs.getBoolean(PREF_STEPS_HIDDEN, false)) return
            val backed = backedUp()
            val done = listOf(
                snap.myKeys.isNotEmpty(),
                snap.myKeys.isNotEmpty() && snap.myKeys.all { it.info.fingerprint in backed },
                snap.contacts.isNotEmpty(),
                snap.contacts.any { it.verified },
            )
            if (done.all { it }) return
            val texts = listOf(
                "Cria a tua chave (mais abaixo, \"Criar uma chave nova\").",
                "Faz backup da chave privada para fora do telemóvel (botão \"Backup da privada…\" ou \"Backup em papel…\").",
                "Troca chaves com alguém: envia-lhe a tua (\"Partilhar pública\" ou \"Mostrar QR\") e importa a dele no separador Contactos.",
                "Verifica a chave dele: comparem a impressão digital em pessoa ou por chamada. Depois já podes encriptar para ele.",
            )
            val c = card()
            c.addView(TextView(this@MainActivity).apply { text = "Primeiros passos"; setTypeface(null, Typeface.BOLD) })
            val next = done.indexOf(false)
            texts.forEachIndexed { i, t ->
                c.addView(TextView(this@MainActivity).apply {
                    text = (if (done[i]) "✔ " else "${i + 1}. ") + t
                    setPadding(0, dp(4), 0, 0)
                    if (done[i]) { setTextColor(green) } else if (i == next) setTypeface(null, Typeface.BOLD)
                })
            }
            c.addView(button("Esconder") {
                prefs.edit().putBoolean(PREF_STEPS_HIDDEN, true).apply()
                refreshSteps()
            })
            steps.addView(c)
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
            if (info.fingerprint !in backedUp()) {
                c.addView(TextView(this@MainActivity).apply {
                    text = "⚠ Sem backup registado. Se perderes o telemóvel ou desinstalares a app, perdes esta chave e o que te enviaram."
                    setTextColor(orange)
                })
                c.addView(button("Já tenho backup desta chave") { markBackedUp(info.fingerprint) })
            }
            val pub = Pgp.armor(Pgp.certificateOf(k.ring))
            c.addView(buttonRow(
                button("Partilhar pública") { pickFormat(pub) { share(it) } },
                button("Copiar pública") { pickFormat(pub) { copy(it, sensitive = false) } },
            ))
            c.addView(buttonRow(
                button("Mostrar QR") {
                    showQr(
                        "A tua chave pública", Pgp.certificateOf(k.ring),
                        "${info.userId}\n${Pgp.prettyFingerprint(info.fingerprint)}\n\nEm palavras:\n${wordsOf(info.fingerprint)}\n\n" +
                            "O teu contacto lê este código em Contactos > Ler QR. " +
                            "Depois confirmem os dois que a impressão digital acima é a mesma que aparece no telemóvel dele.",
                    )
                },
                button("Prolongar validade") { extend(k.ring) },
            ))
            c.addView(buttonRow(
                button("Backup da privada…") { backup(info.fingerprint) },
                button("Backup em papel…") { paperBackup(info) },
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
                    markBackedUp(info.fingerprint) // veio de um backup: já existe fora do telemóvel
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

        private fun paperBackup(info: KeyInfo) {
            confirm(
                "Backup em papel",
                "Vais imprimir a chave privada como código QR (e em texto). Continua protegida pela tua palavra-passe, " +
                    "mas imprime só numa impressora tua e NÃO escolhas \"Guardar como PDF\" para a cloud. Guarda o papel num local seguro.",
                "Continuar",
            ) {
                work("A preparar…", {
                    val ring = vault.backupRing(info.fingerprint)
                    Qr.ofKey(ring).second to Pgp.armor(ring)
                }) { (qr, armored) ->
                    val date = DateFormat.getDateInstance(DateFormat.MEDIUM, Locale.forLanguageTag("pt-PT")).format(Date())
                    PaperBackup(this@MainActivity, info.userId, info.fingerprint, date, qr, armored) { markBackedUp(info.fingerprint) }
                        .print(this@MainActivity)
                }
            }
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
        override val help get() =
            "Aqui guardas as chaves PÚBLICAS das pessoas a quem queres escrever.\n\n" +
                "Convidar: envia a tua chave pública com instruções para quem ainda não usa a app.\n" +
                "1. Importa a chave: cola o texto que te enviaram, abre um ficheiro, ou lê o QR do telemóvel da pessoa.\n" +
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
                button("Colar") { input.setText(pasteText()) },
                button("De ficheiro…") { openFile(KIND_PUBLIC) },
                guard(primaryButton("Importar") { importPublic(input.text.toString().toByteArray()) }),
            ))
            col.addView(button("Ler QR do telemóvel do contacto") { scanQr(KIND_QR_PUBLIC) })
            col.addView(heading("Destinatários"))
            col.addView(list)
        }

        override fun refresh() {
            list.removeAllViews()
            val contacts = snap.contacts.sortedBy { it.info.userId.lowercase() }
            if (contacts.isEmpty()) list.addView(label("Ainda não tens destinatários."))
            contacts.forEach { list.addView(contactCard(it)) }
        }

        /** Partilha a tua chave pública com um texto que explica à outra pessoa o que fazer. */
        private fun invite() {
            val mine = snap.myKeys.firstOrNull { it.info.canEncrypt }
                ?: return alert("Convidar", "Cria primeiro a tua chave no separador Chaves.")
            share(
                "Olá! Quero trocar mensagens encriptadas contigo com a app Reczi cypher.\n\n" +
                    "1. Instala o Reczi cypher (eu envio-te a app).\n" +
                    "2. No separador Chaves, cria a tua chave.\n" +
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
            if (c.verified && c.info.canEncrypt) v.addView(primaryButton("Conversa") { messages.converse(c.info.fingerprint) })
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
                // Uma chave no meio de outro texto (um convite com instruções): fica só a chave.
                val text = String(data, Charsets.UTF_8)
                val plain = vault.reveal(text)?.armored?.toByteArray()
                    ?: if ("BEGIN PGP PUBLIC KEY BLOCK" in text) Pgp.extractPublicKeys(text).toByteArray() else data
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
        private val outTitle = heading("Mensagem encriptada")
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
                "• Formato: \"PGP normal\" abre em qualquer programa mas vê-se que é PGP; os \"Disfarçados\" não parecem PGP e só abrem no Reczi cypher.\n" +
                "• Código secreto: aparece com um formato disfarçado e um só destinatário com quem combinaste um código.\n" +
                "• Só assinar: o texto NÃO fica secreto, só leva a tua assinatura.\n" +
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
            col.addView(buttonRow(
                primaryButton("Encriptar") { encrypt() },
                button("Só assinar") { signOnly() },
            ))
            col.addView(button("Encriptar um ficheiro ou fotografia…") { pickFile() })
            outBox.addView(outTitle)
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
            // O formato e a opção do código secreto usados da última vez com este contacto.
            prefs.getInt(PREF_CONTACT_FORMAT + fingerprint, -1).takeIf { it in FORMATS.indices }?.let { format.setSelection(it) }
            if (prefs.contains(PREF_CONTACT_CODE + fingerprint)) useCode.isChecked = prefs.getBoolean(PREF_CONTACT_CODE + fingerprint, true)
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
            // Com um só contacto (além de ti), lembra o formato e o código para a próxima conversa com ele.
            val mine = snap.myKeys.map { it.info.fingerprint }.toSet()
            to.filterNot { it in mine }.singleOrNull()?.let { other ->
                prefs.edit().putInt(PREF_CONTACT_FORMAT + other, fmt).putBoolean(PREF_CONTACT_CODE + other, useCode.isChecked).apply()
            }
            val run = { chars: CharArray? ->
                work("A encriptar…", {
                    try { formatted(vault.encrypt(text, to, me!!, chars != null, chars), fmt, code) } finally { chars?.fill('\u0000') }
                }) { showOutput("Mensagem encriptada", it) }
            }
            if (sign.isChecked) askPassphrase("Assinar", "Palavra-passe da tua chave:") { run(it) } else run(null)
        }

        private fun showOutput(title: String, text: String) {
            outTitle.text = title
            output.setText(text)
            outBox.visibility = View.VISIBLE
            output.post { (view as ScrollView).smoothScrollTo(0, outBox.top) }
        }

        private fun myKey(): String? {
            val me = myFprs.getOrNull(myKeySpinner.selectedItemPosition.coerceAtLeast(0))
            when {
                me != null -> {}
                snap.myKeys.isNotEmpty() -> alert("Chave", "A tua chave expirou ou foi revogada. Usa \"Prolongar validade\" no separador Chaves.")
                else -> alert("Chave", "Cria primeiro a tua chave no separador Chaves.")
            }
            return me
        }

        /** Assina o texto sem o encriptar: fica legível por toda a gente, com a tua assinatura. */
        private fun signOnly() {
            val text = draft.text.toString()
            if (text.isBlank()) return alert("Assinar", "Escreve primeiro o texto.")
            val me = myKey() ?: return
            askPassphrase(
                "Só assinar",
                "O texto NÃO fica encriptado: qualquer pessoa o consegue ler. A assinatura só prova que é teu.\n\nPalavra-passe da tua chave:",
            ) { chars ->
                work("A assinar…", { try { vault.sign(text, me, chars) } finally { chars.fill('\u0000') } }) {
                    showOutput("Texto assinado (não está encriptado)", it)
                }
            }
        }

        /** Encriptar um ficheiro: usa os destinatários, a chave e a opção "Assinar" deste ecrã. */
        private fun pickFile() {
            val to = boxes.filter { it.first.isChecked }.map { it.second }
            val me = myKey() ?: return
            if (to.isEmpty()) return alert("Encriptar ficheiro", "Escolhe primeiro, em \"Para\", pelo menos um destinatário (podes escolher-te a ti).")
            fileJob = Triple(to, me, sign.isChecked)
            openFile(KIND_FILE_ENC)
        }

        fun runFileJob(input: Uri, out: Uri) {
            val job = fileJob
            fileJob = null
            if (job == null) return work("…", { deleteDocument(out) }) { alert("Ficheiro", "Não ficou nada guardado. Repete a operação.") }
            val (to, me, signed) = job
            val run = { chars: CharArray? ->
                work("A encriptar o ficheiro…", {
                    try {
                        val name = fileName(input)
                        writeTo(out) { o -> contentResolver.openInputStream(input)!!.use { i -> vault.encryptFile(i, o, name, to, me, signed, chars) } }
                    } finally {
                        chars?.fill('\u0000')
                    }
                }) {
                    alert(
                        "Ficheiro encriptado",
                        "Ficou guardado onde escolheste (.pgp). Abre em qualquer programa OpenPGP e no Reczi cypher " +
                            "(Mensagens > Ler > Desencriptar um ficheiro). O ficheiro original não foi apagado."
                    )
                }
            }
            if (signed) {
                // Se desistires aqui, o ficheiro de destino (ainda vazio) é apagado.
                askPassphrase("Assinar o ficheiro", "Palavra-passe da tua chave:", onCancel = { work("…", { deleteDocument(out) }) {} }) { run(it) }
            } else {
                run(null)
            }
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
            replyFpr?.let { fpr -> enc.replyTo(fpr); messages.open(write = true) }
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
                button("Colar") { setMessage(pasteText()) },
                button("De ficheiro…") { openFile(KIND_MESSAGE) },
                primaryButton("Desencriptar") { decrypt() },
            ))
            col.addView(label("Um texto só assinado (sem encriptar) também se verifica aqui."))
            col.addView(button("Desencriptar um ficheiro ou fotografia…") { openFile(KIND_FILE_DEC) })
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

        fun decrypt() {
            val msg = fileMessage ?: input.text.toString().trim()
            if (msg.isEmpty()) return
            clearSensitive()
            if (Pgp.isSignedText(msg)) return work("A verificar a assinatura…", { vault.verify(msg) }) { showResult(it, signedOnly = true) }
            work("A verificar…", { vault.isForMe(msg) }) { forMe ->
                if (!forMe) return@work alert("Desencriptar", "Esta mensagem não foi encriptada para nenhuma das tuas chaves.")
                askPassphrase("Desencriptar", "Palavra-passe da tua chave:") { chars ->
                    work("A desencriptar…", {
                        try { vault.decrypt(msg, chars) } finally { chars.fill('\u0000') }
                    }) { showResult(it) }
                }
            }
        }

        /** Desencripta um ficheiro já escolhido para o destino já escolhido. */
        fun decryptFile(input: Uri, out: Uri) {
            askPassphrase("Desencriptar ficheiro", "Palavra-passe da tua chave:", onCancel = { work("…", { deleteDocument(out) }) {} }) { chars ->
                work("A desencriptar o ficheiro…", {
                    try {
                        // Se falhar (ficheiro alterado, palavra-passe errada...), o que já foi escrito é apagado.
                        writeTo(out) { o -> vault.decryptFile({ contentResolver.openInputStream(input)!! }, o, chars) }
                    } finally {
                        chars.fill('\u0000')
                    }
                }) { r ->
                    val original = if (r.text.isEmpty()) "" else "\n\nNome original: ${r.text}"
                    alert("Ficheiro desencriptado", "Ficou guardado onde escolheste.$original\n\n${signatureText(r).first}")
                }
            }
        }

        private fun showResult(r: DecryptResult, signedOnly: Boolean = false) {
            val (text, color) = signatureText(r)
            status.text = when {
                signedOnly -> "$text\nEste texto não estava encriptado, só assinado."
                r.secretCodeWith == null -> text
                else -> "$text\n🔒 Veio fechada com o código secreto combinado com ${r.secretCodeWith}."
            }
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

    /**
     * Mensagens: junta "Escrever" (encriptar) e "Ler" (desencriptar) num só separador, com o
     * "Colar e detetar" por cima. Numa conversa, fica virado para um contacto.
     */
    private inner class MessagesScreen : Screen("Mensagens") {
        private var writing = false
        /** Contacto da conversa aberta (botão "Conversa" nos Contactos), se houver. */
        private var conversation: String? = null
        private val banner = column(0)
        private val readTab = button("Ler") { open(write = false) }
        private val writeTab = button("Escrever") { open(write = true) }
        private val body = FrameLayout(this@MainActivity)
        override val view: View = LinearLayout(this@MainActivity).apply {
            orientation = LinearLayout.VERTICAL
            val top = column().apply { setPadding(dp(16), dp(8), dp(16), 0) }
            // A largura fica curta para não ficar por baixo do botão "? Ajuda".
            top.addView(button("Colar e detetar") { pasteAndRoute() }, LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT))
            top.addView(banner)
            top.addView(buttonRow(readTab, writeTab))
            addView(top)
            addView(body, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))
        }
        override val help get() =
            "\"Colar e detetar\" vê o que copiaste noutra app: uma mensagem vai para Ler, uma chave para os Contactos, um texto normal para Escrever.\n\n" +
                (if (writing) "ESCREVER\n" + enc.help else "LER\n" + dec.help)

        fun open(write: Boolean) {
            writing = write
            show(TAB_MESSAGES)
        }

        /** Abre uma conversa: Escrever já com este contacto, e um atalho para colar o que ele enviou. */
        fun converse(fingerprint: String) {
            conversation = fingerprint
            enc.replyTo(fingerprint)
            open(write = true)
        }

        override fun refresh() {
            banner.removeAllViews()
            val c = snap.contacts.firstOrNull { it.info.fingerprint == conversation && it.verified }
            if (c == null) {
                conversation = null
            } else {
                banner.addView(nameView("Conversa com ${c.info.userId}"))
                banner.addView(buttonRow(
                    button("Colar o que recebi") {
                        val text = pasteText().trim()
                        if (text.isEmpty()) return@button alert("Colar", "A área de transferência está vazia. Copia primeiro a mensagem na outra app.")
                        dec.setMessage(text)
                        open(write = false)
                        dec.decrypt()
                    },
                    button("Responder") { enc.replyTo(c.info.fingerprint); open(write = true) },
                    button("Sair") { conversation = null; refresh() },
                ))
            }
            val active = if (writing) enc else dec
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
            enc.clearSensitive()
            dec.clearSensitive()
        }
    }

    /** Definições: o bloqueio da app e a ajuda geral. */
    private inner class SettingsScreen : Screen("Definições") {
        override val tab get() = "⚙"
        private val lockBox = column(0)
        private val col = column()
        override val view: View = scroll(col)
        override val help get() =
            "Bloqueio da app: trava quem pegar no telemóvel desbloqueado.\n\n" +
                "• Impressão digital / bloqueio do telemóvel: a forma mais cómoda.\n" +
                "• PIN da app: um PIN só desta app. Se o esqueceres sem teres a impressão digital ligada, só reinstalando.\n" +
                "• PIN de pânico: escrito no ecrã de bloqueio, APAGA TUDO e abre a app vazia. Não há volta.\n\n" +
                "O bloqueio não substitui a palavra-passe da chave, que continua a ser pedida para assinar e desencriptar."

        init {
            col.addView(heading("Bloqueio da app"))
            col.addView(lockBox)
            col.addView(heading("Ajuda"))
            col.addView(button("Como funciona") { alert("Como funciona", HOW_IT_WORKS) })
            col.addView(button("Mostrar de novo os primeiros passos") {
                prefs.edit().remove(PREF_STEPS_HIDDEN).apply()
                show(TAB_KEYS)
            })
        }

        override fun refresh() = refreshLock()

        private fun refreshLock() {
            lockBox.removeAllViews()
            lockBox.addView(label(
                "O bloqueio trava quem pegar no telemóvel desbloqueado: pede-se ao abrir a app e depois de 1 minuto fora dela. " +
                    "A palavra-passe da chave continua a ser pedida para assinar e desencriptar."
            ))
            lockBox.addView(CheckBox(this@MainActivity).apply {
                text = "Desbloquear com a impressão digital (ou o bloqueio do telemóvel)"
                isChecked = prefs.getBoolean(PREF_LOCK_BIO, false)
                setOnClickListener {
                    val on = isChecked
                    val km = getSystemService(Context.KEYGUARD_SERVICE) as? KeyguardManager
                    if (on && km?.isDeviceSecure != true) {
                        isChecked = false
                        alert("Bloqueio", "O telemóvel não tem bloqueio de ecrã. Define primeiro um PIN, padrão ou impressão digital nas definições do Android.")
                    } else if (!on && hasPin) {
                        // Desligar a alternativa não precisa de confirmação: o PIN da app continua a proteger.
                        prefs.edit().putBoolean(PREF_LOCK_BIO, false).apply()
                    } else {
                        prefs.edit().putBoolean(PREF_LOCK_BIO, on).apply()
                    }
                }
            })
            if (!hasPin) {
                lockBox.addView(button("Definir um PIN da app…") {
                    askNewPin(
                        "PIN da app",
                        "Um PIN só desta app. Se te esqueceres dele e não tiveres a impressão digital ligada acima, a única saída é " +
                            "reinstalar a app, e perdes o que não tiver backup.",
                    ) { chars -> changePins({ try { vault.setPin(chars) } finally { chars.fill('\u0000') } }) }
                })
                return
            }
            lockBox.addView(label("✔ PIN da app definido."))
            lockBox.addView(buttonRow(
                button("Mudar PIN…") {
                    withCurrentPin {
                        askNewPin("PIN novo", "") { chars -> changePins({ try { vault.setPin(chars) } finally { chars.fill('\u0000') } }) }
                    }
                },
                button("Tirar PIN") {
                    withCurrentPin { changePins({ vault.clearPin() }) }
                },
            ))
            lockBox.addView(label(
                (if (hasPanic) "✔ PIN de pânico definido. " else "") +
                    "PIN de pânico: se o escreveres no ecrã de bloqueio, a app APAGA TUDO (chaves, contactos, notas e códigos) e abre vazia, " +
                    "como se fosse nova. Não há volta: só recuperas o que tiveres em backup."
            ))
            lockBox.addView(buttonRow(*listOfNotNull(
                button(if (hasPanic) "Mudar PIN de pânico…" else "Definir PIN de pânico…") {
                    val missing = snap.myKeys.filter { it.info.fingerprint !in backedUp() }
                    val go = {
                    withCurrentPin {
                        askNewPin("PIN de pânico", "Tem de ser diferente do PIN da app. Escolhe um que não escrevas por engano.") { chars ->
                            changePins({ try { vault.setPanicPin(chars) } finally { chars.fill('\u0000') } }) {
                                alert("PIN de pânico", "Guardado. Confirma que tens backup da chave privada fora do telemóvel.")
                            }
                        }
                    }
                    }
                    if (missing.isEmpty()) go() else confirm(
                        "Sem backup",
                        "Não há backup registado de: ${missing.joinToString(", ") { it.info.userId }}.\n\n" +
                            "O PIN de pânico apaga tudo sem volta. Faz primeiro o backup, a não ser que já o tenhas noutro sítio.",
                        "Continuar mesmo assim",
                    ) { go() }
                },
                if (hasPanic) button("Tirar PIN de pânico") { withCurrentPin { changePins({ vault.clearPanicPin() }) } } else null,
            ).toTypedArray()))
        }
    }

    /** Bloco de notas: cada nota fica encriptada para as tuas chaves; ler pede a palavra-passe. */
    private inner class NotesScreen : Screen("Notas") {
        private val list = column(0)
        private val editorTitle = heading("Nota nova")
        private val noteTitle = field("Título (fica visível na lista, sem palavra-passe)")
        private val body = textArea("Texto da nota", 6)
        private var editing: String? = null
        private val col = column()
        override val view: View = scroll(col)
        override val help get() =
            "Um bloco de notas só teu. O texto de cada nota fica encriptado para a tua chave.\n\n" +
                "• Guardar não pede nada; abrir pede a palavra-passe da tua chave.\n" +
                "• O título fica visível na lista sem palavra-passe: não ponhas lá segredos.\n" +
                "• As notas vivem só neste telemóvel e não entram no backup da chave. Para guardares uma fora daqui, " +
                "encripta o texto para ti em Mensagens > Escrever e guarda o resultado onde quiseres."

        init {
            col.addView(heading("Notas"))
            col.addView(label(
                "O texto de cada nota é encriptado para a tua chave: guardar não pede nada, ler pede a palavra-passe. " +
                    "O título serve só para a reconheceres e NÃO fica protegido pela palavra-passe: não ponhas lá segredos."
            ))
            col.addView(list)
            col.addView(editorTitle)
            col.addView(noteTitle)
            col.addView(body)
            col.addView(buttonRow(
                primaryButton("Guardar") { save() },
                button("Limpar") { clearSensitive() },
            ))
        }

        override fun refresh() {
            list.removeAllViews()
            if (snap.notes.isEmpty()) list.addView(label("Ainda não tens notas."))
            val fmt = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT, Locale.forLanguageTag("pt-PT"))
            snap.notes.forEach { n -> list.addView(noteCard(n, fmt.format(n.saved))) }
        }

        private fun noteCard(n: Note, date: String): View {
            val c = card()
            c.addView(nameView(n.label))
            c.addView(TextView(this@MainActivity).apply { text = date; textSize = 12f })
            c.addView(buttonRow(
                button("Abrir") { open(n) },
                button("Apagar") {
                    confirm("Apagar nota", "Apagar a nota \"${n.label}\"? Não há volta.", "Apagar") {
                        if (editing == n.id) clearSensitive()
                        change("A apagar…", { vault.deleteNote(n.id) })
                    }
                },
            ))
            return c
        }

        private fun open(n: Note) {
            askPassphrase("Abrir nota", "Palavra-passe da tua chave:") { chars ->
                work("A abrir…", { try { vault.readNote(n.id, chars) } finally { chars.fill('\u0000') } }) { text ->
                    editing = n.id
                    editorTitle.text = "A editar: ${n.label}"
                    noteTitle.setText(n.label)
                    body.setText(text)
                    body.post { (view as ScrollView).smoothScrollTo(0, editorTitle.top) }
                }
            }
        }

        private fun save() {
            val label = noteTitle.text.toString()
            val text = body.text.toString()
            if (text.isBlank()) return alert("Notas", "Escreve primeiro a nota.")
            val id = editing
            change("A guardar…", { vault.saveNote(id, label, text) }) {
                clearSensitive()
                Toast.makeText(this@MainActivity, "Nota guardada.", Toast.LENGTH_SHORT).show()
            }
        }

        override fun clearSensitive() {
            editing = null
            editorTitle.text = "Nota nova"
            noteTitle.setText("")
            body.setText("")
        }
    }

    private companion object {
        const val REQ_OPEN = 1
        const val REQ_SAVE = 2
        const val TAB_MESSAGES = 0
        const val TAB_CONTACTS = 1
        const val TAB_KEYS = 3
        const val PREF_CONTACT_FORMAT = "fmt-"
        const val PREF_CONTACT_CODE = "usecode-"
        const val PREF_WELCOMED = "welcomed"
        const val PREF_STEPS_HIDDEN = "stepsHidden"
        const val PREF_BACKED_UP = "backedUp"
        const val HOW_IT_WORKS =
            "O Reczi cypher encripta mensagens de forma que só o destinatário as consegue ler.\n\n" +
                "Cada pessoa tem uma chave com duas partes. A PÚBLICA é como um cadeado aberto: dás a quem quiseres, e quem a tiver pode " +
                "fechar mensagens para ti. A PRIVADA é a única que as abre: fica no teu telemóvel, protegida pela tua palavra-passe.\n\n" +
                "Para falares com alguém: trocam as chaves públicas, confirmam que são as certas (verificar) e, a partir daí, " +
                "encriptas com a chave dele e ele com a tua. O texto encriptado pode ir por qualquer app de mensagens.\n\n" +
                "A app não usa a Internet: és tu que copias ou partilhas o que ela produz."
        const val REQ_SAVE_FILE = 3
        const val REQ_UNLOCK = 4
        const val REQ_CAMERA = 5
        const val STATE_IN = "pendingIn"
        const val STATE_SAVE = "pendingSave"
        const val STATE_SCAN = "pendingScan"
        const val KIND_FILE_ENC = "fileEnc"
        const val KIND_FILE_DEC = "fileDec"
        const val KIND_QR_PUBLIC = "qrPublic"
        const val KIND_QR_PRIVATE = "qrPrivate"
        const val PREF_LOCK_BIO = "lockBio"
        const val PREF_PIN_FAILS = "pinFails"
        const val PREF_PIN_UNTIL = "pinUntil"
        const val LOCK_AFTER_MS = 60_000L
        const val MAX_PIN_WAIT_MS = 3600_000L
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
