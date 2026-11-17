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
import app.reczi.pgp.core.Backup
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
    private lateinit var screens: List<Screen>
    // Navegação: barra de cima (☰, título, ajuda) e menu lateral.
    private lateinit var menuButton: Button
    private lateinit var titleView: TextView
    private lateinit var drawer: FrameLayout
    private lateinit var drawerPanel: LinearLayout
    private lateinit var signing: SignScreen
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
        signing = SignScreen()
        // A ordem é a dos índices TAB_*: Mensagens (Escrever e Ler), Contactos, Notas, Chaves, Definições, Assinar.
        screens = listOf(messages, contacts, notes, keys, SettingsScreen(), signing)
        val page = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
        }
        page.addView(topBar())
        content = FrameLayout(this)
        page.addView(content, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))
        drawer = buildDrawer()
        val root = FrameLayout(this).apply { fitsSystemWindows = true }
        root.addView(page)
        root.addView(drawer)
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
        menuButton.alpha = 0.4f
        helpButton.visibility = View.GONE
        titleView.text = "Reczi cypher"
        if (::drawer.isInitialized) drawer.visibility = View.GONE
        val bio = prefs.getBoolean(PREF_LOCK_BIO, false)
        val col = column(dp(24))
        col.addView(heading("Reczi cypher bloqueada"))
        if (hasPin) {
            val pin = field("PIN", InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_VARIATION_PASSWORD)
            val msg = label("")
            col.addView(pin)
            col.addView(showToggle(pin))
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
            lines.joinToString("\n") + "\n\nAs tuas: usa Mais opções > \"Prolongar validade\" em ☰ > As minhas chaves e volta a enviar a chave pública. " +
                "As dos contactos: pede-lhes a chave atualizada. Depois de expirar, a app deixa de encriptar para esse contacto até a importares de novo."
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
                "BEGIN PGP PRIVATE KEY BLOCK" in text -> alert(title, "Por segurança, importa chaves privadas a partir de um ficheiro, em ☰ > As minhas chaves.")
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
            setTextColor(BRAND_RED_LIGHT)
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
        alert("Bem-vindo ao Reczi cypher", "$HOW_IT_WORKS\n\nEm ☰ > As minhas chaves tens os primeiros passos, por ordem. O bloqueio da app está em ☰ > Definições. Em cada ecrã há um botão \"? Ajuda\".\n\nJá tinhas chaves (nesta app ou noutro programa)? Importa a chave ou o backup em ☰ > As minhas chaves > Importar.")
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
        menuButton.alpha = 1f
        helpButton.visibility = View.VISIBLE
        titleView.text = screens[i].title
        screens[i].refresh()
    }

    // ------------------------------------------------------------------ navegação: barra e menu lateral

    private fun topBar(): View {
        val bar = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setBackgroundColor(BRAND_BLACK)
        }
        menuButton = Button(this, null, android.R.attr.borderlessButtonStyle).apply {
            text = "☰"
            textSize = 22f
            contentDescription = "Menu"
            setTextColor(Color.WHITE)
            minWidth = dp(56)
            setOnClickListener { openDrawer() }
        }
        titleView = TextView(this).apply {
            setTextColor(Color.WHITE)
            textSize = 18f
            setTypeface(null, Typeface.BOLD)
            maxLines = 1
            ellipsize = TextUtils.TruncateAt.END
            text = "Reczi cypher"
        }
        bar.addView(menuButton)
        bar.addView(titleView, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        bar.addView(helpButton)
        return bar
    }

    /** Entrada do menu: [sub] = indentada dentro de um grupo; [active] = onde estás agora. */
    private class NavItem(val label: String, val active: () -> Boolean, val go: () -> Unit)

    private fun navGroups(): List<Pair<String, List<NavItem>>> = listOf(
        "Mensagens" to listOf(
            NavItem("✉  Escrever (encriptar)", { current == TAB_MESSAGES && messages.writing }) { messages.open(write = true) },
            NavItem("📥  Ler (desencriptar)", { current == TAB_MESSAGES && !messages.writing }) { messages.open(write = false) },
            NavItem("📋  Colar e detetar", { false }) { pasteAndRoute() },
        ),
        "Assinaturas" to listOf(
            NavItem("✍  Assinar e verificar", { current == TAB_SIGN }) { show(TAB_SIGN) },
        ),
        "Pessoas e chaves" to listOf(
            NavItem("👥  Contactos", { current == TAB_CONTACTS }) { show(TAB_CONTACTS) },
            NavItem("🔑  As minhas chaves", { current == TAB_KEYS }) { show(TAB_KEYS) },
        ),
        "Outros" to listOf(
            NavItem("📝  Notas", { current == TAB_NOTES }) { show(TAB_NOTES) },
            NavItem("⚙  Definições, bloqueio e backup", { current == TAB_SETTINGS }) { show(TAB_SETTINGS) },
            NavItem("❓  Como funciona", { false }) { alert("Como funciona", HOW_IT_WORKS) },
        ),
    )

    private fun buildDrawer(): FrameLayout {
        val overlay = FrameLayout(this).apply { visibility = View.GONE }
        // Fundo escurecido: tocar fora do menu fecha-o.
        overlay.addView(View(this).apply {
            setBackgroundColor(0x99000000.toInt())
            setOnClickListener { closeDrawer() }
        })
        drawerPanel = column(0).apply {
            setBackgroundColor(if (isNight) 0xFF1E1E1E.toInt() else Color.WHITE)
            isClickable = true // não deixa passar toques para o ecrã por baixo
        }
        val width = minOf(dp(300), (resources.displayMetrics.widthPixels * 0.82).toInt())
        overlay.addView(scroll(drawerPanel), FrameLayout.LayoutParams(width, ViewGroup.LayoutParams.MATCH_PARENT, Gravity.START))
        return overlay
    }

    private fun refreshDrawer() {
        drawerPanel.removeAllViews()
        drawerPanel.addView(TextView(this).apply {
            text = "Reczi cypher"
            textSize = 20f
            setTypeface(null, Typeface.BOLD)
            setTextColor(Color.WHITE)
            setBackgroundColor(BRAND_BLACK)
            setPadding(dp(20), dp(20), dp(20), dp(20))
        })
        val accent = if (isNight) BRAND_RED_LIGHT else BRAND_RED
        for ((group, items) in navGroups()) {
            drawerPanel.addView(TextView(this).apply {
                text = group.uppercase(Locale.ROOT)
                textSize = 12f
                setTypeface(null, Typeface.BOLD)
                setTextColor(accent)
                setPadding(dp(20), dp(16), dp(20), dp(4))
            })
            for (item in items) {
                val on = item.active()
                drawerPanel.addView(TextView(this).apply {
                    text = item.label
                    textSize = 16f
                    setTypeface(null, if (on) Typeface.BOLD else Typeface.NORMAL)
                    if (on) setBackgroundColor(if (isNight) 0x33FFFFFF else 0x14000000)
                    setPadding(dp(28), dp(12), dp(20), dp(12))
                    isClickable = true
                    isFocusable = true
                    setOnClickListener {
                        closeDrawer()
                        item.go()
                    }
                })
            }
        }
    }

    private fun openDrawer() {
        if (!loaded || locked) return
        refreshDrawer()
        drawer.visibility = View.VISIBLE
        val panel = drawerPanel.parent as View
        panel.translationX = -dp(300).toFloat()
        panel.animate().translationX(0f).setDuration(180).start()
    }

    private fun closeDrawer() {
        if (drawer.visibility != View.VISIBLE) return
        val panel = drawerPanel.parent as View
        panel.animate().translationX(-panel.width.toFloat()).setDuration(150).withEndAction { drawer.visibility = View.GONE }.start()
    }

    @Deprecated("Deprecated in Java")
    override fun onBackPressed() {
        when {
            drawer.visibility == View.VISIBLE -> closeDrawer()
            // Com a app aberta noutro ecrã, "voltar" leva primeiro às Mensagens.
            loaded && !locked && current != TAB_MESSAGES -> show(TAB_MESSAGES)
            else -> @Suppress("DEPRECATION") super.onBackPressed()
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
        onCancel: () -> Unit = {}, extra: View? = null, onOk: (CharArray) -> Unit,
    ) {
        val box = column(dp(20))
        if (hint.isNotEmpty()) box.addView(TextView(this).apply { text = hint })
        val type = if (numeric) InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_VARIATION_PASSWORD
        else InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        val p1 = field(fieldHint, type)
        val p2 = field("Repete", type)
        box.addView(p1)
        if (repeat) box.addView(p2)
        box.addView(showToggle(p1, p2))
        extra?.let { box.addView(it) }
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

    // ------------------------------------------------------------------ palavra-passe com impressão digital

    /**
     * Palavra-passe de uma chave tua. Se estiver guardada (ver [QuickPass]), pede só a impressão digital
     * ou o PIN do telemóvel; senão pede-a escrita, com a opção de a guardar para a próxima vez.
     * [fpr]: a chave a usar. Sem ela, [candidates] são as tuas chaves que servem (as da mensagem, ao
     * desencriptar), ou todas; usa a primeira com a palavra-passe guardada. O CharArray entregue a
     * [onOk] tem de ser apagado por quem o usa.
     */
    private fun keyPassphrase(
        title: String, hint: String, fpr: String? = null, onCancel: () -> Unit = {}, candidates: List<String>? = null,
        onOk: (CharArray) -> Unit,
    ) {
        val keys = fpr?.let { listOf(it) } ?: candidates?.takeIf { it.isNotEmpty() } ?: snap.myKeys.map { it.info.fingerprint }
        val stored = if (quick.available()) keys.filter { quick.has(it) } else emptyList()
        val typed = { typedPassphrase(title, hint, keys.singleOrNull(), onCancel, onOk) }
        val target = stored.firstOrNull() ?: return typed()
        val cipher = quick.decrypter(target) ?: run {
            alert("Impressão digital", "A palavra-passe guardada deixou de servir (por exemplo, juntaste uma impressão digital nova ao telemóvel ou mudaste o bloqueio). Escreve-a e, se quiseres, guarda-a de novo.") { typed() }
            return
        }
        authorize(cipher, title, onFail = typed) { ok ->
            val chars = runCatching { quick.open(target, ok) }.getOrNull() ?: return@authorize typed()
            onOk(chars)
        }
    }

    /** Pede a palavra-passe escrita; [rememberFpr]: chave para a qual se oferece "usar a impressão digital". */
    private fun typedPassphrase(title: String, hint: String, rememberFpr: String?, onCancel: () -> Unit, onOk: (CharArray) -> Unit) {
        val remember = CheckBox(this).apply {
            text = "Da próxima vez, usar a impressão digital (ou o PIN do telemóvel)"
            isChecked = false
        }
        val offer = rememberFpr != null && quick.available() && !quick.has(rememberFpr)
        askPassphrase(title, hint, onCancel = onCancel, extra = remember.takeIf { offer }) { chars ->
            if (offer && remember.isChecked) rememberPassphrase(rememberFpr!!, chars) { onOk(chars) } else onOk(chars)
        }
    }

    /**
     * Guarda [chars] para a chave [fpr] depois de confirmar que é a palavra-passe certa e de o Android
     * confirmar o dono. Não apaga [chars]: no fim chama [then], que fica com essa responsabilidade.
     */
    private fun rememberPassphrase(fpr: String, chars: CharArray, then: () -> Unit) {
        work("A verificar…", { runCatching { Pgp.checkPassphrase(vault.myKey(fpr), chars) }.getOrDefault(false) }) { right ->
            if (!right) return@work alert("Impressão digital", "A palavra-passe está errada, por isso não foi guardada.", then)
            val cipher = try { quick.encrypter() } catch (e: Exception) {
                return@work alert("Impressão digital", "Este telemóvel não deixou guardar a palavra-passe (${e.javaClass.simpleName}).", then)
            }
            authorize(cipher, "Guardar a palavra-passe", onFail = then) { ok ->
                val saved = runCatching { quick.save(fpr, ok, chars) }.isSuccess
                screens[current].refresh()
                if (saved) then() else alert("Impressão digital", "Não foi possível guardar a palavra-passe.", then)
            }
        }
    }

    /** Liga a impressão digital a uma chave a partir do separador Chaves. */
    private fun enableQuick(info: KeyInfo) {
        if (!quick.available()) {
            return alert(
                "Impressão digital",
                "Precisa de Android 11 ou mais recente e de um bloqueio de ecrã definido (impressão digital, PIN, padrão ou palavra-passe)."
            )
        }
        askPassphrase("Usar a impressão digital", "${info.userId}\n\nEscreve uma última vez a palavra-passe desta chave:") { chars ->
            rememberPassphrase(info.fingerprint, chars) {
                chars.fill('\u0000')
                if (quick.has(info.fingerprint)) alert("Impressão digital", "Feito. A partir de agora, onde se pedia a palavra-passe desta chave basta a impressão digital ou o PIN do telemóvel.")
            }
        }
    }

    /** Pede ao Android a impressão digital (ou o PIN do telemóvel) e devolve a cifra autorizada. */
    private fun authorize(cipher: javax.crypto.Cipher, subtitle: String, onFail: () -> Unit, onOk: (javax.crypto.Cipher) -> Unit) {
        if (Build.VERSION.SDK_INT < 30) return onFail()
        BiometricPrompt.Builder(this)
            .setTitle("Reczi cypher")
            .setSubtitle(subtitle)
            .setAllowedAuthenticators(QuickPass.AUTHENTICATORS)
            .build()
            .authenticate(BiometricPrompt.CryptoObject(cipher), CancellationSignal(), mainExecutor, object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult?) {
                    if (isDestroyed) return
                    val ok = result?.cryptoObject?.cipher ?: return onFail()
                    onOk(ok)
                }
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence?) {
                    // Cancelado ou bloqueado: escreve-se a palavra-passe como antes.
                    if (!isDestroyed) onFail()
                }
            })
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
        if (requestCode == REQ_SAVE_TEXT) {
            val text = pendingText
            pendingText = null
            val out = data?.data?.takeIf { resultCode == RESULT_OK } ?: return
            if (text == null) return work("…", { deleteDocument(out) }) { alert("Guardar", "Não ficou nada guardado. Repete a operação.") }
            work("A guardar…", { writeTo(out) { it.write(text.toByteArray(Charsets.UTF_8)) } }) { alert("Guardar", "Ficheiro guardado.") }
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
                    contentResolver.openInputStream(uri)!!.use { vault.myKeysForFile(it) } to fileName(uri)
                }) { (forKeys, name) ->
                    dec.fileKeys = forKeys
                    if (forKeys.isEmpty()) return@work alert("Desencriptar", "Este ficheiro não foi encriptado para nenhuma das tuas chaves.")
                    val plain = Regex("\\.(pgp|gpg|asc)$", RegexOption.IGNORE_CASE).replace(name, "")
                    pickOutput(uri, KIND_FILE_DEC, if (plain != name && plain.isNotEmpty()) plain else "$name.aberto")
                }
                KIND_QR_PUBLIC, KIND_QR_PRIVATE -> work("A ler o código QR…", { readQrImage(uri) }) { text ->
                    if (text == null) return@work alert("QR", "Não encontrei nenhum código QR nesta imagem. Tenta uma fotografia mais nítida e de frente.")
                    // Uma fotografia por código: numa chave grande, pede as seguintes até estarem todas.
                    val asm = qrAssembler ?: Qr.Assembler().also { qrAssembler = it }
                    val (done, message) = feedQr(asm, text)
                    if (done) {
                        qrAssembler = null
                        handleQr(kind, asm.result!!)
                    } else {
                        confirm("QR", message, "Escolher outra fotografia") { openFile(kind) }
                    }
                }
                KIND_BACKUP_ALL -> work("A ler o ficheiro…", { readUri(uri, MAX_BACKUP) }) { bytes -> restoreAll(bytes) }
                KIND_SIGN_FILE -> signing.signFile(uri)
                KIND_VERIFY_DATA -> signing.verifyPickSignature(uri)
                KIND_VERIFY_SIG -> signing.verifyFile(uri)
                else -> work("A ler o ficheiro…", { readUri(uri, if (kind == KIND_PRIVATE) MAX_BACKUP else MAX_FILE) }) { bytes ->
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
            REQ_SAVE_ALL -> saveAll(uri)
            REQ_SAVE_FILE -> when {
                input == null -> work("…", { deleteDocument(uri) }) { alert("Ficheiro", "Não ficou nada guardado. Repete a operação.") }
                saveKind == KIND_FILE_ENC -> enc.runFileJob(input, uri)
                else -> dec.decryptFile(input, uri)
            }
        }
    }

    // ------------------------------------------------------------------ backup completo

    /** Backup completo: pede onde guardar; a palavra-passe é pedida a seguir ([saveAll]). */
    private fun pickBackupAll() {
        if (snap.myKeys.isEmpty()) return alert("Backup completo", "Ainda não tens nenhuma chave para guardar.")
        val day = java.text.SimpleDateFormat("yyyy-MM-dd", Locale.ROOT).format(Date())
        startActivityForResult(
            Intent(Intent.ACTION_CREATE_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType("application/octet-stream")
                .putExtra(Intent.EXTRA_TITLE, "reczi-cypher-backup-$day.rczbak")
                .putExtra(Intent.EXTRA_LOCAL_ONLY, true), // só armazenamento local (não cloud)
            REQ_SAVE_ALL
        )
    }

    private fun saveAll(out: Uri) {
        askPassphrase(
            "Palavra-passe do backup",
            "Escolhe uma palavra-passe para este ficheiro (mín. ${Pgp.MIN_PASSPHRASE} caracteres). Vais precisar dela para o restaurar; " +
                "pode ser a mesma da tua chave. Sem ela, o backup não se abre.",
            repeat = true,
            onCancel = { work("…", { deleteDocument(out) }) {} },
        ) { chars ->
            work("A guardar o backup…", {
                try {
                    val bytes = vault.exportBackup(chars)
                    writeTo(out) { it.write(bytes) }
                    // Confirma que ficou bem escrito.
                    if (!readUri(out, MAX_BACKUP).contentEquals(bytes)) { deleteDocument(out); throw PgpError("O backup ficou incompleto. Repete.") }
                } finally {
                    chars.fill('\u0000')
                }
            }) {
                snap.myKeys.forEach { markBackedUp(it.info.fingerprint) }
                alert(
                    "Backup completo guardado",
                    "Leva as tuas chaves, os contactos (e quais verificaste), os códigos secretos e as notas. " +
                        "Não leva os PINs da app. Guarda o ficheiro num local seguro e offline, e faz um novo quando acrescentares contactos ou notas."
                )
            }
        }
    }

    private fun restoreAll(bytes: ByteArray) {
        // Um ficheiro de uma só chave (.asc) ou um backup de outra app, escolhido em Restaurar: importa-se na mesma.
        if (!Backup.isBackup(bytes)) return keys.importPrivate(bytes)
        askPassphrase("Restaurar backup completo", "Palavra-passe que deste a este backup:") { chars ->
            change("A restaurar…", { try { vault.importBackup(bytes, chars) } finally { chars.fill('\u0000') } }) { r ->
                snap.myKeys.forEach { markBackedUp(it.info.fingerprint) }
                alert(
                    "Backup restaurado",
                    "Acrescentado: ${r.keys} chave(s), ${r.contacts} contacto(s), ${r.codes} código(s) secreto(s) e ${r.notes} nota(s).\n\n" +
                        "O que já existia neste telemóvel ficou como estava."
                )
            }
        }
    }

    // ------------------------------------------------------------------ códigos QR

    /** Mostra uma chave como código QR. */
    private fun showQr(title: String, key: org.bouncycastle.openpgp.PGPKeyRing, note: String) {
        val side = minOf(resources.displayMetrics.widthPixels, resources.displayMetrics.heightPixels) - dp(96)
        work("A desenhar o QR…", { Qr.ofKey(key).map { QrScanner.render(it.modules, side) } }) { bitmaps ->
            val box = column(dp(20))
            box.setBackgroundColor(Color.WHITE)
            val image = ImageView(this).apply { adjustViewBounds = true }
            val which = TextView(this).apply { setTextColor(Color.BLACK); setTypeface(null, Typeface.BOLD); gravity = Gravity.CENTER }
            var index = 0
            fun draw() {
                image.setImageBitmap(bitmaps[index])
                // Sem suavizar: os quadrados têm de ficar nítidos para a câmara os ler.
                (image.drawable as? android.graphics.drawable.BitmapDrawable)?.setFilterBitmap(false)
                which.text = "Código ${index + 1} de ${bitmaps.size}"
            }
            draw()
            box.addView(image, LinearLayout.LayoutParams(side, side))
            if (bitmaps.size > 1) {
                // Chave grande (RSA): vários códigos, que o outro telemóvel lê um a um.
                box.addView(which)
                box.addView(buttonRow(
                    button("◀ Anterior") { index = (index + bitmaps.size - 1) % bitmaps.size; draw() },
                    primaryButton("Seguinte ▶") { index = (index + 1) % bitmaps.size; draw() },
                ))
                box.addView(TextView(this).apply {
                    text = "Esta chave é grande e vai em ${bitmaps.size} códigos. Quem lê vai vendo quais faltam; a ordem não importa."
                    setTextColor(Color.BLACK)
                })
            }
            box.addView(TextView(this).apply { this.text = note; setTextColor(Color.BLACK); setPadding(0, dp(12), 0, 0) })
            AlertDialog.Builder(this).setTitle(title).setView(scroll(box)).setPositiveButton("Fechar", null).showSecure()
        }
    }

    /** Códigos QR lidos até agora (uma chave grande vem em vários; ver [Qr.Assembler]). */
    private var qrAssembler: Qr.Assembler? = null

    /** Junta um código lido aos anteriores. Devolve se a chave já está completa e o que dizer a quem lê. */
    private fun feedQr(asm: Qr.Assembler, text: String): Pair<Boolean, String> = try {
        if (asm.add(text)) true to ""
        else false to "Lidos ${asm.have} de ${asm.total} códigos. Falta(m): ${asm.missing.joinToString(", ")}. Aponta para o seguinte."
    } catch (e: PgpError) {
        false to (e.message ?: "Este código QR não é do Reczi cypher.")
    }

    /** Lê um QR com a câmara (pedindo a permissão na primeira vez) ou, em alternativa, de uma fotografia. */
    private fun scanQr(kind: String) {
        if (checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
            pendingScan = kind
            return requestPermissions(arrayOf(Manifest.permission.CAMERA), REQ_CAMERA)
        }
        val asm = Qr.Assembler()
        qrAssembler = asm
        QrScanner(
            this,
            if (kind == KIND_QR_PRIVATE) "Ler o backup em papel" else "Ler a chave de um contacto",
            accept = { feedQr(asm, it) },
            onPhoto = { openFile(kind) },
            onDone = { qrAssembler = null; handleQr(kind, asm.result!!) },
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
        ) { qrAssembler = Qr.Assembler(); openFile(kind) }
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

    private fun handleQr(kind: String?, bytes: ByteArray) {
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

    private fun readUri(uri: Uri, limit: Int = MAX_FILE): ByteArray = contentResolver.openInputStream(uri)!!.use { input ->
        val bytes = input.readUpTo(limit + 1)
        if (bytes.size > limit) throw PgpError("O ficheiro é demasiado grande.")
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

    /**
     * Abre a app de email com o texto no corpo, em texto simples. Mantém as linhas tal e qual,
     * o que importa nas assinaturas: um email em HTML ou com linhas reformatadas deixa de verificar.
     */
    private fun email(text: String, subject: String = "") {
        val send = Intent(Intent.ACTION_SEND).setType("text/plain")
            .putExtra(Intent.EXTRA_TEXT, text)
            .apply { if (subject.isNotEmpty()) putExtra(Intent.EXTRA_SUBJECT, subject) }
        // Só apps de email (as que tratam "mailto:").
        send.selector = Intent(Intent.ACTION_SENDTO, Uri.parse("mailto:"))
        try {
            startActivity(Intent.createChooser(send, "Enviar por email"))
        } catch (e: android.content.ActivityNotFoundException) {
            alert("Email", "Não encontrei nenhuma app de email. Usa Copiar e cola no teu email (em texto simples, não em HTML).")
        }
    }

    /** Texto à espera de ser guardado no ficheiro que se está a escolher (só em memória). */
    private var pendingText: String? = null

    /** Guarda um texto num ficheiro novo, à escolha (p. ex. uma assinatura .asc ou um certificado de revogação). */
    private fun saveText(name: String, text: String) {
        pendingText = text
        startActivityForResult(
            Intent(Intent.ACTION_CREATE_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType("text/plain")
                .putExtra(Intent.EXTRA_TITLE, name),
            REQ_SAVE_TEXT
        )
    }

    /** Pergunta em que formato partilhar um texto PGP: normal ou disfarçado (ver Disguise no núcleo). */
    private fun pickFormat(armored: String, then: (String) -> Unit) {
        AlertDialog.Builder(this).setTitle("Formato")
            .setItems(FORMATS.map { it.label }.toTypedArray()) { _, i -> then(formatted(armored, FORMATS[i].id, null)) }
            .setNegativeButton("Cancelar", null)
            .showSecure()
    }

    /**
     * [format]: o id do formato ([Format.id]). [codeFpr]: contacto cujo código secreto fecha a camada
     * de fora (só nos formatos disfarçados).
     */
    private fun formatted(armored: String, format: Int, codeFpr: String?): String =
        formatById(format).style?.let { vault.disguise(armored, it, codeFpr) } ?: armored

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
    /** Palavras-passe guardadas para desbloquear com a impressão digital. */
    private val quick by lazy { QuickPass(applicationContext) }

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

    /**
     * Caixa "Mostrar" para ver o que se escreve nos campos de palavra-passe ou PIN (vem desligada).
     * As capturas de ecrã continuam bloqueadas; só protege menos de quem estiver a olhar para o ecrã.
     */
    private fun showToggle(vararg fields: EditText) = CheckBox(this).apply {
        text = "Mostrar"
        setOnClickListener {
            for (f in fields) {
                val cursor = f.selectionEnd
                f.transformationMethod = if (isChecked) null else android.text.method.PasswordTransformationMethod.getInstance()
                f.setSelection(cursor.coerceIn(0, f.length()))
            }
        }
    }

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
        private val keyType = Spinner(this@MainActivity).apply {
            adapter = ArrayAdapter(
                this@MainActivity, android.R.layout.simple_spinner_dropdown_item,
                arrayOf("Tipo: Curve25519 (recomendado)", "Tipo: RSA 4096 (maior e mais lento)"),
            )
        }
        private val problems = column(0)
        private val steps = column(0)
        private val list = column(0)
        private val col = column()
        override val view: View = scroll(col)
        override val help get() =
            "Aqui estão as TUAS chaves. Cada chave tem duas partes: a pública, que dás aos outros para te escreverem, e a privada, " +
                "que nunca sai do teu telemóvel e abre o que te enviam.\n\n" +
                "• Partilhar pública e Mostrar QR: para dares a tua chave a alguém.\n" +
                "• Backup…: a chave privada num ficheiro ou em papel (o backup completo, com contactos e notas, está em ☰ > Definições). " +
                "Sem backup, se perderes o telemóvel ou desinstalares a app, perdes tudo o que te enviaram. Também aqui: o certificado " +
                "de revogação, para guardares com o backup e enviares aos contactos se um dia perderes a chave.\n" +
                "• Mais opções…: copiar ou enviar a pública por email, prolongar validade (a chave vale 2 anos), mudar a palavra-passe, " +
                "impressão digital, revogar e apagar.\n" +
                "• Revogar: para sempre. A chave deixa de assinar e, quando enviares a pública revogada, os contactos deixam de a usar. " +
                "As mensagens antigas continuam a abrir.\n" +
                "• Mostrar QR também mostra a impressão digital em palavras, para a confirmares com os teus contactos.\n" +
                "• Impressão digital (em Mais opções): escreves a palavra-passe uma última vez e depois basta o dedo " +
                "ou o PIN do telemóvel para assinar, desencriptar e abrir notas (Android 11 ou mais recente). Fica guardada no chip de " +
                "segurança do telemóvel e o Android só a solta depois de te reconhecer. Se juntares uma impressão digital nova ao " +
                "telemóvel, deixa de servir e voltas a escrevê-la uma vez. Não substitui o backup: a palavra-passe continua a ser precisa noutro telemóvel.\n" +
                "• Tipo de chave: Curve25519 é o recomendado (chaves e mensagens pequenas, cabe num só QR). RSA 4096 serve se precisares " +
                "de RSA; é maior e mais lento, e o QR e o backup em papel passam a ser vários códigos, lidos um a um. " +
                "Chaves RSA criadas no computador importam-se aqui e funcionam da mesma maneira.\n" +
                "• Os campos de palavra-passe têm uma caixa \"Mostrar\" para veres o que escreves.\n\n" +
                "A palavra-passe da chave não se recupera: se a esqueceres, a chave fica inútil."

        init {
            col.addView(problems)
            col.addView(steps)
            col.addView(heading("As tuas chaves"))
            col.addView(list)
            col.addView(heading("Criar uma chave nova"))
            col.addView(label("Usa uma frase longa como palavra-passe (5 ou mais palavras ao acaso). Sem ela ninguém consegue usar a tua chave, nem tu."))
            listOf(name, email, pass1, pass2).forEach { col.addView(it) }
            col.addView(showToggle(pass1, pass2))
            col.addView(keyType)
            col.addView(guard(primaryButton("Criar chave") { create() }))
            col.addView(heading("Importar a tua chave privada"))
            col.addView(label(
                "Serve o ficheiro .asc do \"Backup…\" de uma chave, o backup completo (.rczbak), um backup com código " +
                    "(p. ex. do OpenKeychain) ou uma chave exportada de outro programa (GnuPG, Kleopatra, Proton…). " +
                    "A app reconhece o tipo sozinha."
            ))
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
                "Faz backup da chave privada para fora do telemóvel (botão \"Backup…\" da tua chave).",
                "Troca chaves com alguém: envia-lhe a tua (\"Partilhar pública\" ou \"Mostrar QR\") e importa a dele em ☰ > Contactos.",
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
            if (quick.has(info.fingerprint)) c.addView(label("✔ Palavra-passe com impressão digital (ou o PIN do telemóvel)."))
            c.addView(buttonRow(
                button("Partilhar pública") { pickFormat(pub) { share(it) } },
                button("Mostrar QR") {
                    showQr(
                        "A tua chave pública", Pgp.certificateOf(k.ring),
                        "${info.userId}\n${Pgp.prettyFingerprint(info.fingerprint)}\n\nEm palavras:\n${wordsOf(info.fingerprint)}\n\n" +
                            "O teu contacto lê este código em Contactos > Ler QR. " +
                            "Depois confirmem os dois que a impressão digital acima é a mesma que aparece no telemóvel dele.",
                    )
                },
            ))
            c.addView(buttonRow(
                button("Backup…") { backupMenu(info) },
                button("Mais opções…") { moreMenu(k, pub) },
            ))
            return c
        }

        /** Submenu "Backup…": as cópias da chave e o certificado de revogação. */
        private fun backupMenu(info: KeyInfo) {
            val items = arrayOf(
                "Guardar a chave privada num ficheiro",
                "Imprimir em papel (QR)",
                "Certificado de revogação (para um dia, se perderes a chave)",
            )
            AlertDialog.Builder(this@MainActivity).setTitle("Backup: ${info.userId}")
                .setItems(items) { _, i ->
                    when (i) {
                        0 -> backup(info.fingerprint)
                        1 -> paperBackup(info)
                        2 -> revocationCertificate(info)
                    }
                }
                .setNegativeButton("Fechar", null)
                .showSecure()
        }

        /** Submenu "Mais opções…": o resto das ações sobre a chave, as perigosas no fim. */
        private fun moreMenu(k: MyKey, pub: String) {
            val info = k.info
            val actions = mutableListOf<Pair<String, () -> Unit>>(
                "Copiar a chave pública" to { pickFormat(pub) { copy(it, sensitive = false) } },
                "Enviar a chave pública por email" to { email(pub, "A minha chave pública PGP") },
                "Prolongar validade" to { extend(k.ring) },
                "Mudar a palavra-passe" to { changePassphrase(info) },
                if (quick.has(info.fingerprint)) "Deixar de usar a impressão digital" to { quick.forget(info.fingerprint); refresh() }
                else "Usar a impressão digital em vez da palavra-passe" to { enableQuick(info) },
            )
            if (!info.revoked) actions += "Revogar esta chave…" to { revoke(info) }
            actions += "Apagar esta chave…" to { delete(info) }
            AlertDialog.Builder(this@MainActivity).setTitle(info.userId)
                .setItems(actions.map { it.first }.toTypedArray()) { _, i -> actions[i].second() }
                .setNegativeButton("Fechar", null)
                .showSecure()
        }

        private fun changePassphrase(info: KeyInfo) {
            askPassphrase("Mudar a palavra-passe", "${info.userId}\n\nPalavra-passe ATUAL:", fieldHint = "Palavra-passe atual") { old ->
                askPassphrase(
                    "Palavra-passe nova",
                    "Mín. ${Pgp.MIN_PASSPHRASE} caracteres. Os backups antigos desta chave continuam com a palavra-passe antiga.",
                    repeat = true,
                    onCancel = { old.fill('\u0000') },
                ) { new ->
                    change("A mudar a palavra-passe…", {
                        try { vault.changePassphrase(info.fingerprint, old, new) } finally { old.fill('\u0000'); new.fill('\u0000') }
                    }) {
                        // A palavra-passe guardada para a impressão digital era a antiga.
                        val hadQuick = quick.has(info.fingerprint)
                        quick.forget(info.fingerprint)
                        refresh()
                        alert(
                            "Palavra-passe mudada",
                            "A partir de agora usa a nova." + (if (hadQuick) " Volta a ligar a impressão digital em Mais opções." else "") +
                                "\n\nFaz um backup novo da chave: os antigos abrem com a palavra-passe antiga.",
                        )
                    }
                }
            }
        }

        private fun revocationCertificate(info: KeyInfo) {
            keyPassphrase(
                "Certificado de revogação",
                "Cria um ficheiro que, se um dia perderes a chave ou a palavra-passe (ou alguém a apanhar), envias aos teus contactos " +
                    "para eles deixarem de a usar. Guarda-o junto ao backup, fora do telemóvel. Criá-lo não revoga nada.\n\nPalavra-passe da tua chave:",
                info.fingerprint,
            ) { chars ->
                work("A criar…", { try { vault.revocationCertificate(info.fingerprint, chars) } finally { chars.fill('\u0000') } }) { cert ->
                    saveText("revogacao-${info.fingerprint.takeLast(16)}.asc", cert)
                }
            }
        }

        private fun revoke(info: KeyInfo) {
            val reasons = arrayOf(
                "Alguém pode ter a chave (telemóvel perdido, palavra-passe vista…)",
                "Substituí-a por uma chave nova",
                "Deixei de a usar",
            )
            AlertDialog.Builder(this@MainActivity).setTitle("Porque revogas?")
                .setItems(reasons) { _, i ->
                    val reason = listOf(Pgp.RevokeReason.Compromised, Pgp.RevokeReason.Superseded, Pgp.RevokeReason.Retired)[i]
                    typedConfirm(
                        "Revogar chave",
                        "${info.userId}\n\nRevogar é para sempre: a chave deixa de assinar e, quando enviares a pública revogada, " +
                            "os teus contactos deixam de encriptar para ela. As mensagens antigas continuam a abrir aqui.\n\nEscreve REVOGAR para confirmar:",
                        "REVOGAR",
                    ) {
                        keyPassphrase("Revogar chave", "Palavra-passe da tua chave:", info.fingerprint) { chars ->
                            change("A revogar…", { try { vault.revoke(info.fingerprint, chars, reason) } finally { chars.fill('\u0000') } }) { pub ->
                                AlertDialog.Builder(this@MainActivity).setTitle("Chave revogada")
                                    .setMessage("Envia agora a chave pública revogada aos teus contactos (e a quem a publicaste). Ao importarem, deixam de a usar.")
                                    .setPositiveButton("Partilhar") { _, _ -> share(pub) }
                                    .setNeutralButton("Email") { _, _ -> email(pub, "Revoguei a minha chave PGP") }
                                    .setNegativeButton("Depois", null)
                                    .showSecure()
                            }
                        }
                    }
                }
                .setNegativeButton("Cancelar", null)
                .showSecure()
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
            val rsa = keyType.selectedItemPosition == 1
            change(if (rsa) "A criar a chave RSA (pode demorar um minuto ou mais)…" else "A criar a chave…", {
                try {
                    Pgp.generate(n, e, chars, rsa = rsa).also { vault.addMyKey(it) }
                } finally {
                    chars.fill('\u0000')
                }
            }) { key ->
                name.setText(""); email.setText("")
                alert(
                    "Chave criada",
                    "Impressão digital:\n${Pgp.prettyFingerprint(Pgp.fingerprint(key))}\n\n" +
                        "Faz já um backup da chave privada (botão \"Backup…\" da chave) para um local seguro. " +
                        "Se desinstalares a app ou perderes o telemóvel sem backup, perdes o acesso às tuas mensagens."
                )
            }
        }

        /**
         * Importa chaves privadas. Também aceita, pela mesma porta, o backup completo (.rczbak) e
         * os backups protegidos com palavra-passe ou código (p. ex. do OpenKeychain): cada um vai
         * para o sítio certo. [then] corre depois da última chave importada.
         */
        fun importPrivate(data: ByteArray, fromClipboard: Boolean = false, then: () -> Unit = {}) {
            if (data.isEmpty()) return
            if (Backup.isBackup(data)) return restoreAll(data)
            if (Pgp.isPasswordEncrypted(data)) {
                if (fromClipboard) clearClipboard()
                return importPasswordBackup(data)
            }
            work("A ler a chave…", {
                Pgp.parseSecretKeys(data).map { ring -> ring to runCatching { Pgp.info(ring) } }
            }) { keys ->
                if (fromClipboard) clearClipboard() // não deixar a chave privada na área de transferência
                val ok = keys.mapNotNull { (ring, info) -> info.getOrNull()?.let { ring to it } }
                val bad = keys.filter { it.second.isFailure }.map { (ring, info) ->
                    "${Pgp.fingerprint(ring).takeLast(16)}: ${(info.exceptionOrNull() as? PgpError)?.message ?: "chave inválida"}"
                }
                val go = { importNext(ok.toMutableList(), then) }
                if (bad.isNotEmpty()) alert("Chaves ignoradas", bad.joinToString("\n"), go) else go()
            }
        }

        /** Backup encriptado com palavra-passe ou código: abre-o e importa o que tem dentro. */
        private fun importPasswordBackup(data: ByteArray) {
            askPassphrase(
                "Backup protegido",
                "Este ficheiro é um backup protegido por uma palavra-passe ou por um código de backup " +
                    "(por exemplo, o do OpenKeychain, com grupos de algarismos). Escreve-o; os hífenes e espaços tanto faz.",
            ) { chars ->
                work("A abrir o backup…", {
                    try { Pgp.openPasswordBackup(data, chars) } finally { chars.fill('\u0000') }
                }) { inside ->
                    // As chaves públicas de contactos que vierem no backup importam-se no fim.
                    val others = Pgp.otherCertificates(inside)
                    importPrivate(inside) { if (others.isNotEmpty()) contacts.importPublic(others) }
                }
            }
        }

        private fun importNext(queue: MutableList<Pair<PGPSecretKeyRing, KeyInfo>>, then: () -> Unit = {}) {
            val (key, info) = queue.removeFirstOrNull() ?: return then()
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
                    alert("Chave importada", "${info.userId}\n${Pgp.prettyFingerprint(info.fingerprint)}") { importNext(queue, then) }
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
                    Qr.ofKey(ring).map { it.modules } to Pgp.armor(ring)
                }) { (qr, armored) ->
                    val date = DateFormat.getDateInstance(DateFormat.MEDIUM, Locale.forLanguageTag("pt-PT")).format(Date())
                    PaperBackup(this@MainActivity, info.userId, info.fingerprint, date, qr, armored) { markBackedUp(info.fingerprint) }
                        .print(this@MainActivity)
                }
            }
        }

        private fun extend(key: PGPSecretKeyRing) {
            keyPassphrase("Prolongar validade", "A chave fica válida por mais 2 anos a partir de hoje.", Pgp.fingerprint(key)) { chars ->
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
            ) { change("A apagar…", { vault.deleteMyKey(info.fingerprint); quick.forget(info.fingerprint) }) }
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
                ?: return alert("Convidar", "Cria primeiro a tua chave em ☰ > As minhas chaves.")
            share(
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
        /** Modo compacto: sem assinatura e sem cópia para ti, para a mensagem (e o poema) ficar mais curta. */
        private val compact = CheckBox(this@MainActivity).apply {
            text = "Modo compacto: mensagem com cerca de metade do tamanho, mas sem assinatura e sem a conseguires reler"
            isChecked = prefs.getBoolean(PREF_COMPACT, false)
        }
        private val format = Spinner(this@MainActivity)
        private val formatHint = label("")
        /** Contacto cujo código secreto pode fechar a camada de fora (um só destinatário, com código). */
        private var codeFpr: String? = null
        private val useCode = CheckBox(this@MainActivity).apply { isChecked = prefs.getBoolean(PREF_USE_CODE, false) }
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
                "diário de viagem, relato de futebol ou letra de rap. Os textos corridos lêem-se como texto normal, mas são compridos: " +
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
                prefs.edit().putBoolean(PREF_COMPACT, compact.isChecked).apply()
                sign.isEnabled = !compact.isChecked
            }
            col.addView(compact)
            col.addView(heading("Formato"))
            format.adapter = ArrayAdapter(this@MainActivity, android.R.layout.simple_spinner_dropdown_item, FORMATS.map { it.label })
            format.setSelection(formatPosition(prefs.getInt(PREF_FORMAT, FORMAT_PGP)))
            format.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
                override fun onItemSelected(parent: AdapterView<*>?, v: View?, position: Int, id: Long) {
                    prefs.edit().putInt(PREF_FORMAT, FORMATS[position].id).apply()
                    updateCode()
                    formatHint.text = FORMATS[position].hint
                }
                override fun onNothingSelected(parent: AdapterView<*>?) {}
            }
            col.addView(format)
            col.addView(formatHint)
            useCode.setOnClickListener { prefs.edit().putBoolean(PREF_USE_CODE, useCode.isChecked).apply() }
            col.addView(useCode)
            col.addView(primaryButton("Encriptar") { encrypt() })
            col.addView(button("Encriptar um ficheiro ou fotografia…") { pickFile() })
            col.addView(label("Para assinar sem encriptar (por exemplo, um email ao CERT), usa ☰ > Assinar e verificar."))
            outBox.addView(outTitle)
            outBox.addView(outNote)
            outBox.addView(output)
            outBox.addView(buttonRow(
                button("Copiar") { copy(output.text.toString(), sensitive = false) },
                button("Partilhar") { share(output.text.toString()) },
                button("Limpar") { clearSensitive() },
            ))
            outBox.addView(button("Enviar por email…") { email(output.text.toString()) })
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
            codeFpr = c?.info?.fingerprint?.takeIf { selectedFormat().id != FORMAT_PGP }
            useCode.text = "Fechar com o código secreto de ${c?.info?.userId ?: ""}"
            useCode.visibility = if (codeFpr != null) View.VISIBLE else View.GONE
        }

        /** Prepara uma resposta: fica escolhido só este destinatário. */
        fun replyTo(fingerprint: String) {
            // O formato e a opção do código secreto usados da última vez com este contacto.
            prefs.getInt(PREF_CONTACT_FORMAT + fingerprint, -1).takeIf { it >= 0 }?.let { format.setSelection(formatPosition(it)) }
            useCode.isChecked = prefs.getBoolean(PREF_CONTACT_CODE + fingerprint, false)
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
            if (snap.myKeys.isEmpty()) {
                // Sem chave tua não há "Eu" nem se pode encriptar: diz porquê e leva lá.
                recipients.addView(label("Ainda não tens a tua chave nesta app, por isso não há destinatários (nem \"Eu\"). Cria-a ou importa-a em ☰ > As minhas chaves."))
                recipients.addView(button("Ir para Chaves") { show(TAB_KEYS) })
            } else if (verified.isEmpty()) {
                recipients.addView(label("Para escrever a outras pessoas, adiciona-as e verifica-as em ☰ > Contactos. Para testar, escolhe \"Eu\"."))
            }
            myFprs = mine.map { it.fingerprint }
            val selected = myKeySpinner.selectedItemPosition
            myKeySpinner.adapter = ArrayAdapter(this@MainActivity, android.R.layout.simple_spinner_dropdown_item, mine.map { "De: ${it.userId}" })
            if (selected in mine.indices) myKeySpinner.setSelection(selected)
            myKeySpinner.visibility = if (mine.size > 1) View.VISIBLE else View.GONE
            if (snap.myKeys.isNotEmpty() && mine.isEmpty()) {
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
                text.isEmpty() -> return alert("Encriptar", "Escreve primeiro a mensagem.")
                me == null && snap.myKeys.isNotEmpty() -> return alert("Encriptar", "A tua chave expirou ou foi revogada. Usa Mais opções > \"Prolongar validade\" em ☰ > As minhas chaves.")
                me == null -> return alert("Encriptar", "Cria primeiro a tua chave em ☰ > As minhas chaves.")
                to.isEmpty() -> return alert("Encriptar", "Escolhe pelo menos um destinatário (podes escolher-te a ti).")
            }
            // Com um só contacto (além de ti), lembra o formato e o código para a próxima conversa com ele.
            val mine = snap.myKeys.map { it.info.fingerprint }.toSet()
            to.filterNot { it in mine }.singleOrNull()?.let { other ->
                prefs.edit().putInt(PREF_CONTACT_FORMAT + other, fmt.id).putBoolean(PREF_CONTACT_CODE + other, useCode.isChecked).apply()
            }
            val run = { chars: CharArray? ->
                work("A encriptar…", {
                    try { formatted(vault.encrypt(text, to, me!!, chars != null, chars, toSelf = !small), fmt.id, code) } finally { chars?.fill('\u0000') }
                }) { out ->
                    showOutput(if (small) "Mensagem encriptada (compacta: não a consegues reler)" else "Mensagem encriptada", out)
                    outNote.text = sizeNote(out, fmt, small)
                    outNote.visibility = if (outNote.text.isEmpty()) View.GONE else View.VISIBLE
                }
            }
            if (sign.isChecked && !small) keyPassphrase("Assinar", "Palavra-passe da tua chave:", me) { run(it) } else run(null)
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
                snap.myKeys.isNotEmpty() -> alert("Chave", "A tua chave expirou ou foi revogada. Usa Mais opções > \"Prolongar validade\" em ☰ > As minhas chaves.")
                else -> alert("Chave", "Cria primeiro a tua chave em ☰ > As minhas chaves.")
            }
            return me
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
                keyPassphrase("Assinar o ficheiro", "Palavra-passe da tua chave:", me, onCancel = { work("…", { deleteDocument(out) }) {} }) { run(it) }
            } else {
                run(null)
            }
        }
    }

    private inner class DecryptScreen : Screen("Desencriptar") {
        /** As tuas chaves para as quais o ficheiro a desencriptar foi feito. */
        var fileKeys: List<String>? = null
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
            work("A verificar…", { vault.myKeysFor(msg) }) { forKeys ->
                if (forKeys.isEmpty()) return@work alert("Desencriptar", "Esta mensagem não foi encriptada para nenhuma das tuas chaves.")
                keyPassphrase("Desencriptar", "Palavra-passe da tua chave:", candidates = forKeys) { chars ->
                    work("A desencriptar…", {
                        try { vault.decrypt(msg, chars) } finally { chars.fill('\u0000') }
                    }) { showResult(it) }
                }
            }
        }

        /** Desencripta um ficheiro já escolhido para o destino já escolhido. */
        fun decryptFile(input: Uri, out: Uri) {
            keyPassphrase(
                "Desencriptar ficheiro", "Palavra-passe da tua chave:", onCancel = { work("…", { deleteDocument(out) }) {} }, candidates = fileKeys,
            ) { chars ->
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
        /** Abre em Escrever: o que se recebe chega a Ler sozinho (Colar e detetar, partilha, Conversa). */
        var writing = true
            private set
        /** Contacto da conversa aberta (botão "Conversa" nos Contactos), se houver. */
        private var conversation: String? = null
        private val banner = column(0)
        private val readTab = button("Ler (desencriptar)") { open(write = false) }
        private val writeTab = button("Escrever (encriptar)") { open(write = true) }
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
            titleView.text = if (writing) "Escrever (encriptar)" else "Ler (desencriptar)"
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

    /**
     * Assinar e verificar, sem encriptar: texto (p. ex. um email ao CERT) e ficheiros com a
     * assinatura à parte (.asc). Quem recebe vê o conteúdo; a assinatura prova que é teu e que
     * não foi alterado.
     */
    private inner class SignScreen : Screen("Assinar e verificar") {
        private val draft = textArea("Texto a assinar", 5)
        private val keySpinner = Spinner(this@MainActivity)
        private var signers = listOf<String>()
        private val output = textArea("", 5, mono = true).apply { keyListener = null; setTextIsSelectable(true) }
        private val outBox = column(0)
        private val check = textArea("Cola aqui o texto assinado que recebeste", 5, mono = true)
        private val checkResult = TextView(this@MainActivity).apply { setPadding(0, dp(8), 0, dp(8)); visibility = View.GONE }
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
                button("Copiar") { copy(output.text.toString(), sensitive = false) },
                button("Partilhar") { share(output.text.toString()) },
            ))
            outBox.addView(button("Enviar por email…") { email(output.text.toString()) })
            outBox.visibility = View.GONE
            col.addView(outBox)

            col.addView(heading("Verificar texto assinado"))
            col.addView(check)
            col.addView(buttonRow(
                button("Colar") { check.setText(pasteText()) },
                primaryButton("Verificar") { verifyText() },
            ))
            col.addView(checkResult)

            col.addView(heading("Ficheiros"))
            col.addView(label("A assinatura fica num ficheiro à parte (.asc); o original não é alterado."))
            col.addView(button("Assinar um ficheiro…") { if (myKey() != null) openFile(KIND_SIGN_FILE) })
            col.addView(button("Verificar um ficheiro…") {
                alert("Verificar ficheiro", "Escolhe primeiro o ficheiro e depois a assinatura (.asc ou .sig).") { openFile(KIND_VERIFY_DATA) }
            })
        }

        override fun refresh() {
            val mine = snap.myKeys.map { it.info }.filter { it.canSign }
            signers = mine.map { it.fingerprint }
            val selected = keySpinner.selectedItemPosition
            keySpinner.adapter = ArrayAdapter(this@MainActivity, android.R.layout.simple_spinner_dropdown_item, mine.map { "Assinar como: ${it.userId}" })
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
                alert(
                    "Assinar",
                    if (snap.myKeys.isEmpty()) "Cria ou importa primeiro a tua chave em ☰ > As minhas chaves."
                    else "A tua chave expirou ou foi revogada: já não pode assinar. Vê em ☰ > As minhas chaves.",
                )
            }
            return me
        }

        private fun signText() {
            val text = draft.text.toString()
            if (text.isBlank()) return alert("Assinar", "Escreve primeiro o texto.")
            val me = myKey() ?: return
            keyPassphrase("Assinar", "O texto NÃO fica encriptado: qualquer pessoa o consegue ler.\n\nPalavra-passe da tua chave:", me) { chars ->
                work("A assinar…", { try { vault.sign(text, me, chars) } finally { chars.fill('\u0000') } }) {
                    output.setText(it)
                    outBox.visibility = View.VISIBLE
                    output.post { (view as ScrollView).smoothScrollTo(0, outBox.top) }
                }
            }
        }

        private fun verifyText() {
            val text = check.text.toString().trim()
            if (text.isEmpty()) return alert("Verificar", "Cola primeiro o texto assinado.")
            if (!Pgp.isSignedText(text)) {
                return alert("Verificar", "Isto não é um texto assinado (falta \"-----BEGIN PGP SIGNED MESSAGE-----\"). Se for uma mensagem encriptada, abre-a em ☰ > Ler.")
            }
            work("A verificar…", { vault.verify(text) }) { r ->
                val (msg, color) = signatureText(r)
                checkResult.text = msg
                checkResult.setTextColor(color)
                checkResult.visibility = View.VISIBLE
            }
        }

        /** Escolhido o ficheiro: pede a palavra-passe, assina e pergunta onde guardar a assinatura. */
        fun signFile(input: Uri) {
            val me = myKey() ?: return
            work("…", { fileName(input) }) { name ->
                keyPassphrase("Assinar ficheiro", "$name\n\nPalavra-passe da tua chave:", me) { chars ->
                    work("A assinar o ficheiro…", {
                        try { contentResolver.openInputStream(input)!!.use { vault.signDetached(it, me, chars) } } finally { chars.fill('\u0000') }
                    }) { sig -> saveText("$name.asc", sig) }
                }
            }
        }

        fun verifyPickSignature(data: Uri) {
            verifyData = data
            openFile(KIND_VERIFY_SIG)
        }

        fun verifyFile(signature: Uri) {
            val data = verifyData ?: return alert("Verificar ficheiro", "Escolhe primeiro o ficheiro e depois a assinatura.")
            verifyData = null
            work("A verificar o ficheiro…", {
                val sig = readUri(signature, MAX_SIGNATURE)
                fileName(data) to vault.verifyDetached({ contentResolver.openInputStream(data)!! }, sig)
            }) { (name, r) ->
                val (msg, _) = signatureText(r)
                alert("Verificar ficheiro", "$name\n\n$msg")
            }
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
                "O bloqueio não substitui a palavra-passe da chave, que continua a ser pedida para assinar e desencriptar.\n\n" +
                "Backup completo: guarda tudo num ficheiro com palavra-passe própria (chaves, contactos, verificações, códigos secretos e notas; " +
                "os PINs não). No telemóvel novo, instala a app e usa Restaurar. O \"Backup…\" de cada chave, em As minhas chaves, guarda só essa chave."

        init {
            col.addView(heading("Bloqueio da app"))
            col.addView(lockBox)
            col.addView(heading("Backup completo"))
            col.addView(label(
                "Um só ficheiro, protegido por uma palavra-passe, com as tuas chaves, os contactos e verificações, os códigos secretos " +
                    "e as notas. Serve para mudar de telemóvel sem refazer tudo. Restaurar junta ao que já cá está, sem apagar nada."
            ))
            col.addView(buttonRow(
                button("Guardar backup…") { pickBackupAll() },
                button("Restaurar…") { openFile(KIND_BACKUP_ALL) },
            ))
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
                    "A palavra-passe da chave continua a ser pedida para assinar e desencriptar; para a trocar pela impressão digital, " +
                    "usa Mais opções > \"Usar a impressão digital\" em ☰ > As minhas chaves."
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
            keyPassphrase("Abrir nota", "Palavra-passe da tua chave:") { chars ->
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
        const val TAB_NOTES = 2
        const val TAB_KEYS = 3
        const val TAB_SETTINGS = 4
        const val TAB_SIGN = 5
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
        const val REQ_SAVE_ALL = 6
        const val KIND_BACKUP_ALL = "backupAll"
        const val MAX_BACKUP = 64 shl 20
        const val REQ_SAVE_FILE = 3
        const val REQ_UNLOCK = 4
        const val REQ_CAMERA = 5
        const val STATE_IN = "pendingIn"
        const val STATE_SAVE = "pendingSave"
        const val STATE_SCAN = "pendingScan"
        const val KIND_FILE_ENC = "fileEnc"
        const val KIND_SIGN_FILE = "signFile"
        /** Um ficheiro de assinatura é pequeno; acima disto não é uma assinatura. */
        const val MAX_SIGNATURE = 1 shl 20
        const val KIND_VERIFY_DATA = "verifyData"
        const val KIND_VERIFY_SIG = "verifySig"
        const val REQ_SAVE_TEXT = 40
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
        // Ids guardados nas preferências: nunca mudar os números (o 2 era "palavras", que já não se oferece).
        const val FORMAT_PGP = 0
        const val FORMAT_CODE = 1
        const val FORMAT_WORDS = 2
        const val FORMAT_POEM = 3
        const val FORMAT_CHRONICLE = 4
        const val FORMAT_TRIP = 5
        const val FORMAT_FOOTBALL = 6
        const val FORMAT_LYRICS = 7
        const val PREF_COMPACT = "compact"
        /** Os formatos oferecidos, pela ordem do menu. */
        val FORMATS = listOf(
            Format(FORMAT_PGP, "PGP normal", null, "",
                "Mensagem PGP normal: abre em qualquer programa OpenPGP (GnuPG, etc.), mas vê-se logo que é PGP."),
            Format(FORMAT_CODE, "Disfarçado: código", Disguise.Style.Code, "",
                "Parece um código ao acaso; não se vê que é PGP. É o mais curto. Só quem usa o Reczi cypher o consegue abrir."),
            Format(FORMAT_POEM, "Disfarçado: poema", Disguise.Style.Poem, "versos",
                "Parece um poema em português, em quadras. Uma mensagem curta dá à volta de 100 versos (cerca de 50 com o modo compacto); " +
                    "com chaves RSA, bastante mais. Só quem usa o Reczi cypher o consegue abrir."),
            Format(FORMAT_CHRONICLE, "Disfarçado: crónica do dia-a-dia", Disguise.Style.Chronicle, "frases",
                "Parece uma carta com as novidades da semana (\"a tia Rosa foi à praça…\"). Lê-se como texto normal, mas é comprido: " +
                    "uma mensagem curta dá à volta de 150 frases (80 com o modo compacto). Só quem usa o Reczi cypher o consegue abrir."),
            Format(FORMAT_TRIP, "Disfarçado: diário de viagem", Disguise.Style.Trip, "frases",
                "Parece o diário de uma viagem por Portugal: terras, tascas, monumentos. É o mais comprido dos textos: " +
                    "uma mensagem curta dá à volta de 200 frases (100 com o modo compacto). Só quem usa o Reczi cypher o consegue abrir."),
            Format(FORMAT_FOOTBALL, "Disfarçado: relato de futebol", Disguise.Style.Football, "frases",
                "Parece o relato de um jogo: cruzamentos, remates, substituições. Uma mensagem curta dá à volta de 150 frases " +
                    "(70 com o modo compacto). Só quem usa o Reczi cypher o consegue abrir."),
            Format(FORMAT_LYRICS, "Disfarçado: letra de rap", Disguise.Style.Lyrics, "barras",
                "Parece uma letra de rap, com barras rimadas aos pares: deuses antigos, futebol, géneros musicais. É o mais curto dos textos: " +
                    "uma mensagem curta dá à volta de 130 barras (65 com o modo compacto). Só quem usa o Reczi cypher o consegue abrir."),
        )

        /** O formato com este id; o antigo "palavras" passa a crónica, e um id desconhecido a PGP normal. */
        fun formatById(id: Int): Format =
            FORMATS.firstOrNull { it.id == (if (id == FORMAT_WORDS) FORMAT_CHRONICLE else id) } ?: FORMATS[0]

        fun formatPosition(id: Int): Int = FORMATS.indexOf(formatById(id))
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

/** Um formato de saída: [style] null é o PGP normal; [unit] é como se conta o tamanho (frases, versos…). */
class Format(val id: Int, val label: String, val style: Disguise.Style?, val unit: String, val hint: String)
