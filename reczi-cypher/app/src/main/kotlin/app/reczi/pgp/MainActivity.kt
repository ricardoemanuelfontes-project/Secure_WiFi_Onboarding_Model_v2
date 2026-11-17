package app.reczi.pgp

import android.Manifest
import android.annotation.SuppressLint
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
import android.graphics.BitmapFactory
import android.graphics.Color
import android.graphics.Typeface
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
import android.provider.Settings
import android.provider.DocumentsContract
import android.provider.OpenableColumns
import android.text.Editable
import android.text.InputType
import android.text.TextUtils
import android.text.TextWatcher
import android.view.Gravity
import android.view.MotionEvent
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import app.reczi.pgp.core.Backup
import app.reczi.pgp.core.Contact
import app.reczi.pgp.core.DecryptResult
import app.reczi.pgp.core.Disguise
import app.reczi.pgp.core.KeyInfo
import app.reczi.pgp.core.Lock
import app.reczi.pgp.core.Pgp
import app.reczi.pgp.core.PgpError
import app.reczi.pgp.core.PinResult
import app.reczi.pgp.core.Qr
import app.reczi.pgp.core.SignatureStatus
import app.reczi.pgp.core.Snapshot
import app.reczi.pgp.core.Vault
import java.text.DateFormat
import java.util.Date
import java.util.Locale

/**
 * Protege uma janela da app (a principal e cada diálogo):
 * - sem capturas nem gravações de ecrã (FLAG_SECURE);
 * - no Android 12+, sem janelas de outras apps por cima;
 * - no Android 14+, o conteúdo fica escondido dos serviços de acessibilidade que não são
 *   ferramentas de acessibilidade. Esses serviços leem tudo o que está no ecrã e são o truque
 *   preferido do spyware; o FLAG_SECURE não os trava. O TalkBack e outras ferramentas a sério
 *   continuam a funcionar.
 */
internal fun protectWindow(w: android.view.Window?) {
    w ?: return
    w.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
    if (Build.VERSION.SDK_INT >= 31) w.setHideOverlayWindows(true)
    if (Build.VERSION.SDK_INT >= 34) w.decorView.setAccessibilityDataSensitive(View.ACCESSIBILITY_DATA_SENSITIVE_YES)
}

class MainActivity : Activity(), Ui {
    override val ctx: Activity get() = this
    private lateinit var store: KeystoreStore
    internal lateinit var vault: Vault
    internal var snap = Snapshot(emptyList(), emptyList(), emptyList())
    internal var loaded = false

    private val worker get() = Vaults.worker
    private val main = Handler(Looper.getMainLooper())
    private var progress: AlertDialog? = null
    private var running = 0

    private lateinit var content: FrameLayout
    private lateinit var screens: List<Screen>
    // Navegação: barra de cima (☰, título, ajuda) e menu lateral.
    private lateinit var menuButton: Button
    internal lateinit var titleView: TextView
    private lateinit var drawer: FrameLayout
    private lateinit var drawerPanel: LinearLayout
    private lateinit var signing: SignScreen
    internal lateinit var messages: MessagesScreen
    internal lateinit var contacts: ContactsScreen
    private lateinit var notes: NotesScreen
    private lateinit var keys: KeysScreen
    internal lateinit var enc: EncryptScreen
    internal lateinit var dec: DecryptScreen
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
    internal var hasPin = false
    internal var hasPanic = false
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

        enc = EncryptScreen(this)
        dec = DecryptScreen(this)
        messages = MessagesScreen(this)
        contacts = ContactsScreen(this)
        notes = NotesScreen(this)
        keys = KeysScreen(this)
        signing = SignScreen(this)
        // A ordem é a dos índices TAB_*: Mensagens (Escrever e Ler), Contactos, Notas, Chaves, Definições, Assinar.
        screens = listOf(messages, contacts, notes, keys, SettingsScreen(this), signing)
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
                if (store.isKeyLost()) Result.failure(VaultKeyLostException()) else {
                    // Até à 1.4.2 havia fingerprints em claro fora do cofre. Se falhar, fica para a próxima abertura.
                    runCatching { movePrefsToVault() }
                    runCatching { QuickPass(this).moveIntoVault() }
                    Result.success(vault.snapshot())
                }
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

    /**
     * Quanto falta esperar depois de demasiados PINs errados. Conta pelo tempo desde que o telemóvel
     * ligou (SystemClock.elapsedRealtime), não pela hora: mudar a hora nas definições não salta a
     * espera. Se o telemóvel reiniciou entretanto (esse tempo volta a zero), a espera começa de novo.
     */
    private fun pinWaitLeft(): Long {
        val wait = prefs.getLong(PREF_PIN_WAIT, 0)
        if (wait <= 0) return 0
        val now = SystemClock.elapsedRealtime()
        val boot = bootCount()
        if (prefs.getInt(PREF_PIN_BOOT, -1) != boot) {
            prefs.edit().putLong(PREF_PIN_DEADLINE, now + wait).putInt(PREF_PIN_BOOT, boot).apply()
            return wait
        }
        return (prefs.getLong(PREF_PIN_DEADLINE, 0) - now).coerceIn(0, wait)
    }

    private fun bootCount(): Int = Settings.Global.getInt(contentResolver, Settings.Global.BOOT_COUNT, 0)

    private fun tryPin(pin: EditText, msg: TextView) {
        val wait = pinWaitLeft()
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
                    prefs.edit().remove(PREF_PIN_FAILS).remove(PREF_PIN_UNTIL).remove(PREF_PIN_WAIT).remove(PREF_PIN_DEADLINE).remove(PREF_PIN_BOOT).apply()
                    unlocked()
                }
                PinResult.Panic -> panic()
                PinResult.Wrong -> {
                    // A partir da 5.ª tentativa errada, cada erro obriga a esperar o dobro (30 s, 1 min, ... até 1 h).
                    val fails = prefs.getInt(PREF_PIN_FAILS, 0) + 1
                    val edit = prefs.edit().putInt(PREF_PIN_FAILS, fails)
                    if (fails >= 5) {
                        val wait = (30_000L shl (fails - 5).coerceAtMost(7)).coerceAtMost(MAX_PIN_WAIT_MS)
                        edit.putLong(PREF_PIN_WAIT, wait).putLong(PREF_PIN_DEADLINE, SystemClock.elapsedRealtime() + wait)
                            .putInt(PREF_PIN_BOOT, bootCount()).remove(PREF_PIN_UNTIL)
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
            // Primeiro a chave do Keystore e os ficheiros, de uma vez: sem a chave, o que sobrar no
            // armazenamento já não se lê. Depois esquece o que estava em memória.
            store.wipe()
            runCatching { vault.wipe() }
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
            enc.forgetChoices()
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
    internal fun askNewPin(title: String, hint: String, onOk: (CharArray) -> Unit) =
        askPassphrase(title, hint, repeat = true, fieldHint = "PIN (mín. ${Lock.MIN_PIN} algarismos)", numeric = true, onOk = onOk)

    /** Antes de mudar ou tirar o bloqueio, confirma o PIN atual. */
    internal fun withCurrentPin(then: () -> Unit) {
        if (!hasPin) return then()
        askPassphrase("PIN atual", "", fieldHint = "PIN", numeric = true) { chars ->
            work("A verificar…", { try { vault.checkPin(chars) } finally { chars.fill('\u0000') } }) { r ->
                if (r == PinResult.Ok) then() else alert("PIN", "PIN errado.")
            }
        }
    }

    /** Guarda uma alteração aos PINs e atualiza o que o ecrã mostra. */
    internal fun changePins(task: () -> Unit, done: () -> Unit = {}) {
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
    internal fun <T> change(label: String, task: () -> T, done: (T) -> Unit = {}) {
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
    internal fun pasteAndRoute() {
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
    internal fun backedUp(): Set<String> =
        vaultPrefs().keys.filter { it.startsWith(VP_BACKED_UP) }.map { it.removePrefix(VP_BACKED_UP) }.toSet()

    internal fun markBackedUp(fingerprint: String) = markBackedUp(listOf(fingerprint))

    internal fun markBackedUp(fingerprints: List<String>) {
        if (fingerprints.isEmpty()) return
        setVaultPrefs(fingerprints.map { VP_BACKED_UP + it to "1" }) { if (loaded && !locked) screens[current].refresh() }
    }

    /**
     * As preferências que dizem com quem e como comunicas ficam no cofre, cifradas (ver
     * [Vault.prefs]); nas preferências do Android só ficam opções sem nada de pessoal.
     */
    internal fun vaultPrefs(): Map<String, String> = runCatching { vault.prefs() }.getOrDefault(emptyMap())

    /** Guarda preferências privadas no cofre, na fila de trabalho (a escrita é cifrada e lenta). */
    internal fun setVaultPrefs(changes: List<Pair<String, String?>>, then: () -> Unit = {}) {
        worker.execute {
            runCatching { vault.setPrefs(changes.toMap()) }
            main.post { if (!isDestroyed) then() }
        }
    }

    /**
     * Até à versão 1.4.2, o formato usado com cada contacto (pelo fingerprint), as chaves com
     * backup e o formato escolhido ficavam nas preferências do Android, em claro. Passam para o
     * cofre e só depois saem das preferências. Corre em segundo plano (por isso commit: tem de ficar gravado).
     */
    @SuppressLint("ApplySharedPref")
    private fun movePrefsToVault() {
        val old = prefs.all.filterKeys {
            it.startsWith(LEGACY_CONTACT_FORMAT) || it.startsWith(LEGACY_CONTACT_CODE) || it == LEGACY_BACKED_UP || it == LEGACY_FORMAT || it == LEGACY_USE_CODE
        }
        if (old.isEmpty()) return
        val moved = HashMap<String, String?>()
        for ((k, v) in old) when {
            k.startsWith(LEGACY_CONTACT_FORMAT) && v is Int -> moved[VP_CONTACT_FORMAT + k.removePrefix(LEGACY_CONTACT_FORMAT)] = v.toString()
            k.startsWith(LEGACY_CONTACT_CODE) && v == true -> moved[VP_CONTACT_CODE + k.removePrefix(LEGACY_CONTACT_CODE)] = "1"
            k == LEGACY_BACKED_UP && v is Set<*> -> v.filterIsInstance<String>().forEach { moved[VP_BACKED_UP + it] = "1" }
            k == LEGACY_FORMAT && v is Int && v != FORMAT_PGP -> moved[VP_FORMAT] = v.toString()
            k == LEGACY_USE_CODE && v == true -> moved[VP_USE_CODE] = "1"
        }
        vault.setPrefs(moved.filterKeys { Vault.isPrefName(it) })
        prefs.edit().apply { old.keys.forEach { remove(it) } }.commit()
    }

    internal fun show(i: Int) {
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

    internal fun <T> work(label: String, task: () -> T, done: (T) -> Unit) {
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

    private fun secureWindow(w: android.view.Window?) = protectWindow(w)

    internal fun alert(title: String, text: String, then: (() -> Unit)? = null) {
        AlertDialog.Builder(this).setTitle(title).setMessage(text)
            .setPositiveButton("OK") { _, _ -> then?.invoke() }
            .setCancelable(then == null)
            .showSecure()
    }

    internal fun confirm(title: String, text: String, yes: String, onYes: () -> Unit) {
        AlertDialog.Builder(this).setTitle(title).setMessage(text)
            .setPositiveButton(yes) { _, _ -> onYes() }
            .setNegativeButton("Cancelar", null)
            .showSecure()
    }

    /** Confirmação que obriga a escrever uma palavra. */
    internal fun typedConfirm(title: String, text: String, word: String, onYes: () -> Unit) {
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
    internal fun askPassphrase(
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
    internal fun keyPassphrase(
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
    internal fun enableQuick(info: KeyInfo) {
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
    internal fun wordsOf(fingerprint: String) = Pgp.fingerprintWords(fingerprint).chunked(5).joinToString("\n") { it.joinToString(" ") }

    /** Mostra a impressão digital (primeiro, em grande) e pede a confirmação de que coincide. */
    internal fun showFingerprintAndVerify(info: KeyInfo) {
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

    internal fun openFile(kind: String) {
        pendingOpen = kind
        startActivityForResult(
            Intent(Intent.ACTION_OPEN_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType("*/*"), REQ_OPEN
        )
    }

    internal fun saveBackup(fingerprint: String) {
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
    internal fun fileName(uri: Uri): String = runCatching {
        contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
            if (c.moveToFirst()) c.getString(0) else null
        }
    }.getOrNull()?.takeIf { it.isNotBlank() } ?: "ficheiro"

    internal fun deleteDocument(uri: Uri) {
        runCatching { DocumentsContract.deleteDocument(contentResolver, uri) }
    }

    /** Escreve em [out]; se [task] falhar, apaga o ficheiro incompleto antes de mostrar o erro. */
    internal fun <T> writeTo(out: Uri, task: (java.io.OutputStream) -> T): T = try {
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
    internal fun pickBackupAll() {
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
                markBackedUp(snap.myKeys.map { it.info.fingerprint })
                alert(
                    "Backup completo guardado",
                    "Leva as tuas chaves, os contactos (e quais verificaste), os códigos secretos e as notas. " +
                        "Não leva os PINs da app. Guarda o ficheiro num local seguro e offline, e faz um novo quando acrescentares contactos ou notas."
                )
            }
        }
    }

    internal fun restoreAll(bytes: ByteArray) {
        // Um ficheiro de uma só chave (.asc) ou um backup de outra app, escolhido em Restaurar: importa-se na mesma.
        if (!Backup.isBackup(bytes)) return keys.importPrivate(bytes)
        askPassphrase("Restaurar backup completo", "Palavra-passe que deste a este backup:") { chars ->
            change("A restaurar…", { try { vault.importBackup(bytes, chars) } finally { chars.fill('\u0000') } }) { r ->
                markBackedUp(snap.myKeys.map { it.info.fingerprint })
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
    internal fun showQr(title: String, key: org.bouncycastle.openpgp.PGPKeyRing, note: String) {
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
    internal fun scanQr(kind: String) {
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
    internal fun signatureText(r: DecryptResult): Pair<String, Int> {
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

    internal fun readUri(uri: Uri, limit: Int = MAX_FILE): ByteArray = contentResolver.openInputStream(uri)!!.use { input ->
        val bytes = input.readUpTo(limit + 1)
        if (bytes.size > limit) throw PgpError("O ficheiro é demasiado grande.")
        bytes
    }

    internal fun copy(text: String, sensitive: Boolean) {
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

    internal fun pasteText(): String {
        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        return cm.primaryClip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.coerceToText(this)?.toString() ?: ""
    }

    internal fun clearClipboard() = ClipboardClearReceiver.clear(applicationContext)

    internal fun share(text: String) {
        startActivity(Intent.createChooser(Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, text), "Partilhar"))
    }

    /**
     * Abre a app de email com o texto no corpo, em texto simples. Mantém as linhas tal e qual,
     * o que importa nas assinaturas: um email em HTML ou com linhas reformatadas deixa de verificar.
     */
    internal fun email(text: String, subject: String = "") {
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
    internal fun saveText(name: String, text: String) {
        pendingText = text
        startActivityForResult(
            Intent(Intent.ACTION_CREATE_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType("text/plain")
                .putExtra(Intent.EXTRA_TITLE, name),
            REQ_SAVE_TEXT
        )
    }

    /** Pergunta em que formato partilhar um texto PGP: normal ou disfarçado (ver Disguise no núcleo). */
    internal fun pickFormat(armored: String, then: (String) -> Unit) {
        AlertDialog.Builder(this).setTitle("Formato")
            .setItems(FORMATS.map { it.label }.toTypedArray()) { _, i -> then(formatted(armored, FORMATS[i].id, null)) }
            .setNegativeButton("Cancelar", null)
            .showSecure()
    }

    /**
     * [format]: o id do formato ([Format.id]). [codeFpr]: contacto cujo código secreto fecha a camada
     * de fora (só nos formatos disfarçados).
     */
    internal fun formatted(armored: String, format: Int, codeFpr: String?): String =
        formatById(format).style?.let { vault.disguise(armored, it, codeFpr) } ?: armored

    /** Combinar (ou mudar) o código secreto com um contacto. */
    internal fun askSecretCode(c: Contact) {
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

    internal val prefs get() = getSharedPreferences("prefs", Context.MODE_PRIVATE)
    /** Palavras-passe guardadas para desbloquear com a impressão digital. */
    internal val quick by lazy { QuickPass(applicationContext) }

    internal fun validity(info: KeyInfo): Pair<String, Int?> {
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

    internal companion object {
        const val REQ_OPEN = 1
        const val REQ_SAVE = 2
        const val TAB_MESSAGES = 0
        const val TAB_CONTACTS = 1
        const val TAB_NOTES = 2
        const val TAB_KEYS = 3
        const val TAB_SETTINGS = 4
        const val TAB_SIGN = 5
        const val PREF_WELCOMED = "welcomed"
        const val PREF_STEPS_HIDDEN = "stepsHidden"
        // Preferências privadas, no cofre (cifradas): dizem com quem e como comunicas.
        const val VP_CONTACT_FORMAT = "fmt-"
        const val VP_CONTACT_CODE = "usecode-"
        const val VP_BACKED_UP = "backedup-"
        const val VP_FORMAT = "format"
        const val VP_USE_CODE = "useCode"
        // Onde ficavam até à 1.4.2, em claro nas preferências do Android (só para as passar para o cofre).
        const val LEGACY_CONTACT_FORMAT = "fmt-"
        const val LEGACY_CONTACT_CODE = "usecode-"
        const val LEGACY_BACKED_UP = "backedUp"
        const val LEGACY_FORMAT = "format"
        const val LEGACY_USE_CODE = "useCode"
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
        /** Até à 1.4.4: a hora até quando esperar (saltava-se mudando a hora). Só para apagar. */
        const val PREF_PIN_UNTIL = "pinUntil"
        const val PREF_PIN_WAIT = "pinWait"
        const val PREF_PIN_DEADLINE = "pinDeadline"
        const val PREF_PIN_BOOT = "pinBoot"
        const val LOCK_AFTER_MS = 60_000L
        const val MAX_PIN_WAIT_MS = 3600_000L
        const val MAX_FILE = 1 shl 20
        const val STATE_OPEN = "pendingOpen"
        const val STATE_BACKUP = "pendingBackup"
        const val KIND_PRIVATE = "private"
        const val KIND_PUBLIC = "public"
        const val KIND_MESSAGE = "message"
        // Ids guardados nas preferências: nunca mudar os números (o 2 era "palavras", que já não se oferece).
        const val FORMAT_PGP = 0
        const val FORMAT_CODE = 1
        const val FORMAT_WORDS = 2
        const val FORMAT_POEM = 3
        const val FORMAT_CHRONICLE = 4
        const val FORMAT_TRIP = 5
        const val FORMAT_FOOTBALL = 6
        const val FORMAT_LYRICS = 7
        const val FORMAT_LYRICS2 = 8
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
            Format(FORMAT_LYRICS2, "Disfarçado: letra de rap 2", Disguise.Style.Lyrics2, "barras",
                "Como a letra de rap, mas mais variada: heróis, musas e criaturas ao lado dos deuses, nunca o mesmo nome duas vezes na " +
                    "mesma barra, e mais formas de começar e acabar (às vezes nenhuma). Uma mensagem curta dá à volta de 150 barras " +
                    "(75 com o modo compacto). Quem recebe precisa do Reczi cypher 1.4.4 ou mais recente.")
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
