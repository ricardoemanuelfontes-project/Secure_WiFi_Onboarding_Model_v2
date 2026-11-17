package app.reczi.pgp

import android.app.AlertDialog
import android.app.Dialog
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.ActivityInfo
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Looper
import android.os.SystemClock
import android.provider.Settings
import android.text.InputType
import android.view.MotionEvent
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.view.inputmethod.EditorInfo
import android.widget.EditText
import android.widget.TextView
import app.reczi.pgp.core.Pgp
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
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
import org.robolectric.shadows.ShadowSystemClock
import java.io.File
import java.time.Duration
import javax.crypto.KeyGenerator

/**
 * Bateria de ataques: cada teste faz de alguém que tenta tirar alguma coisa da app.
 *
 * - quem tem os ficheiros da app (telemóvel com root, análise forense, cópia de segurança);
 * - outra app instalada no mesmo telemóvel (partilhas maliciosas, capturas de ecrã, toques por cima);
 * - quem pega no telemóvel desbloqueado (PIN da app, área de transferência, ecrã esquecido aberto);
 * - o teclado (aprender o que se escreve).
 *
 * O que estes testes NÃO cobrem está no README (Modelo de ameaça): spyware com root a ler a memória
 * enquanto a app está aberta, o Keystore do telemóvel comprometido, alguém a ver o ecrã por cima do ombro.
 * No Robolectric não há Keystore: o cofre usa uma chave AES comum, guardada só na memória, como no telemóvel.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class AttackTest {
    private lateinit var controller: ActivityController<MainActivity>
    private val activity get() = controller.get()
    private val app get() = RuntimeEnvironment.getApplication()

    // Valores compridos e únicos, para não aparecerem por acaso no meio de bytes cifrados.
    private val pass = "cavalo bateria agrafo correto"
    private val myName = "Anastácia Ferreirinha"
    private val myEmail = "anastacia.ferreirinha@exemplo.pt"
    private val ruiName = "Rui Bartolomeu Vasconcelos"
    private val ruiEmail = "rui.vasconcelos@exemplo.pt"
    private val secretCode = "a sardinha voa ao contrário"
    private val noteTitle = "Plano de Novembro"
    private val noteBody = "a caixa azul está debaixo da escada"
    private val messageText = "encontro às oito na estação de Campanhã"
    private val pin = "246813"

    private lateinit var myFpr: String
    private lateinit var ruiFpr: String
    private lateinit var secrets: List<String>
    private lateinit var secretBytes: List<ByteArray>

    @Before
    fun setUp() {
        val key = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
        shadowOf(app).grantPermissions("android.permission.HIDE_OVERLAY_WINDOWS")
        app.dataDir.listFiles()?.forEach { it.deleteRecursively() }
        prefs().edit().clear().commit()
        Vaults.useForTests(app, key)
        val v = Vaults.vault(app)
        val me = Pgp.generate(myName, myEmail, pass.toCharArray()).also { v.addMyKey(it) }
        val rui = Pgp.generate(ruiName, ruiEmail, pass.toCharArray())
        v.importContacts(listOf(Pgp.certificateOf(rui)))
        myFpr = Pgp.fingerprint(me)
        ruiFpr = Pgp.fingerprint(rui)
        v.setVerified(ruiFpr, true)
        v.setCode(ruiFpr, secretCode.toCharArray())
        v.saveNote(null, noteTitle, noteBody)
        v.setPrefs(mapOf("fmt-$ruiFpr" to "8", "backedup-$myFpr" to "1"))
        val keyIds = (Pgp.keyIds(me) + Pgp.keyIds(Pgp.certificateOf(rui))).map { "%016X".format(it) }
        secrets = listOf(pass, myName, myEmail, ruiName, ruiEmail, secretCode, noteTitle, noteBody, messageText, myFpr, ruiFpr) + keyIds +
            listOf("BEGIN PGP", "Ferreirinha", "Vasconcelos", "sardinha", "Campanh")
        // A chave pública do Rui e a minha, em binário, como estão no cofre (só a parte do meio, sem cabeçalhos).
        secretBytes = listOf(Pgp.certificateOf(rui).encoded, Pgp.certificateOf(me).encoded).map { it.copyOfRange(20, 60) }
    }

    // ------------------------------------------------------------------ ajudas

    private fun prefs() = app.getSharedPreferences("prefs", Context.MODE_PRIVATE)

    private fun launch(intent: Intent? = null) {
        controller = (if (intent == null) Robolectric.buildActivity(MainActivity::class.java) else Robolectric.buildActivity(MainActivity::class.java, intent)).setup()
        waitIdle()
    }

    private fun idle() = shadowOf(Looper.getMainLooper()).idle()

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

    /** Tudo o que se vê: a janela principal e os diálogos abertos. */
    private fun visibleText(): String =
        (screen() + dialogs().flatMap { all(it.window!!.decorView) }).filterIsInstance<TextView>().joinToString("\n") { it.text.toString() }

    private fun click(text: String) {
        val v = (screen() + dialogs().flatMap { all(it.window!!.decorView) }).filterIsInstance<TextView>().firstOrNull { it.text.toString() == text }
        assertNotNull("Não encontrei \"$text\" no ecrã", v)
        assertTrue(v!!.performClick())
        idle()
    }

    private fun field(hint: String): EditText = screen().filterIsInstance<EditText>().first { it.hint?.toString() == hint }

    private fun dismissAlerts() {
        repeat(5) {
            val d = dialogs().lastOrNull() ?: return
            (d.getButton(AlertDialog.BUTTON_POSITIVE) ?: return).performClick()
            idle()
        }
    }

    private fun typePassphrase() {
        waitIdle()
        val d = dialogs().last()
        all(d.window!!.decorView).filterIsInstance<EditText>().first().setText(pass)
        d.getButton(AlertDialog.BUTTON_POSITIVE).performClick()
        idle()
        waitIdle()
    }

    private fun enterPin(p: String) {
        field("PIN").setText(p)
        click("Entrar")
        waitIdle()
    }

    private fun locked() = visibleText().contains("Reczi cypher bloqueada")

    /** Uma mensagem para mim, desencriptada no ecrã Ler (o texto em claro passa pela interface). */
    private fun readAMessage() {
        val msg = Vaults.vault(app).encrypt(messageText, listOf(myFpr), myFpr, false, null, toSelf = false)
        dismissAlerts()
        click("☰")
        click("📥  Ler (desencriptar)")
        field("Cola aqui a mensagem (normal ou disfarçada)").setText(msg)
        click("Desencriptar")
        typePassphrase()
        assertTrue(visibleText().contains(messageText))
    }

    private fun share(text: String?, stream: Uri? = null) = Intent(Intent.ACTION_SEND).apply {
        setClass(app, MainActivity::class.java)
        type = "text/plain"
        if (text != null) putExtra(Intent.EXTRA_TEXT, text)
        if (stream != null) putExtra(Intent.EXTRA_STREAM, stream)
    }

    private fun indexOf(hay: ByteArray, needle: ByteArray): Int {
        if (needle.isEmpty() || hay.size < needle.size) return -1
        outer@ for (i in 0..hay.size - needle.size) {
            for (j in needle.indices) if (hay[i + j] != needle[j]) continue@outer
            return i
        }
        return -1
    }

    // ------------------------------------------------------------------ quem tem os ficheiros

    /**
     * Ataque: telemóvel com root ou análise forense. Copia todos os ficheiros da app depois de um
     * uso normal (chaves, contacto, código secreto, nota, PIN, uma mensagem lida e copiada) e procura
     * lá dentro nomes, emails, fingerprints, ids de chaves, palavra-passe, frase do código, nota,
     * mensagem e as chaves PGP em binário. Não pode encontrar nada.
     */
    @Test
    fun stolenFilesShowNothing() {
        Vaults.vault(app).setPin(pin.toCharArray())
        launch()
        assertTrue(locked())
        enterPin(pin)
        readAMessage()
        click("Copiar (limpa após ~45 s)")
        controller.pause().stop().destroy()

        val files = app.dataDir.walkTopDown().filter { it.isFile }.toList() +
            listOfNotNull(app.externalCacheDir, app.getExternalFilesDir(null)).flatMap { d -> d.walkTopDown().filter { it.isFile }.toList() }
        assertTrue("o cofre devia ter ficheiros", files.size >= 3)
        val found = ArrayList<String>()
        for (f in files) {
            val bytes = f.readBytes()
            for (s in secrets) for (variant in listOf(s, s.uppercase(), s.lowercase())) {
                for (cs in listOf(Charsets.UTF_8, Charsets.UTF_16LE, Charsets.UTF_16BE)) {
                    if (indexOf(bytes, variant.toByteArray(cs)) >= 0) found += "${f.name}: \"$variant\" ($cs)"
                }
            }
            for ((i, b) in secretBytes.withIndex()) if (indexOf(bytes, b) >= 0) found += "${f.name}: chave pública $i em binário"
        }
        // As preferências do Android (em claro) só têm interruptores, sem nada pessoal.
        val plain = prefs().all.toString()
        for (s in secrets + pin) if (plain.contains(s, ignoreCase = true)) found += "preferências: \"$s\""
        assertEquals(emptyList<String>(), found)
        // E os nomes dos ficheiros também não dizem nada.
        val names = files.map { it.name }
        assertFalse(names.toString(), names.any { n -> n.contains(myFpr) || n.contains(ruiFpr) || n.contains("panic") || n.contains("pin") || n.contains("note") })
    }

    /** Ataque: cópia de segurança (adb backup, cloud do Google, passar para um telemóvel novo). */
    @Test
    fun backupsTakeNothing() {
        val info = app.packageManager.getApplicationInfo(app.packageName, 0)
        assertEquals("allowBackup tem de estar desligado", 0, info.flags and ApplicationInfo.FLAG_ALLOW_BACKUP)
        // As regras da cloud e da passagem para outro telemóvel excluem todos os domínios.
        val parser = app.resources.getXml(R.xml.data_extraction_rules)
        val excluded = HashMap<String, MutableSet<String>>()
        var section = ""
        while (parser.next() != org.xmlpull.v1.XmlPullParser.END_DOCUMENT) {
            if (parser.eventType != org.xmlpull.v1.XmlPullParser.START_TAG) continue
            when (parser.name) {
                "cloud-backup", "device-transfer" -> section = parser.name
                "include" -> error("Não pode haver nada incluído na cópia de segurança")
                "exclude" -> {
                    assertEquals(".", parser.getAttributeValue(null, "path"))
                    excluded.getOrPut(section) { HashSet() } += parser.getAttributeValue(null, "domain")
                }
            }
        }
        val everything = setOf("root", "file", "database", "sharedpref", "external")
        assertEquals(everything, excluded["cloud-backup"])
        assertEquals(everything, excluded["device-transfer"])
    }

    // ------------------------------------------------------------------ outra app no mesmo telemóvel

    /**
     * Ataque: outra app procura portas abertas. Só a atividade principal pode ser aberta de fora
     * (e só recebe texto partilhado); nada de serviços, fornecedores de conteúdo ou recetores
     * exportados; sem Internet; tarefa própria (contra o sequestro de tarefas, "StrandHogg").
     */
    @Test
    fun onlyTheFrontDoorIsOpen() {
        val pm = app.packageManager
        @Suppress("DEPRECATION")
        val p = pm.getPackageInfo(
            app.packageName,
            PackageManager.GET_ACTIVITIES or PackageManager.GET_RECEIVERS or PackageManager.GET_SERVICES or
                PackageManager.GET_PROVIDERS or PackageManager.GET_PERMISSIONS,
        )
        val mine = { name: String -> name.startsWith("app.reczi.pgp.") }
        val activities = p.activities.orEmpty().filter { mine(it.name) }
        assertEquals(listOf("app.reczi.pgp.MainActivity"), activities.filter { it.exported }.map { it.name })
        val main = activities.first { it.name == "app.reczi.pgp.MainActivity" }
        assertEquals(ActivityInfo.LAUNCH_SINGLE_TASK, main.launchMode)
        assertEquals("", main.taskAffinity ?: "")
        assertTrue(p.receivers.orEmpty().filter { mine(it.name) }.none { it.exported })
        assertTrue(p.services.orEmpty().none { mine(it.name) })
        assertTrue(p.providers.orEmpty().none { mine(it.name) })
        val perms = p.requestedPermissions.orEmpty().toSet()
        assertFalse("sem Internet", "android.permission.INTERNET" in perms)
        assertTrue(perms.toString(), perms.all {
            it in setOf("android.permission.HIDE_OVERLAY_WINDOWS", "android.permission.CAMERA", "android.permission.USE_BIOMETRIC") ||
                it.endsWith(".DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION")
        })
        // De fora, a atividade só aceita partilhas de texto.
        val send = pm.queryIntentActivities(Intent(Intent.ACTION_SEND).setType("application/octet-stream").setPackage(app.packageName), 0)
        assertTrue(send.isEmpty())
        val view = pm.queryIntentActivities(Intent(Intent.ACTION_VIEW, Uri.parse("content://x/y")).setPackage(app.packageName), 0)
        assertTrue(view.isEmpty())
    }

    /**
     * Ataque: outra app partilha um "ficheiro" que aponta para os ficheiros privados do Reczi
     * (file://…/no_backup/vault/…), à espera que a app o leia com as suas próprias permissões e o
     * mostre. A app só lê texto partilhado e ignora o resto.
     */
    @Test
    fun sharedFilePointingAtTheVaultIsIgnored() {
        launch()
        dismissAlerts()
        val fields = { screen().filterIsInstance<EditText>().map { it.text.toString() } }
        val before = fields()
        val vaultFile = app.noBackupFilesDir.walkTopDown().first { it.isFile }
        val notes = File(app.dataDir, "shared_prefs").walkTopDown().firstOrNull { it.isFile }
        for (target in listOfNotNull(vaultFile, notes)) {
            controller.newIntent(share(null, Uri.fromFile(target)))
            waitIdle()
            // Recusa (não há texto) e não pôs nada em nenhum campo.
            assertTrue(visibleText().contains("Não recebi texto"))
            dismissAlerts()
            assertEquals(before, fields())
        }
    }

    /**
     * Ataque: com a app bloqueada (PIN), outra app partilha texto para a abrir por trás do
     * bloqueio. Só aparece o ecrã do PIN; o menu e o "voltar" não levam a lado nenhum, e o texto
     * só chega depois do PIN certo.
     */
    @Test
    fun sharingDoesNotGetPastTheLock() {
        Vaults.vault(app).setPin(pin.toCharArray())
        launch(share("abre-te sésamo"))
        assertTrue(locked())
        val before = visibleText()
        click("☰")
        activity.onBackPressed()
        idle()
        controller.newIntent(share("outra vez"))
        waitIdle()
        val shown = visibleText()
        assertTrue(locked())
        assertEquals(before, shown)
        for (s in secrets + "abre-te sésamo" + "outra vez") assertFalse("apareceu \"$s\"", shown.contains(s))
        // Com o PIN certo, a partilha segue (a app funciona; só estava bloqueada).
        enterPin(pin)
        dismissAlerts()
        assertFalse(locked())
        assertTrue(screen().filterIsInstance<EditText>().any { it.text.toString() == "outra vez" || it.text.toString() == "abre-te sésamo" })
    }

    /**
     * Ataque: capturas de ecrã, gravação do ecrã e a imagem nas apps recentes. Todas as janelas
     * (a principal e cada diálogo que aparece num uso normal) têm FLAG_SECURE.
     */
    @Test
    fun noScreenshotsAnywhere() {
        launch()
        readAMessage()
        click("? Ajuda")
        dismissAlerts()
        click("☰")
        click("🔑  As minhas chaves")
        dismissAlerts()
        click("Mais opções…")
        idle()
        val windows = listOf(activity.window) + ShadowDialog.getShownDialogs().map(Dialog::getWindow)
        assertTrue("devia ter aberto vários diálogos", windows.size >= 4)
        for (w in windows) {
            assertTrue("janela sem FLAG_SECURE: ${w!!.attributes.title}", w.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE != 0)
            assertTrue(w.decorView.isAccessibilityDataSensitive)
        }
    }

    /**
     * Ataque: uma app desenha por cima do Reczi (invisível ou em parte) para enganar os toques
     * ("tapjacking"). Os botões importantes ignoram toques quando há algo por cima.
     */
    @Test
    fun tapsThroughAnOverlayAreRefused() {
        Vaults.vault(app).setPin(pin.toCharArray())
        launch()
        field("PIN").setText(pin)
        val enter = screen().filterIsInstance<TextView>().first { it.text.toString() == "Entrar" }
        val t = SystemClock.uptimeMillis()
        for (action in listOf(MotionEvent.ACTION_DOWN, MotionEvent.ACTION_UP)) {
            val props = arrayOf(MotionEvent.PointerProperties().apply { id = 0; toolType = MotionEvent.TOOL_TYPE_FINGER })
            val coords = arrayOf(MotionEvent.PointerCoords().apply { x = 5f; y = 5f })
            val ev = MotionEvent.obtain(t, t, action, 1, props, coords, 0, 0, 1f, 1f, 0, 0, 0, MotionEvent.FLAG_WINDOW_IS_OBSCURED)
            enter.dispatchTouchEvent(ev)
            ev.recycle()
        }
        waitIdle()
        assertTrue("um toque por baixo de outra app não pode desbloquear", locked())
        // E o pedido para esconder as janelas das outras apps está feito.
        val privateFlags = WindowManager.LayoutParams::class.java.getField("privateFlags").getInt(activity.window.attributes)
        assertTrue("SYSTEM_FLAG_HIDE_NON_SYSTEM_OVERLAY_WINDOWS", privateFlags and 0x80000 != 0)
    }

    // ------------------------------------------------------------------ quem pega no telemóvel

    /** Ataque: adivinhar o PIN da app. A partir do 5.º erro há espera, e nem o PIN certo entra durante a espera. */
    @Test
    fun guessingThePinIsSlowedDown() {
        Vaults.vault(app).setPin(pin.toCharArray())
        launch()
        repeat(5) { enterPin("000000"); assertTrue(locked()) }
        enterPin(pin)
        assertTrue("o PIN certo não pode entrar durante a espera", locked())
        assertTrue(visibleText().contains("Demasiadas tentativas"))
        // Abrir a app de novo não apaga a espera.
        controller.pause().stop().destroy()
        launch()
        enterPin(pin)
        assertTrue(locked())
        // Passado o tempo, entra.
        ShadowSystemClock.advanceBy(Duration.ofSeconds(31))
        enterPin(pin)
        assertFalse(locked())
    }

    /**
     * Ataque: mudar a hora do telemóvel para saltar a espera do PIN (até à 1.4.4 bastava). Agora a
     * espera conta pelo tempo desde que o telemóvel ligou, e reiniciar faz a espera começar de novo.
     */
    @Test
    fun changingTheClockOrRebootingDoesNotSkipTheWait() {
        Vaults.vault(app).setPin(pin.toCharArray())
        launch()
        repeat(5) { enterPin("000000") }
        // A hora (System.currentTimeMillis) não conta: só o tempo desde que o telemóvel ligou.
        assertFalse(prefs().all.keys.any { it == "pinUntil" })
        // "Reiniciar": a contagem desde que ligou volta ao princípio e o número de arranques muda.
        Settings.Global.putInt(app.contentResolver, Settings.Global.BOOT_COUNT, Settings.Global.getInt(app.contentResolver, Settings.Global.BOOT_COUNT, 0) + 1)
        ShadowSystemClock.advanceBy(Duration.ofSeconds(20))
        enterPin(pin)
        assertTrue("depois de reiniciar a espera começa de novo", locked())
        ShadowSystemClock.advanceBy(Duration.ofSeconds(20))
        enterPin(pin)
        assertTrue(locked())
        ShadowSystemClock.advanceBy(Duration.ofSeconds(15))
        enterPin(pin)
        assertFalse(locked())
    }

    /**
     * Ataque: alguém pega no telemóvel depois de copiares uma mensagem desencriptada. A cópia vai
     * marcada como sensível (o teclado não a mostra) e é apagada ao fim de 45 s, mesmo com a app fechada.
     */
    @Test
    fun copiedSecretsLeaveTheClipboard() {
        launch()
        readAMessage()
        click("Copiar (limpa após ~45 s)")
        val cm = app.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = cm.primaryClip!!
        assertEquals(messageText, clip.getItemAt(0).text.toString())
        assertTrue(clip.description.extras!!.getBoolean(android.content.ClipDescription.EXTRA_IS_SENSITIVE))
        // Há um alarme do sistema para a limpar (funciona com a app fechada).
        val alarm = shadowOf(app.getSystemService(Context.ALARM_SERVICE) as android.app.AlarmManager).peekNextScheduledAlarm()
        assertNotNull(alarm)
        controller.pause().stop().destroy()
        ClipboardClearReceiver().onReceive(app, Intent(app, ClipboardClearReceiver::class.java))
        assertFalse(cm.hasPrimaryClip() && cm.primaryClip!!.getItemAt(0).text?.toString() == messageText)
    }

    /**
     * Ataque: o telemóvel fica esquecido com a mensagem aberta no ecrã. Ao fim de 1 minuto fora da
     * app volta o bloqueio; ao fim de 5 minutos o texto em claro já nem está no ecrã por baixo.
     */
    @Test
    fun forgottenScreenLocksAndForgets() {
        Vaults.vault(app).setPin(pin.toCharArray())
        launch()
        enterPin(pin)
        readAMessage()
        controller.pause().stop()
        ShadowSystemClock.advanceBy(Duration.ofMinutes(6))
        controller.start().resume()
        waitIdle()
        assertTrue(locked())
        assertFalse(visibleText().contains(messageText))
        enterPin(pin)
        dismissAlerts()
        // Depois de desbloquear, a mensagem em claro já não está lá (é preciso desencriptar de novo).
        assertFalse(screen().filterIsInstance<TextView>().any { it.text.toString().contains(messageText) })
    }

    // ------------------------------------------------------------------ o teclado

    /**
     * Ataque: teclados que aprendem e enviam o que se escreve, e o preenchimento automático que
     * guarda palavras-passe. Todos os campos de todos os ecrãs pedem "não aprender" e ficam fora do
     * preenchimento automático; os de palavra-passe e PIN são do tipo palavra-passe.
     */
    @Test
    fun theKeyboardLearnsNothing() {
        launch()
        dismissAlerts()
        val menu = listOf(
            "✉  Escrever (encriptar)", "📥  Ler (desencriptar)", "👥  Contactos", "📝  Notas", "🔑  As minhas chaves", "✍  Assinar e verificar", "⚙  Definições, bloqueio e backup",
        )
        val fields = HashSet<EditText>()
        for (item in menu) {
            click("☰")
            val entry = (screen()).filterIsInstance<TextView>().firstOrNull { it.text.toString() == item } ?: continue
            entry.performClick()
            idle()
            dismissAlerts()
            fields += screen().filterIsInstance<EditText>()
        }
        // E os diálogos de palavra-passe.
        readAMessage()
        fields += ShadowDialog.getShownDialogs().flatMap { all(it.window!!.decorView) }.filterIsInstance<EditText>()
        assertTrue("devia ter encontrado vários campos (${fields.size})", fields.size >= 8)
        for (f in fields) {
            val name = f.hint?.toString() ?: "?"
            assertTrue("\"$name\" deixa o teclado aprender", f.imeOptions and EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING != 0)
            assertEquals("\"$name\" entra no preenchimento automático", View.IMPORTANT_FOR_AUTOFILL_NO, f.importantForAutofill)
            val secret = name.startsWith("Palavra-passe") || name.startsWith("Repete a palavra-passe") || name.startsWith("PIN")
            if (secret) {
                val variation = f.inputType and InputType.TYPE_MASK_VARIATION
                assertTrue(
                    "\"$name\" não é um campo de palavra-passe",
                    variation == InputType.TYPE_TEXT_VARIATION_PASSWORD || variation == InputType.TYPE_NUMBER_VARIATION_PASSWORD,
                )
            }
        }
    }

    // ------------------------------------------------------------------ o código

    /** Ataque: procurar no código registos (logcat) ou ligações à rede por onde algo pudesse sair. */
    @Test
    fun noLogsAndNoNetworkInTheCode() {
        val roots = listOf(File("src/main"), File("../core/src/main")).filter { it.exists() }
        assertTrue(roots.size == 2)
        val banned = listOf(
            Regex("""\bLog\.[vdiwe]\("""), Regex("""\bprintStackTrace\("""), Regex("""\bjava\.net\.(URL|Socket|HttpURLConnection)\b"""),
            Regex("""\bHttpURLConnection\b"""), Regex("""\bnew Socket\(|\bSocket\("""), Regex("""android\.permission\.INTERNET"""),
            Regex("""usesCleartextTraffic"""), Regex("""android:debuggable"""),
        )
        val found = roots.flatMap { r -> r.walkTopDown().filter { it.isFile && (it.extension == "kt" || it.extension == "xml") } }
            // O desfazedor corre no computador e escreve no terminal de propósito.
            .filter { it.name != "Desfazer.kt" }
            .flatMap { f -> f.readLines().withIndex().filter { (_, l) -> !l.trimStart().startsWith("//") && !l.trimStart().startsWith("*") && banned.any { it.containsMatchIn(l) } }.map { "${f.name}:${it.index + 1}: ${it.value.trim()}" } }
        assertEquals(emptyList<String>(), found)
        // println só no desfazedor (no telemóvel iria para o logcat).
        val prints = roots.flatMap { r -> r.walkTopDown().filter { it.isFile && it.extension == "kt" && it.name != "Desfazer.kt" } }
            .filter { f -> f.readText().contains(Regex("""\bprintln\(|\bSystem\.(out|err)\b""")) }.map { it.name }
        assertEquals(emptyList<String>(), prints)
    }
}
