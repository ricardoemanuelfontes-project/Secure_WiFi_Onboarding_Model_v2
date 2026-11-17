package app.reczi.pgp

import android.app.AlertDialog
import android.graphics.Typeface
import android.text.InputType
import android.view.View
import android.widget.ArrayAdapter
import android.widget.Spinner
import android.widget.TextView
import app.reczi.pgp.core.Backup
import app.reczi.pgp.core.BrokenEntry
import app.reczi.pgp.core.KeyInfo
import app.reczi.pgp.core.MyKey
import app.reczi.pgp.core.Pgp
import app.reczi.pgp.core.PgpError
import app.reczi.pgp.core.Qr
import org.bouncycastle.openpgp.PGPSecretKeyRing
import java.text.DateFormat
import java.util.Date
import java.util.Locale
import app.reczi.pgp.MainActivity.Companion.KIND_PRIVATE
import app.reczi.pgp.MainActivity.Companion.KIND_QR_PRIVATE
import app.reczi.pgp.MainActivity.Companion.PREF_STEPS_HIDDEN

/** As minhas chaves: criar, importar, partilhar a pública, backup, prolongar, apagar. */
internal class KeysScreen(a: MainActivity) : Screen(a, "Chaves") {
    private val name = field("Nome", InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PERSON_NAME)
    private val email = field("Email", InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS)
    private val pass1 = passwordField("Palavra-passe (mín. ${Pgp.MIN_PASSPHRASE} caracteres)")
    private val pass2 = passwordField("Repete a palavra-passe")
    private val keyType = Spinner(a).apply {
        adapter = ArrayAdapter(
            a, android.R.layout.simple_spinner_dropdown_item,
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
            button("De ficheiro…") { a.openFile(KIND_PRIVATE) },
            button("Colar") {
                val text = a.pasteText()
                importPrivate(text.toByteArray(), fromClipboard = true)
            },
            button("Ler QR") { a.scanQr(KIND_QR_PRIVATE) },
        ))
    }

    override fun refresh() {
        problems.removeAllViews()
        if (a.snap.broken.isNotEmpty()) problems.addView(brokenCard(a.snap.broken))
        list.removeAllViews()
        if (a.snap.myKeys.isEmpty()) list.addView(label("Ainda não tens nenhuma chave."))
        a.snap.myKeys.forEach { list.addView(keyCard(it)) }
        refreshSteps()
    }

    /** Primeiros passos: uma lista que se vai riscando sozinha, até estar tudo feito (ou a esconderes). */
    private fun refreshSteps() {
        steps.removeAllViews()
        if (a.prefs.getBoolean(PREF_STEPS_HIDDEN, false)) return
        val backed = a.backedUp()
        val done = listOf(
            a.snap.myKeys.isNotEmpty(),
            a.snap.myKeys.isNotEmpty() && a.snap.myKeys.all { it.info.fingerprint in backed },
            a.snap.contacts.isNotEmpty(),
            a.snap.contacts.any { it.verified },
        )
        if (done.all { it }) return
        val texts = listOf(
            "Cria a tua chave (mais abaixo, \"Criar uma chave nova\").",
            "Faz backup da chave privada para fora do telemóvel (botão \"Backup…\" da tua chave).",
            "Troca chaves com alguém: envia-lhe a tua (\"Partilhar pública\" ou \"Mostrar QR\") e importa a dele em ☰ > Contactos.",
            "Verifica a chave dele: comparem a impressão digital em pessoa ou por chamada. Depois já podes encriptar para ele.",
        )
        val c = card()
        c.addView(TextView(a).apply { text = "Primeiros passos"; setTypeface(null, Typeface.BOLD) })
        val next = done.indexOf(false)
        texts.forEachIndexed { i, t ->
            c.addView(TextView(a).apply {
                text = (if (done[i]) "✔ " else "${i + 1}. ") + t
                setPadding(0, dp(4), 0, 0)
                if (done[i]) { setTextColor(green) } else if (i == next) setTypeface(null, Typeface.BOLD)
            })
        }
        c.addView(button("Esconder") {
            a.prefs.edit().putBoolean(PREF_STEPS_HIDDEN, true).apply()
            refreshSteps()
        })
        steps.addView(c)
    }

    private fun brokenCard(broken: List<BrokenEntry>): View {
        val c = card()
        c.addView(TextView(a).apply {
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
                a.confirm("Ficheiro com problemas", msg, "Continuar") { a.change("A arrumar…", { a.vault.discardBroken(b.name) }) }
            })
        }
        return c
    }

    private fun keyCard(k: MyKey): View {
        val info = k.info
        val c = card()
        c.addView(nameView(info.userId))
        c.addView(fingerprintView(info.fingerprint))
        val (v, color) = a.validity(info)
        c.addView(TextView(a).apply { text = v; color?.let { setTextColor(it) } })
        if (info.fingerprint !in a.backedUp()) {
            c.addView(TextView(a).apply {
                text = "⚠ Sem backup registado. Se perderes o telemóvel ou desinstalares a app, perdes esta chave e o que te enviaram."
                setTextColor(orange)
            })
            c.addView(button("Já tenho backup desta chave") { a.markBackedUp(info.fingerprint) })
        }
        val pub = Pgp.armor(Pgp.certificateOf(k.ring))
        if (a.quick.has(info.fingerprint)) c.addView(label("✔ Palavra-passe com impressão digital (ou o PIN do telemóvel)."))
        c.addView(buttonRow(
            button("Partilhar pública") { a.pickFormat(pub) { a.share(it) } },
            button("Mostrar QR") {
                a.showQr(
                    "A tua chave pública", Pgp.certificateOf(k.ring),
                    "${info.userId}\n${Pgp.prettyFingerprint(info.fingerprint)}\n\nEm palavras:\n${a.wordsOf(info.fingerprint)}\n\n" +
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
        AlertDialog.Builder(a).setTitle("Backup: ${info.userId}")
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
            "Copiar a chave pública" to { a.pickFormat(pub) { a.copy(it, sensitive = false) } },
            "Enviar a chave pública por email" to { a.email(pub, "A minha chave pública PGP") },
            "Prolongar validade" to { extend(k.ring) },
            "Mudar a palavra-passe" to { changePassphrase(info) },
            if (a.quick.has(info.fingerprint)) "Deixar de usar a impressão digital" to { a.quick.forget(info.fingerprint); refresh() }
            else "Usar a impressão digital em vez da palavra-passe" to { a.enableQuick(info) },
        )
        if (!info.revoked) actions += "Revogar esta chave…" to { revoke(info) }
        actions += "Apagar esta chave…" to { delete(info) }
        AlertDialog.Builder(a).setTitle(info.userId)
            .setItems(actions.map { it.first }.toTypedArray()) { _, i -> actions[i].second() }
            .setNegativeButton("Fechar", null)
            .showSecure()
    }

    private fun changePassphrase(info: KeyInfo) {
        a.askPassphrase("Mudar a palavra-passe", "${info.userId}\n\nPalavra-passe ATUAL:", fieldHint = "Palavra-passe atual") { old ->
            a.askPassphrase(
                "Palavra-passe nova",
                "Mín. ${Pgp.MIN_PASSPHRASE} caracteres. Os backups antigos desta chave continuam com a palavra-passe antiga.",
                repeat = true,
                onCancel = { old.fill('\u0000') },
            ) { new ->
                a.change("A mudar a palavra-passe…", {
                    try { a.vault.changePassphrase(info.fingerprint, old, new) } finally { old.fill('\u0000'); new.fill('\u0000') }
                }) {
                    // A palavra-passe guardada para a impressão digital era a antiga.
                    val hadQuick = a.quick.has(info.fingerprint)
                    a.quick.forget(info.fingerprint)
                    refresh()
                    a.alert(
                        "Palavra-passe mudada",
                        "A partir de agora usa a nova." + (if (hadQuick) " Volta a ligar a impressão digital em Mais opções." else "") +
                            "\n\nFaz um backup novo da chave: os antigos abrem com a palavra-passe antiga.",
                    )
                }
            }
        }
    }

    private fun revocationCertificate(info: KeyInfo) {
        a.keyPassphrase(
            "Certificado de revogação",
            "Cria um ficheiro que, se um dia perderes a chave ou a palavra-passe (ou alguém a apanhar), envias aos teus contactos " +
                "para eles deixarem de a usar. Guarda-o junto ao backup, fora do telemóvel. Criá-lo não revoga nada.\n\nPalavra-passe da tua chave:",
            info.fingerprint,
        ) { chars ->
            a.work("A criar…", { try { a.vault.revocationCertificate(info.fingerprint, chars) } finally { chars.fill('\u0000') } }) { cert ->
                a.saveText("revogacao-${info.fingerprint.takeLast(16)}.asc", cert)
            }
        }
    }

    private fun revoke(info: KeyInfo) {
        val reasons = arrayOf(
            "Alguém pode ter a chave (telemóvel perdido, palavra-passe vista…)",
            "Substituí-a por uma chave nova",
            "Deixei de a usar",
        )
        AlertDialog.Builder(a).setTitle("Porque revogas?")
            .setItems(reasons) { _, i ->
                val reason = listOf(Pgp.RevokeReason.Compromised, Pgp.RevokeReason.Superseded, Pgp.RevokeReason.Retired)[i]
                a.typedConfirm(
                    "Revogar chave",
                    "${info.userId}\n\nRevogar é para sempre: a chave deixa de assinar e, quando enviares a pública revogada, " +
                        "os teus contactos deixam de encriptar para ela. As mensagens antigas continuam a abrir aqui.\n\nEscreve REVOGAR para confirmar:",
                    "REVOGAR",
                ) {
                    a.keyPassphrase("Revogar chave", "Palavra-passe da tua chave:", info.fingerprint) { chars ->
                        a.change("A revogar…", { try { a.vault.revoke(info.fingerprint, chars, reason) } finally { chars.fill('\u0000') } }) { pub ->
                            AlertDialog.Builder(a).setTitle("Chave revogada")
                                .setMessage("Envia agora a chave pública revogada aos teus contactos (e a quem a publicaste). Ao importarem, deixam de a usar.")
                                .setPositiveButton("Partilhar") { _, _ -> a.share(pub) }
                                .setNeutralButton("Email") { _, _ -> a.email(pub, "Revoguei a minha chave PGP") }
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
        a.change(if (rsa) "A criar a chave RSA (pode demorar um minuto ou mais)…" else "A criar a chave…", {
            try {
                Pgp.generate(n, e, chars, rsa = rsa).also { a.vault.addMyKey(it) }
            } finally {
                chars.fill('\u0000')
            }
        }) { key ->
            name.setText(""); email.setText("")
            a.alert(
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
        if (Backup.isBackup(data)) return a.restoreAll(data)
        if (Pgp.isPasswordEncrypted(data)) {
            if (fromClipboard) a.clearClipboard()
            return importPasswordBackup(data)
        }
        a.work("A ler a chave…", {
            Pgp.parseSecretKeys(data).map { ring -> ring to runCatching { Pgp.info(ring) } }
        }) { keys ->
            if (fromClipboard) a.clearClipboard() // não deixar a chave privada na área de transferência
            val ok = keys.mapNotNull { (ring, info) -> info.getOrNull()?.let { ring to it } }
            val bad = keys.filter { it.second.isFailure }.map { (ring, info) ->
                "${Pgp.fingerprint(ring).takeLast(16)}: ${(info.exceptionOrNull() as? PgpError)?.message ?: "chave inválida"}"
            }
            val go = { importNext(ok.toMutableList(), then) }
            if (bad.isNotEmpty()) a.alert("Chaves ignoradas", bad.joinToString("\n"), go) else go()
        }
    }

    /** Backup encriptado com palavra-passe ou código: abre-o e importa o que tem dentro. */
    private fun importPasswordBackup(data: ByteArray) {
        a.askPassphrase(
            "Backup protegido",
            "Este ficheiro é um backup protegido por uma palavra-passe ou por um código de backup " +
                "(por exemplo, o do OpenKeychain, com grupos de algarismos). Escreve-o; os hífenes e espaços tanto faz.",
        ) { chars ->
            a.work("A abrir o backup…", {
                try { Pgp.openPasswordBackup(data, chars) } finally { chars.fill('\u0000') }
            }) { inside ->
                // As chaves públicas de contactos que vierem no backup importam-se no fim.
                val others = Pgp.otherCertificates(inside)
                importPrivate(inside) { if (others.isNotEmpty()) a.contacts.importPublic(others) }
            }
        }
    }

    private fun importNext(queue: MutableList<Pair<PGPSecretKeyRing, KeyInfo>>, then: () -> Unit = {}) {
        val (key, info) = queue.removeFirstOrNull() ?: return then()
        val prot = Pgp.isProtected(key)
        a.askPassphrase(
            "Importar chave",
            if (prot) "${info.userId}\n\nPalavra-passe desta chave:"
            else "${info.userId}\n\nEsta chave não tem palavra-passe. Define uma agora (mín. ${Pgp.MIN_PASSPHRASE} caracteres):",
            repeat = !prot,
        ) { chars ->
            a.change("A importar…", {
                try { a.vault.addMyKey(Pgp.prepareImported(key, chars)) } finally { chars.fill('\u0000') }
            }) {
                a.markBackedUp(info.fingerprint) // veio de um backup: já existe fora do telemóvel
                a.alert("Chave importada", "${info.userId}\n${Pgp.prettyFingerprint(info.fingerprint)}") { importNext(queue, then) }
            }
        }
    }

    fun backup(fingerprint: String) {
        a.confirm(
            "Backup da chave privada",
            "O ficheiro continua protegido pela tua palavra-passe, mas guarda-o só num local offline " +
                "(pen USB, cartão SD guardado). Nunca na cloud, email ou mensagens.",
            "Continuar",
        ) { a.saveBackup(fingerprint) }
    }

    private fun paperBackup(info: KeyInfo) {
        a.confirm(
            "Backup em papel",
            "Vais imprimir a chave privada como código QR (e em texto). Continua protegida pela tua palavra-passe, " +
                "mas imprime só numa impressora tua e NÃO escolhas \"Guardar como PDF\" para a cloud. Guarda o papel num local seguro.",
            "Continuar",
        ) {
            a.work("A preparar…", {
                val ring = a.vault.backupRing(info.fingerprint)
                Qr.ofKey(ring).map { it.modules } to Pgp.armor(ring)
            }) { (qr, armored) ->
                val date = DateFormat.getDateInstance(DateFormat.MEDIUM, Locale.forLanguageTag("pt-PT")).format(Date())
                PaperBackup(a, info.userId, info.fingerprint, date, qr, armored) { a.markBackedUp(info.fingerprint) }
                    .print(a)
            }
        }
    }

    private fun extend(key: PGPSecretKeyRing) {
        a.keyPassphrase("Prolongar validade", "A chave fica válida por mais 2 anos a partir de hoje.", Pgp.fingerprint(key)) { chars ->
            a.change("A atualizar…", {
                try { a.vault.addMyKey(Pgp.extendExpiry(key, chars)) } finally { chars.fill('\u0000') }
            }) {
                a.alert("Validade prolongada", "Volta a enviar a tua chave pública aos teus contactos, para eles também a atualizarem.")
            }
        }
    }

    private fun delete(info: KeyInfo) {
        a.typedConfirm(
            "Apagar chave",
            "Vais apagar a chave PRIVADA de ${info.userId}. Sem backup, deixas de conseguir ler as mensagens enviadas para ela.\n\nEscreve APAGAR para confirmar:",
            "APAGAR",
        ) { a.change("A apagar…", { a.vault.deleteMyKey(info.fingerprint); a.quick.forget(info.fingerprint) }) }
    }
}
