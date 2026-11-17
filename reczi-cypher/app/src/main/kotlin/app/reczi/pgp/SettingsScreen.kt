package app.reczi.pgp

import android.app.KeyguardManager
import android.content.Context
import android.view.View
import android.widget.CheckBox
import app.reczi.pgp.MainActivity.Companion.HOW_IT_WORKS
import app.reczi.pgp.MainActivity.Companion.KIND_BACKUP_ALL
import app.reczi.pgp.MainActivity.Companion.PREF_LOCK_BIO
import app.reczi.pgp.MainActivity.Companion.PREF_STEPS_HIDDEN
import app.reczi.pgp.MainActivity.Companion.TAB_KEYS

/** Definições: o bloqueio da app e a ajuda geral. */
internal class SettingsScreen(a: MainActivity) : Screen(a, "Definições") {
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
            button("Guardar backup…") { a.pickBackupAll() },
            button("Restaurar…") { a.openFile(KIND_BACKUP_ALL) },
        ))
        col.addView(heading("Ajuda"))
        col.addView(button("Como funciona") { a.alert("Como funciona", HOW_IT_WORKS) })
        col.addView(button("Mostrar de novo os primeiros passos") {
            a.prefs.edit().remove(PREF_STEPS_HIDDEN).apply()
            a.show(TAB_KEYS)
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
        lockBox.addView(label(
            if (a.vaultUnlockedOnly()) {
                "✔ A chave do cofre só funciona com o telemóvel desbloqueado: com ele bloqueado, nem uma ferramenta que corra " +
                    "como esta app consegue abrir o cofre."
            } else {
                "A chave do cofre funciona sempre que o telemóvel já foi desbloqueado desde que ligou. Prendê-la ao telemóvel " +
                    "desbloqueado só é seguro a partir do Android 15 (antes, tirar o bloqueio de ecrã apagava-a)."
            }
        ))
        lockBox.addView(CheckBox(a).apply {
            text = "Desbloquear com a impressão digital (ou o bloqueio do telemóvel)"
            isChecked = a.prefs.getBoolean(PREF_LOCK_BIO, false)
            setOnClickListener {
                val on = isChecked
                val km = a.getSystemService(Context.KEYGUARD_SERVICE) as? KeyguardManager
                if (on && km?.isDeviceSecure != true) {
                    isChecked = false
                    a.alert("Bloqueio", "O telemóvel não tem bloqueio de ecrã. Define primeiro um PIN, padrão ou impressão digital nas definições do Android.")
                } else if (!on && a.hasPin) {
                    // Desligar a alternativa não precisa de confirmação: o PIN da app continua a proteger.
                    a.prefs.edit().putBoolean(PREF_LOCK_BIO, false).apply()
                } else {
                    a.prefs.edit().putBoolean(PREF_LOCK_BIO, on).apply()
                }
            }
        })
        if (!a.hasPin) {
            lockBox.addView(button("Definir um PIN da app…") {
                a.askNewPin(
                    "PIN da app",
                    "Um PIN só desta app. Se te esqueceres dele e não tiveres a impressão digital ligada acima, a única saída é " +
                        "reinstalar a app, e perdes o que não tiver backup.",
                ) { chars -> a.changePins({ try { a.vault.setPin(chars) } finally { chars.fill('\u0000') } }) }
            })
            return
        }
        lockBox.addView(label("✔ PIN da app definido."))
        lockBox.addView(buttonRow(
            button("Mudar PIN…") {
                a.withCurrentPin {
                    a.askNewPin("PIN novo", "") { chars -> a.changePins({ try { a.vault.setPin(chars) } finally { chars.fill('\u0000') } }) }
                }
            },
            button("Tirar PIN") {
                a.withCurrentPin { a.changePins({ a.vault.clearPin() }) }
            },
        ))
        lockBox.addView(label(
            (if (a.hasPanic) "✔ PIN de pânico definido. " else "") +
                "PIN de pânico: se o escreveres no ecrã de bloqueio, a app APAGA TUDO (chaves, contactos, notas e códigos) e abre vazia, " +
                "como se fosse nova. Não há volta: só recuperas o que tiveres em backup."
        ))
        lockBox.addView(buttonRow(*listOfNotNull(
            button(if (a.hasPanic) "Mudar PIN de pânico…" else "Definir PIN de pânico…") {
                val missing = a.snap.myKeys.filter { it.info.fingerprint !in a.backedUp() }
                val go = {
                a.withCurrentPin {
                    a.askNewPin("PIN de pânico", "Tem de ser diferente do PIN da app. Escolhe um que não escrevas por engano.") { chars ->
                        a.changePins({ try { a.vault.setPanicPin(chars) } finally { chars.fill('\u0000') } }) {
                            a.alert("PIN de pânico", "Guardado. Confirma que tens backup da chave privada fora do telemóvel.")
                        }
                    }
                }
                }
                if (missing.isEmpty()) go() else a.confirm(
                    "Sem backup",
                    "Não há backup registado de: ${missing.joinToString(", ") { it.info.userId }}.\n\n" +
                        "O PIN de pânico apaga tudo sem volta. Faz primeiro o backup, a não ser que já o tenhas noutro sítio.",
                    "Continuar mesmo assim",
                ) { go() }
            },
            if (a.hasPanic) button("Tirar PIN de pânico") { a.withCurrentPin { a.changePins({ a.vault.clearPanicPin() }) } } else null,
        ).toTypedArray()))
    }
}
