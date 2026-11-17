package app.reczi.pgp

import android.app.Activity
import android.view.View

/** Um separador do ecrã principal. Vê a atividade por [a]; as ajudas de interface vêm de [Ui]. */
abstract class Screen(val a: MainActivity, val title: String) : Ui {
    override val ctx: android.app.Activity get() = a
    /** O que aparece no separador (por omissão, o título). */
    open val tab: String get() = title
    /** Explicação curta deste separador, mostrada pelo botão "? Ajuda". */
    abstract val help: String
    abstract val view: View
    abstract fun refresh()
    open fun clearSensitive() {}
}
