package app.reczi.pgp

import android.app.Activity
import android.app.AlertDialog
import android.content.res.ColorStateList
import android.content.res.Configuration
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.text.InputType
import android.text.TextUtils
import android.view.Gravity
import android.view.MotionEvent
import android.view.View
import android.view.ViewGroup
import android.view.inputmethod.EditorInfo
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import app.reczi.pgp.core.Pgp

/**
 * Ajudas de interface comuns à atividade e aos separadores (a interface é toda feita em código).
 * Tudo é criado sobre [ctx].
 */
interface Ui {
    val ctx: android.app.Activity

    fun AlertDialog.Builder.showSecure(): AlertDialog {
        val d = create()
        protectWindow(d.window)
        d.show()
        return d
    }

    /**
     * Protege um botão importante contra "tapjacking": ignora toques quando outra app desenha por
     * cima da janela (mesmo só em parte) e explica porquê, em vez de a app parecer bloqueada.
     */
    fun <V : View> guard(v: V): V {
        v.setOnTouchListener { _, ev ->
            val obscured = ev.flags and (MotionEvent.FLAG_WINDOW_IS_OBSCURED or MainActivity.FLAG_PARTIALLY_OBSCURED) != 0
            if (obscured && ev.action == MotionEvent.ACTION_UP) {
                Toast.makeText(ctx, "Há outra app a desenhar por cima do ecrã (filtro de luz, bolha de chat...). Desliga-a para continuar.", Toast.LENGTH_LONG).show()
            }
            obscured
        }
        return v
    }

    fun dp(v: Int) = (v * ctx.resources.displayMetrics.density).toInt()

    val isNight get() = (ctx.resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK) == Configuration.UI_MODE_NIGHT_YES
    val green get() = if (isNight) 0xFF81C784.toInt() else 0xFF2E7D32.toInt()
    val orange get() = if (isNight) 0xFFFFB74D.toInt() else 0xFFB45309.toInt()
    val red get() = if (isNight) 0xFFEF9A9A.toInt() else 0xFFC62828.toInt()

    fun column(padding: Int = dp(16)) = LinearLayout(ctx).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(padding, padding, padding, padding)
    }

    fun scroll(child: View) = ScrollView(ctx).apply { isFillViewport = true; addView(child) }

    fun heading(text: String) = TextView(ctx).apply {
        this.text = text
        textSize = 18f
        setTypeface(null, Typeface.BOLD)
        setPadding(0, dp(16), 0, dp(8))
    }

    fun label(text: String) = TextView(ctx).apply { this.text = text; setPadding(0, dp(4), 0, dp(4)) }

    /** Nome de uma chave: numa só linha, para um nome enorme não esconder o resto. */
    fun nameView(name: String) = TextView(ctx).apply {
        text = name
        setTypeface(null, Typeface.BOLD)
        maxLines = 1
        ellipsize = TextUtils.TruncateAt.END
    }

    fun fingerprintView(fpr: String) = TextView(ctx).apply {
        text = Pgp.prettyFingerprint(fpr); typeface = Typeface.MONOSPACE; textSize = 12f
    }

    fun button(text: String, onClick: () -> Unit) = Button(ctx).apply {
        this.text = text
        isAllCaps = false
        setOnClickListener { onClick() }
    }

    /** Botão da ação principal do ecrã, na cor da marca. */
    fun primaryButton(text: String, onClick: () -> Unit) = button(text, onClick).apply {
        backgroundTintList = ColorStateList.valueOf(MainActivity.BRAND_RED)
        setTextColor(Color.WHITE)
    }

    fun buttonRow(vararg buttons: Button) = LinearLayout(ctx).apply {
        orientation = LinearLayout.HORIZONTAL
        buttons.forEach { addView(it, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)) }
    }

    fun field(hint: String, type: Int = InputType.TYPE_CLASS_TEXT) = EditText(ctx).apply {
        this.hint = hint
        inputType = type
        imeOptions = EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
        importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO
    }

    fun passwordField(hint: String) =
        field(hint, InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD)

    /**
     * Caixa "Mostrar" para ver o que se escreve nos campos de palavra-passe ou PIN (vem desligada).
     * As capturas de ecrã continuam bloqueadas; só protege menos de quem estiver a olhar para o ecrã.
     */
    fun showToggle(vararg fields: EditText) = CheckBox(ctx).apply {
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
    fun textArea(hint: String, lines: Int, mono: Boolean = false) = field(
        hint,
        InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
    ).apply {
        minLines = lines
        maxLines = lines * 3
        gravity = Gravity.TOP or Gravity.START
        if (mono) { typeface = Typeface.MONOSPACE; textSize = 12f }
    }

    fun card() = LinearLayout(ctx).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(dp(12), dp(12), dp(12), dp(12))
        background = GradientDrawable().apply {
            cornerRadius = dp(8).toFloat()
            setStroke(dp(1), if (isNight) 0x40FFFFFF else 0x30000000)
        }
        layoutParams = LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
            .apply { bottomMargin = dp(8) }
    }

}

/** Tira o texto do campo como CharArray; setText("") também apaga o histórico de "anular". */
internal fun EditText.takeChars(): CharArray {
    val e = text
    val chars = CharArray(e.length)
    e.getChars(0, e.length, chars, 0)
    setText("")
    return chars
}
