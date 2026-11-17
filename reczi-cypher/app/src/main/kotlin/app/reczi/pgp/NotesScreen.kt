package app.reczi.pgp

import android.view.View
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import app.reczi.pgp.core.Note
import java.text.DateFormat
import java.util.Locale

/** Bloco de notas: cada nota fica encriptada para as tuas chaves; ler pede a palavra-passe. */
internal class NotesScreen(a: MainActivity) : Screen(a, "Notas") {
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
        if (a.snap.notes.isEmpty()) list.addView(label("Ainda não tens notas."))
        val fmt = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT, Locale.forLanguageTag("pt-PT"))
        a.snap.notes.forEach { n -> list.addView(noteCard(n, fmt.format(n.saved))) }
    }

    private fun noteCard(n: Note, date: String): View {
        val c = card()
        c.addView(nameView(n.label))
        c.addView(TextView(a).apply { text = date; textSize = 12f })
        c.addView(buttonRow(
            button("Abrir") { open(n) },
            button("Apagar") {
                a.confirm("Apagar nota", "Apagar a nota \"${n.label}\"? Não há volta.", "Apagar") {
                    if (editing == n.id) clearSensitive()
                    a.change("A apagar…", { a.vault.deleteNote(n.id) })
                }
            },
        ))
        return c
    }

    private fun open(n: Note) {
        a.keyPassphrase("Abrir nota", "Palavra-passe da tua chave:") { chars ->
            a.work("A abrir…", { try { a.vault.readNote(n.id, chars) } finally { chars.fill('\u0000') } }) { text ->
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
        if (text.isBlank()) return a.alert("Notas", "Escreve primeiro a nota.")
        val id = editing
        a.change("A guardar…", { a.vault.saveNote(id, label, text) }) {
            clearSensitive()
            Toast.makeText(a, "Nota guardada.", Toast.LENGTH_SHORT).show()
        }
    }

    override fun clearSensitive() {
        editing = null
        editorTitle.text = "Nota nova"
        noteTitle.setText("")
        body.setText("")
    }
}
