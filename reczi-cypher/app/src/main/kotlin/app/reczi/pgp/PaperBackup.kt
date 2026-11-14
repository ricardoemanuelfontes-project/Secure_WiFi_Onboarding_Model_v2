package app.reczi.pgp

import android.app.Activity
import android.content.Context
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.Rect
import android.graphics.Typeface
import android.os.Bundle
import android.os.CancellationSignal
import android.os.ParcelFileDescriptor
import android.print.PageRange
import android.print.PrintAttributes
import android.print.PrintDocumentAdapter
import android.print.PrintDocumentInfo
import android.print.PrintManager
import android.print.pdf.PrintedPdfDocument
import java.io.FileOutputStream

/**
 * Backup em papel da chave privada: uma página com o código QR (para restaurar com a câmara) e,
 * a seguir, o texto da chave (para o caso de o QR não se conseguir ler).
 *
 * A chave impressa continua protegida pela palavra-passe; sem a palavra-passe o papel não serve
 * de nada, e com ela serve de tudo. O documento passa pelo serviço de impressão do Android.
 */
class PaperBackup(
    private val context: Context,
    private val name: String,
    private val fingerprint: String,
    private val date: String,
    private val qr: Array<BooleanArray>,
    private val armored: String,
    /** Chamado quando o documento foi entregue ao serviço de impressão. */
    private val onPrinted: () -> Unit = {},
) : PrintDocumentAdapter() {
    private var pdf: PrintedPdfDocument? = null
    private var attributes: PrintAttributes? = null

    fun print(activity: Activity) {
        (activity.getSystemService(Context.PRINT_SERVICE) as PrintManager).print("Reczi cypher - backup", this, null)
    }

    override fun onLayout(old: PrintAttributes?, new: PrintAttributes, signal: CancellationSignal?, callback: LayoutResultCallback, extras: Bundle?) {
        attributes = new
        if (signal?.isCanceled == true) return callback.onLayoutCancelled()
        val info = PrintDocumentInfo.Builder("reczi-backup-${fingerprint.takeLast(16)}.pdf")
            .setContentType(PrintDocumentInfo.CONTENT_TYPE_DOCUMENT)
            .setPageCount(PrintDocumentInfo.PAGE_COUNT_UNKNOWN)
            .build()
        callback.onLayoutFinished(info, old != new)
    }

    override fun onWrite(pages: Array<out PageRange>?, destination: ParcelFileDescriptor, signal: CancellationSignal?, callback: WriteResultCallback) {
        val doc = PrintedPdfDocument(context, attributes ?: return callback.onWriteFailed("sem formato de página"))
        pdf = doc
        try {
            draw(doc)
            FileOutputStream(destination.fileDescriptor).use { doc.writeTo(it) }
            callback.onWriteFinished(arrayOf(PageRange.ALL_PAGES))
            onPrinted()
        } catch (e: Exception) {
            callback.onWriteFailed(e.javaClass.simpleName)
        } finally {
            doc.close()
            pdf = null
        }
    }

    private fun draw(doc: PrintedPdfDocument) {
        val black = Paint(Paint.ANTI_ALIAS_FLAG).apply { color = 0xFF000000.toInt(); textSize = 11f }
        val bold = Paint(black).apply { typeface = Typeface.DEFAULT_BOLD; textSize = 16f }
        val mono = Paint(black).apply { typeface = Typeface.MONOSPACE; textSize = 8.5f }

        // Página 1: identificação e código QR. As medidas são em pontos (1/72 de polegada).
        var page = doc.startPage(0)
        var canvas: Canvas = page.canvas
        val area: Rect = page.info.contentRect
        val left = area.left + 36f
        var y = area.top + 56f
        canvas.drawText("Reczi cypher - backup da chave privada", left, y, bold); y += 24f
        for (line in listOf(name, fingerprint.chunked(4).joinToString(" "), "Impresso em $date")) { canvas.drawText(line, left, y, black); y += 16f }
        y += 8f
        for (line in listOf(
            "Esta chave continua protegida pela tua palavra-passe: sem ela, este papel não abre nada.",
            "Guarda-o num local seguro (cofre). Não o fotografes nem o guardes na cloud.",
            "Para restaurar: Reczi cypher > Chaves > Importar > Ler QR.",
        )) { canvas.drawText(line, left, y, black); y += 15f }
        y += 12f
        val side = minOf(area.width() - 72f, area.bottom - y - 36f)
        val cell = side / qr.size
        val fill = Paint().apply { color = 0xFF000000.toInt(); isAntiAlias = false }
        for (r in qr.indices) for (c in qr[r].indices) {
            if (qr[r][c]) canvas.drawRect(left + c * cell, y + r * cell, left + (c + 1) * cell + 0.05f, y + (r + 1) * cell + 0.05f, fill)
        }
        doc.finishPage(page)

        // Páginas seguintes: o texto da chave, para escrever à mão/OCR se o QR falhar.
        val lines = listOf("Texto da chave (o mesmo que está no código QR):", "") + armored.trim().lines()
        val perPage = ((area.height() - 96f) / 11f).toInt().coerceAtLeast(10)
        lines.chunked(perPage).forEachIndexed { i, chunk ->
            page = doc.startPage(i + 1)
            canvas = page.canvas
            y = area.top + 48f
            for (line in chunk) { canvas.drawText(line, left, y, mono); y += 11f }
            doc.finishPage(page)
        }
    }

    override fun onFinish() {
        pdf?.close()
        pdf = null
    }
}
