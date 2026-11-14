package app.reczi.pgp.core

import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.EncodeHintType
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel

/**
 * Códigos QR para trocar chaves públicas em pessoa e para o backup em papel da chave privada.
 * O conteúdo é sempre o texto "disfarçado: código" (ver [Disguise]), que a app já sabe ler.
 */
object Qr {
    /** Margem branca à volta, em módulos (o mínimo da norma é 4). */
    private const val MARGIN = 4

    /** Módulos do QR (true = preto), incluindo a margem branca. */
    fun encode(text: String): Array<BooleanArray> {
        // Mais correção de erros quando o texto é curto; menos quando é preciso para caber.
        for (level in listOf(ErrorCorrectionLevel.M, ErrorCorrectionLevel.L)) {
            try {
                val m = QRCodeWriter().encode(
                    text, BarcodeFormat.QR_CODE, 0, 0,
                    mapOf(EncodeHintType.ERROR_CORRECTION to level, EncodeHintType.MARGIN to MARGIN, EncodeHintType.CHARACTER_SET to "ISO-8859-1"),
                )
                return Array(m.height) { y -> BooleanArray(m.width) { x -> m[x, y] } }
            } catch (e: Exception) {
                // demasiado grande para este nível: tenta o seguinte
            }
        }
        throw PgpError("É demasiado grande para caber num código QR.")
    }

    /** Lê um QR de uma imagem (píxeis ARGB, linha a linha). Devolve o texto, ou null se não encontrar nenhum. */
    fun decode(pixels: IntArray, width: Int, height: Int): String? {
        // O detetor por vezes não encontra um código grande num dado tamanho de imagem: se falhar,
        // tenta de novo com a imagem um pouco reduzida.
        decodeOnce(pixels, width, height)?.let { return it }
        for (percent in listOf(90, 80, 67)) {
            val w = width * percent / 100
            val h = height * percent / 100
            if (w < 64 || h < 64) break
            val small = IntArray(w * h) { i -> pixels[((i / w) * height / h) * width + (i % w) * width / w] }
            decodeOnce(small, w, h)?.let { return it }
        }
        return null
    }

    private fun decodeOnce(pixels: IntArray, width: Int, height: Int): String? = try {
        val bitmap = BinaryBitmap(HybridBinarizer(RGBLuminanceSource(width, height, pixels)))
        QRCodeReader().decode(bitmap, mapOf(DecodeHintType.TRY_HARDER to true, DecodeHintType.CHARACTER_SET to "ISO-8859-1")).text
    } catch (e: Exception) {
        null
    }

    /**
     * QR de uma chave pública (ou de uma privada protegida, para o backup em papel): o texto e os
     * módulos. Ver [reliable].
     */
    fun ofKey(key: org.bouncycastle.openpgp.PGPKeyRing): Pair<String, Array<BooleanArray>> {
        val bytes = key.encoded
        return reliable { Disguise.hide(bytes) }
    }

    /**
     * Alguns conteúdos dão um QR que os leitores não conseguem localizar (por acaso, os dados
     * desenham algo parecido com os cantos do código): em testes, cerca de 1 em cada 10 destes
     * códigos grandes. Como o texto disfarçado muda de cada vez ([text] é chamado de novo), gera-se
     * outro até sair um que se lê de volta, e só esse é mostrado ou impresso.
     */
    fun reliable(text: () -> String): Pair<String, Array<BooleanArray>> {
        repeat(30) {
            val t = text()
            val modules = encode(t)
            if (listOf(3, 4, 5, 6).all { scale -> readsBack(modules, scale, t) }) return t to modules
        }
        throw PgpError("Não foi possível criar um código QR fiável.")
    }

    private fun readsBack(m: Array<BooleanArray>, scale: Int, expected: String): Boolean {
        val w = m.size * scale
        val px = IntArray(w * w) { i -> if (m[(i / w) / scale][(i % w) / scale]) 0xFF000000.toInt() else 0xFFFFFFFF.toInt() }
        return decodeOnce(px, w, w) == expected
    }
}
