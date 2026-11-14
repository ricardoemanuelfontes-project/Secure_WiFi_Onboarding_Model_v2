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

    /** Um código QR: o texto que leva e os módulos para o desenhar. */
    class Code(val text: String, val modules: Array<BooleanArray>)

    /** Bytes de chave por código, quando é preciso dividir (QR de densidade média, fácil de ler). */
    private const val PART_BYTES = 1100
    private const val PART_MARK: Byte = 0x01
    private const val PART_HEADER = 7
    const val MAX_PARTS = 40

    /**
     * QR de uma chave pública (ou de uma privada protegida, para o backup em papel). As chaves
     * pequenas (Curve25519) cabem num só código; as grandes (RSA) são divididas por vários, para
     * mostrar ou imprimir em sequência e ler um a um, por qualquer ordem ([Assembler]).
     *
     * Cada parte leva: marca (1 byte, que nunca é o início de dados OpenPGP), id do conjunto (4),
     * número da parte (1), total (1) e o pedaço da chave, tudo no texto disfarçado habitual.
     */
    fun ofKey(key: org.bouncycastle.openpgp.PGPKeyRing): List<Code> {
        val bytes = key.encoded
        if (bytes.size <= PART_BYTES) return listOf(reliable { Disguise.hide(bytes) })
        val total = (bytes.size + PART_BYTES - 1) / PART_BYTES
        if (total > MAX_PARTS) throw PgpError("Esta chave é demasiado grande para códigos QR.")
        val size = (bytes.size + total - 1) / total
        val set = ByteArray(4).also { java.security.SecureRandom().nextBytes(it) }
        return (0 until total).map { i ->
            val chunk = bytes.copyOfRange(i * size, minOf(bytes.size, (i + 1) * size))
            val part = byteArrayOf(PART_MARK) + set + byteArrayOf(i.toByte(), total.toByte()) + chunk
            reliable { Disguise.hide(part) }
        }
    }

    /** Junta os códigos lidos (um só, ou as várias partes de uma chave grande) até a chave estar completa. */
    class Assembler {
        private var set: ByteArray? = null
        private val parts = HashMap<Int, ByteArray>()
        var total = 0
            private set
        val have get() = parts.size
        /** Números (a começar em 1) dos códigos que ainda falta ler. */
        val missing get() = (1..total).filter { it - 1 !in parts }
        /** A chave completa (bytes OpenPGP), quando [add] devolveu true. */
        var result: ByteArray? = null
            private set

        /** Acrescenta um código lido. Devolve true quando a chave está completa. */
        @Synchronized
        fun add(text: String): Boolean {
            val bytes = Disguise.reveal(text) ?: throw PgpError("Este código QR não é do Reczi cypher.")
            if ((bytes[0].toInt() and 0x80) != 0) { // dados OpenPGP: a chave inteira num só código
                result = bytes
                return true
            }
            val n = if (bytes.size > PART_HEADER && bytes[0] == PART_MARK) bytes[6].toInt() and 0xff else 0
            val index = if (n > 0) bytes[5].toInt() and 0xff else 0
            if (n !in 2..MAX_PARTS || index >= n) throw PgpError("Este código QR não é do Reczi cypher.")
            val id = bytes.copyOfRange(1, 5)
            if (set != null && (!set.contentEquals(id) || total != n)) {
                throw PgpError("Este código é de outro conjunto (outra chave, ou outra vez que foi mostrada/impressa). Lê só os códigos do mesmo conjunto.")
            }
            set = id
            total = n
            parts[index] = bytes.copyOfRange(PART_HEADER, bytes.size)
            if (parts.size < n) return false
            result = (0 until n).fold(ByteArray(0)) { acc, i -> acc + parts.getValue(i) }
            return true
        }
    }

    /**
     * Alguns conteúdos dão um QR que os leitores não conseguem localizar (por acaso, os dados
     * desenham algo parecido com os cantos do código): em testes, cerca de 1 em cada 10 destes
     * códigos grandes. Como o texto disfarçado muda de cada vez ([text] é chamado de novo), gera-se
     * outro até sair um que se lê de volta, e só esse é mostrado ou impresso.
     */
    fun reliable(text: () -> String): Code {
        repeat(30) {
            val t = text()
            val modules = encode(t)
            if (listOf(3, 4, 5, 6).all { scale -> readsBack(modules, scale, t) }) return Code(t, modules)
        }
        throw PgpError("Não foi possível criar um código QR fiável.")
    }

    private fun readsBack(m: Array<BooleanArray>, scale: Int, expected: String): Boolean {
        val w = m.size * scale
        val px = IntArray(w * w) { i -> if (m[(i / w) / scale][(i % w) / scale]) 0xFF000000.toInt() else 0xFFFFFFFF.toInt() }
        return decodeOnce(px, w, w) == expected
    }
}
