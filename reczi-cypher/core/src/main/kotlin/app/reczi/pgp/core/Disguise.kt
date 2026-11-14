package app.reczi.pgp.core

import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Modo disfarçado: esconde que o texto é OpenPGP.
 *
 * Uma mensagem ou chave PGP normal é reconhecível à primeira vista ("-----BEGIN PGP MESSAGE-----")
 * e, mesmo sem esse cabeçalho, os pacotes binários têm uma estrutura conhecida (e mostram os ids
 * das chaves dos destinatários). Aqui, os bytes PGP são misturados com AES-256-CTR e um valor
 * aleatório novo de cada vez, e o resultado é escrito em Base64 URL-safe numa só linha, sem
 * cabeçalhos. O texto final parece uma sequência aleatória, como um token ou um código.
 *
 * IMPORTANTE: isto é camuflagem, NÃO é uma camada extra de segurança. A chave do disfarce é fixa e
 * está dentro da app: quem tiver a app (ou ler este código) consegue tirar o disfarce e ver que é
 * PGP. A confidencialidade continua a vir só do OpenPGP, por baixo. O disfarce também não esconde
 * que é texto encriptado; só que é PGP.
 *
 * Formato (antes do Base64): nonce(16) || AES-256-CTR(nonce, pgp) || etiqueta(4).
 * A etiqueta (HMAC-SHA256 truncado, com a mesma chave fixa) só serve para reconhecer de forma
 * fiável um texto disfarçado e detetar erros de cópia; a integridade real vem do OpenPGP.
 */
object Disguise {
    private const val NONCE = 16
    private const val TAG = 4

    private val encKey: ByteArray = derive("enc")
    private val macKey: ByteArray = derive("mac")
    private val random = SecureRandom()

    private fun derive(label: String): ByteArray =
        MessageDigest.getInstance("SHA-256").digest("Reczi cypher / disfarce v1 / $label".toByteArray(Charsets.UTF_8))

    /** Disfarça bytes PGP binários (mensagem ou chave pública). */
    fun hide(pgp: ByteArray): String {
        val nonce = ByteArray(NONCE).also { random.nextBytes(it) }
        val body = ctr(nonce, pgp)
        val tag = tag(nonce, body)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(nonce + body + tag)
    }

    /**
     * Tira o disfarce. Devolve os bytes PGP binários, ou null se [text] não for um texto disfarçado
     * válido (p. ex. um texto normal, uma mensagem PGP normal, ou uma cópia cortada).
     */
    fun reveal(text: String): ByteArray? {
        val compact = text.filterNot { it.isWhitespace() }
        if (compact.length < 32 || compact.any { !(it.isLetterOrDigit() && it.code < 128) && it != '-' && it != '_' }) return null
        val raw = try {
            Base64.getUrlDecoder().decode(compact)
        } catch (e: IllegalArgumentException) {
            return null
        }
        if (raw.size <= NONCE + TAG) return null
        val nonce = raw.copyOfRange(0, NONCE)
        val body = raw.copyOfRange(NONCE, raw.size - TAG)
        val tag = raw.copyOfRange(raw.size - TAG, raw.size)
        if (!MessageDigest.isEqual(tag, tag(nonce, body))) return null
        return ctr(nonce, body)
    }

    fun isDisguised(text: String): Boolean = reveal(text) != null

    private fun ctr(nonce: ByteArray, data: ByteArray): ByteArray =
        Cipher.getInstance("AES/CTR/NoPadding").run {
            init(Cipher.ENCRYPT_MODE, SecretKeySpec(encKey, "AES"), IvParameterSpec(nonce))
            doFinal(data)
        }

    private fun tag(nonce: ByteArray, body: ByteArray): ByteArray =
        Mac.getInstance("HmacSHA256").run {
            init(SecretKeySpec(macKey, "HmacSHA256"))
            update(nonce)
            doFinal(body)
        }.copyOf(TAG)
}
