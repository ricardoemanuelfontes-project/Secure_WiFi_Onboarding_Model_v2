package app.reczi.pgp.core

import org.bouncycastle.crypto.generators.SCrypt
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * PIN da app (ecrã de bloqueio). Guarda-se só sal + scrypt do PIN, nunca o PIN.
 *
 * Um PIN curto não é uma proteção criptográfica forte: serve para travar quem pega no telemóvel
 * desbloqueado. As chaves privadas continuam protegidas pela palavra-passe OpenPGP.
 */
object Lock {
    const val MIN_PIN = 4
    private const val SALT = 16

    fun hash(pin: CharArray): ByteArray {
        if (pin.size < MIN_PIN) throw PgpError("O PIN tem de ter pelo menos $MIN_PIN algarismos.")
        val salt = ByteArray(SALT).also { SecureRandom().nextBytes(it) }
        return salt + scrypt(pin, salt)
    }

    /** true se [pin] é o PIN guardado em [stored]. Com [stored] nulo faz o mesmo trabalho e devolve false. */
    fun matches(stored: ByteArray?, pin: CharArray): Boolean {
        val valid = stored != null && stored.size == SALT + 32
        val data = if (valid) stored!! else ByteArray(SALT + 32)
        val same = MessageDigest.isEqual(data.copyOfRange(SALT, data.size), scrypt(pin, data.copyOfRange(0, SALT)))
        return valid && same
    }

    private fun scrypt(pin: CharArray, salt: ByteArray): ByteArray =
        SCrypt.generate(String(pin).toByteArray(Charsets.UTF_8), salt, 1 shl 14, 8, 1, 32)
}
