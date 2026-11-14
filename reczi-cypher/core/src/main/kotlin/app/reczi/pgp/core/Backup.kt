package app.reczi.pgp.core

import org.bouncycastle.crypto.generators.SCrypt
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Backup completo do cofre num só ficheiro: chaves privadas, contactos (e quais estão verificados),
 * códigos secretos e notas. Serve para mudar de telemóvel sem refazer tudo.
 *
 * O ficheiro é cifrado com AES-256-GCM, com a chave derivada da palavra-passe do backup por scrypt
 * (N=2^15, r=8, p=1) e um sal aleatório. Sem a palavra-passe não se lê nem se altera nada.
 * As chaves privadas lá dentro continuam, além disso, protegidas pela sua própria palavra-passe.
 *
 * Formato: "RECZI-BACKUP-1\n" | sal(16) | nonce(12) | AES-GCM(entradas), com o cabeçalho e o sal
 * autenticados. Entradas: nº de entradas, e para cada uma nome (UTF) + tamanho + bytes.
 */
object Backup {
    private val MAGIC = "RECZI-BACKUP-1\n".toByteArray(Charsets.US_ASCII)
    private const val SALT = 16
    private const val NONCE = 12
    private const val MAX_ENTRIES = 100_000

    fun isBackup(data: ByteArray): Boolean = data.size > MAGIC.size + SALT + NONCE && data.copyOf(MAGIC.size).contentEquals(MAGIC)

    fun seal(entries: Map<String, ByteArray>, passphrase: CharArray): ByteArray {
        Pgp.checkNewPassphrase(passphrase)
        val plain = ByteArrayOutputStream()
        DataOutputStream(plain).use { out ->
            out.writeInt(entries.size)
            for ((name, data) in entries) {
                out.writeUTF(name)
                out.writeInt(data.size)
                out.write(data)
            }
        }
        val random = SecureRandom()
        val salt = ByteArray(SALT).also { random.nextBytes(it) }
        val nonce = ByteArray(NONCE).also { random.nextBytes(it) }
        return MAGIC + salt + nonce + cipher(Cipher.ENCRYPT_MODE, passphrase, salt, nonce).doFinal(plain.toByteArray())
    }

    fun open(data: ByteArray, passphrase: CharArray): Map<String, ByteArray> {
        if (!isBackup(data)) throw PgpError("Isto não é um backup completo do Reczi cypher.")
        val salt = data.copyOfRange(MAGIC.size, MAGIC.size + SALT)
        val nonce = data.copyOfRange(MAGIC.size + SALT, MAGIC.size + SALT + NONCE)
        val plain = try {
            cipher(Cipher.DECRYPT_MODE, passphrase, salt, nonce).doFinal(data, MAGIC.size + SALT + NONCE, data.size - MAGIC.size - SALT - NONCE)
        } catch (e: Exception) {
            throw PgpError("Palavra-passe do backup errada, ou o ficheiro está danificado.", e)
        }
        return try {
            DataInputStream(ByteArrayInputStream(plain)).use { input ->
                val n = input.readInt()
                if (n !in 0..MAX_ENTRIES) throw PgpError("Backup inválido.")
                val entries = LinkedHashMap<String, ByteArray>()
                repeat(n) {
                    val name = input.readUTF()
                    val size = input.readInt()
                    if (size < 0 || size > plain.size) throw PgpError("Backup inválido.")
                    entries[name] = ByteArray(size).also { input.readFully(it) }
                }
                entries
            }
        } catch (e: PgpError) {
            throw e
        } catch (e: Exception) {
            throw PgpError("Backup inválido.", e)
        }
    }

    private fun cipher(mode: Int, passphrase: CharArray, salt: ByteArray, nonce: ByteArray): Cipher {
        val normalized = java.text.Normalizer.normalize(String(passphrase), java.text.Normalizer.Form.NFKC)
        val key = SCrypt.generate(normalized.toByteArray(Charsets.UTF_8), salt, 1 shl 15, 8, 1, 32)
        return Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(mode, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
            updateAAD(MAGIC)
            updateAAD(salt)
        }
    }
}
