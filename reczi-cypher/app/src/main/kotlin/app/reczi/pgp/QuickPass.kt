package app.reczi.pgp

import android.content.Context
import android.hardware.biometrics.BiometricManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Palavra-passe de uma chave tua guardada para a desbloquear com a impressão digital ou com o
 * PIN/padrão do telemóvel, em vez de a escrever.
 *
 * Fica cifrada (AES-256-GCM) com uma chave do Android Keystore que só funciona depois de o
 * Android confirmar o dono, em cada utilização (não há "janela" de segundos). Quem copiar os
 * ficheiros da app não a consegue abrir, e a app sozinha também não. O Android invalida esta
 * chave se for acrescentada uma impressão digital nova ou se o bloqueio de ecrã for tirado:
 * nesse caso a palavra-passe guardada deixa de servir e volta a escrever-se.
 *
 * Os nomes começam por "vault" (ficheiros) e "reczi-pgp-vault" (Keystore) para o PIN de pânico
 * os apagar juntamente com o cofre ([KeystoreStore.wipe]). Só existe em Android 11 ou mais recente.
 */
class QuickPass(private val context: Context) {
    private val dir = File(context.noBackupFilesDir, "vault-quick")

    /** true se este telemóvel suporta o desbloqueio (Android 11+ com bloqueio de ecrã definido). */
    fun available(): Boolean {
        if (Build.VERSION.SDK_INT < 30) return false
        val bm = context.getSystemService(BiometricManager::class.java) ?: return false
        return bm.canAuthenticate(AUTHENTICATORS) == BiometricManager.BIOMETRIC_SUCCESS
    }

    fun has(fingerprint: String): Boolean = file(fingerprint).exists()

    fun forget(fingerprint: String) {
        file(fingerprint).delete()
    }

    /** Cifra pronta a guardar uma palavra-passe; só funciona depois de autorizada pelo Android. */
    fun encrypter(): Cipher = Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, key()) }

    /**
     * Cifra pronta a abrir a palavra-passe guardada; null se não há nada guardado ou se o Android
     * invalidou a chave (nesse caso o que estava guardado é apagado).
     */
    fun decrypter(fingerprint: String): Cipher? {
        val data = runCatching { file(fingerprint).readBytes() }.getOrNull() ?: return null
        if (data.size < 1 + IV_LEN + TAG_LEN / 8 || data[0] != FORMAT) { forget(fingerprint); return null }
        return try {
            val key = existingKey() ?: throw IOException("sem chave")
            Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_LEN, data, 1, IV_LEN)) }
        } catch (e: Exception) {
            // KeyPermanentlyInvalidatedException (impressão digital nova, bloqueio retirado) ou chave em falta.
            forget(fingerprint)
            null
        }
    }

    /** Guarda a palavra-passe com uma cifra já autorizada por [encrypter]. */
    fun save(fingerprint: String, authorized: Cipher, passphrase: CharArray) {
        val plain = utf8(passphrase)
        try {
            authorized.updateAAD(fingerprint.toByteArray())
            val sealed = authorized.doFinal(plain)
            val iv = authorized.iv
            check(iv.size == IV_LEN)
            dir.mkdirs()
            val target = file(fingerprint)
            val tmp = File(dir, "$fingerprint.tmp")
            FileOutputStream(tmp).use { out ->
                out.write(byteArrayOf(FORMAT))
                out.write(iv)
                out.write(sealed)
                out.fd.sync()
            }
            if (!tmp.renameTo(target)) {
                tmp.delete()
                throw IOException("Não foi possível guardar.")
            }
        } finally {
            plain.fill(0)
        }
    }

    /** Abre a palavra-passe com uma cifra já autorizada por [decrypter]. Quem a recebe tem de a apagar. */
    fun open(fingerprint: String, authorized: Cipher): CharArray {
        val data = file(fingerprint).readBytes()
        authorized.updateAAD(fingerprint.toByteArray())
        val plain = authorized.doFinal(data, 1 + IV_LEN, data.size - 1 - IV_LEN)
        try {
            val chars = Charsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(plain))
            val out = CharArray(chars.remaining()).also { chars.get(it) }
            chars.array().fill('\u0000')
            return out
        } finally {
            plain.fill(0)
        }
    }

    private fun utf8(chars: CharArray): ByteArray {
        val buf = Charsets.UTF_8.newEncoder().encode(CharBuffer.wrap(chars))
        val out = ByteArray(buf.remaining()).also { buf.get(it) }
        if (buf.hasArray()) buf.array().fill(0)
        return out
    }

    private fun file(fingerprint: String): File {
        require(FPR.matches(fingerprint)) { "impressão digital inválida" }
        return File(dir, fingerprint)
    }

    private fun existingKey(): SecretKey? {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        return ks.getKey(ALIAS, null) as? SecretKey
    }

    private fun key(): SecretKey {
        existingKey()?.let { key ->
            // Se o Android a invalidou, cria-se outra (o que estava guardado com ela já não abre).
            try {
                Cipher.getInstance(TRANSFORMATION).init(Cipher.ENCRYPT_MODE, key)
                return key
            } catch (e: Exception) {
                KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }.deleteEntry(ALIAS)
                dir.listFiles()?.forEach { it.delete() }
            }
        }
        val spec = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(true)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)
            .setUnlockedDeviceRequired(true)
        // 0 segundos: o Android tem de confirmar o dono em cada utilização.
        if (Build.VERSION.SDK_INT >= 30) {
            spec.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL)
        }
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
            .apply { init(spec.build()) }
            .generateKey()
    }

    companion object {
        /** Impressão digital "forte" (classe 3) ou o PIN/padrão/palavra-passe do telemóvel. */
        const val AUTHENTICATORS = BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val ALIAS = "reczi-pgp-vault-quick"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val IV_LEN = 12
        private const val TAG_LEN = 128
        private const val FORMAT: Byte = 1
        private val FPR = Regex("^[0-9A-F]{40,64}$")
    }
}
