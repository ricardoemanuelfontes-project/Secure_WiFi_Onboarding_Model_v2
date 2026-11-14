package app.reczi.pgp

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import app.reczi.pgp.core.Store
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** A chave do Keystore desapareceu (p. ex. reposição do telemóvel) mas há ficheiros do cofre. */
class VaultKeyLostException : IOException("A chave de proteção do cofre deste telemóvel desapareceu.")

/**
 * Guarda cada ficheiro do cofre cifrado com AES-256-GCM, com uma chave que vive no
 * Android Keystore (no chip de segurança do telemóvel, quando existe) e nunca sai de lá.
 * Os ficheiros ficam em noBackupFilesDir, que o Android nunca inclui em cópias de segurança.
 *
 * As chaves privadas já estão protegidas pela palavra-passe OpenPGP; esta é uma segunda
 * camada que liga os dados a este telemóvel.
 */
class KeystoreStore(context: Context) : Store {
    private val base = context.noBackupFilesDir
    private val dir = File(base, "vault").apply { mkdirs() }
    /** Nome da chave do Keystore deste cofre (um cofre novo usa sempre um nome novo). */
    private val aliasFile = File(base, "vault-alias")
    private var key: SecretKey? = null

    private fun alias(): String = aliasFile.takeIf { it.exists() }?.readText()?.trim()?.ifEmpty { null } ?: DEFAULT_ALIAS

    @Synchronized
    override fun names(): List<String> = dir.list()?.filter { NAME.matches(it) }?.sorted() ?: emptyList()

    @Synchronized
    override fun read(name: String): ByteArray? {
        val f = file(name)
        if (!f.exists()) return null
        val data = f.readBytes()
        if (data.size < 1 + IV_LEN + TAG_LEN / 8 || data[0] != FORMAT) throw IOException("Ficheiro do cofre inválido.")
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(TAG_LEN, data, 1, IV_LEN))
        cipher.updateAAD(name.toByteArray())
        return cipher.doFinal(data, 1 + IV_LEN, data.size - 1 - IV_LEN)
    }

    @Synchronized
    override fun write(name: String, data: ByteArray) {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key()) // o Keystore gera o IV
        cipher.updateAAD(name.toByteArray()) // impede trocar o conteúdo entre ficheiros
        val sealed = cipher.doFinal(data)
        val iv = cipher.iv
        check(iv.size == IV_LEN)
        // Escrita atómica: ficheiro temporário, sincronizado com o disco, depois renomeado.
        val target = file(name)
        val tmp = File(dir, "$name.tmp")
        FileOutputStream(tmp).use { out ->
            out.write(byteArrayOf(FORMAT))
            out.write(iv)
            out.write(sealed)
            out.fd.sync()
        }
        if (!tmp.renameTo(target)) {
            tmp.delete()
            throw IOException("Não foi possível guardar no cofre.")
        }
    }

    @Synchronized
    override fun delete(name: String) {
        file(name).delete()
    }

    /** Muda o nome do ficheiro para fora do cofre (fica em noBackupFilesDir/vault-avariados). */
    @Synchronized
    override fun quarantine(name: String) {
        val bad = File(base, "vault-avariados").apply { mkdirs() }
        val f = file(name)
        if (f.exists() && !f.renameTo(File(bad, "$name.${System.currentTimeMillis()}"))) f.delete()
    }

    /**
     * Começa um cofre novo quando o atual não pode ser aberto. Nada é apagado: os ficheiros antigos
     * ficam em noBackupFilesDir/vault-perdido-<data> e a chave antiga do Keystore (se ainda existir)
     * fica intacta; o cofre novo usa uma chave com outro nome.
     */
    @Synchronized
    fun resetVault() {
        val stamp = System.currentTimeMillis()
        val lost = File(base, "vault-perdido-$stamp")
        if (dir.exists() && !dir.renameTo(lost)) throw IOException("Não foi possível pôr de lado o cofre antigo.")
        File(lost, "alias-antigo").takeIf { lost.exists() }?.writeText(alias())
        dir.mkdirs()
        aliasFile.writeText("$DEFAULT_ALIAS-$stamp")
        key = null
    }

    /**
     * PIN de pânico: apaga tudo, sem volta. Além dos ficheiros (incluindo os postos de lado), destrói
     * as chaves do Keystore, por isso mesmo que alguém recupere os ficheiros do armazenamento do
     * telemóvel já não há chave para os abrir.
     */
    @Synchronized
    fun wipe() {
        key = null
        runCatching {
            val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            ks.aliases().toList().filter { it.startsWith(DEFAULT_ALIAS) }.forEach { ks.deleteEntry(it) }
        }
        base.listFiles()?.filter { it.name.startsWith("vault") }?.forEach { it.deleteRecursively() }
        dir.mkdirs()
    }

    /** true se há ficheiros no cofre mas a chave do Keystore que os protegia desapareceu. */
    @Synchronized
    fun isKeyLost(): Boolean {
        if (key != null) return false
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        return ks.getKey(alias(), null) == null && names().isNotEmpty()
    }

    private fun file(name: String): File {
        require(NAME.matches(name)) { "nome inválido" }
        return File(dir, name)
    }

    private fun key(): SecretKey = key ?: loadOrCreateKey().also { key = it }

    private fun loadOrCreateKey(): SecretKey {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val alias = alias()
        (ks.getKey(alias, null) as? SecretKey)?.let { return it }
        // Sem chave mas com ficheiros: não criar outra às escondidas (os ficheiros ficariam ilegíveis
        // para sempre e qualquer recuperação deixaria de ser possível).
        if (names().isNotEmpty()) throw VaultKeyLostException()
        // Tenta primeiro o StrongBox (chip de segurança dedicado); se não existir ou falhar, usa o TEE.
        if (Build.VERSION.SDK_INT >= 28) {
            try {
                return selfTest(generate(alias, strongBox = true))
            } catch (e: Exception) {
                ks.deleteEntry(alias) // só a chave acabada de criar, que falhou o teste
            }
        }
        return selfTest(generate(alias, strongBox = false))
    }

    private fun generate(alias: String, strongBox: Boolean): SecretKey {
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(true)
        if (strongBox && Build.VERSION.SDK_INT >= 28) spec.setIsStrongBoxBacked(true)
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
            .apply { init(spec.build()) }
            .generateKey()
    }

    /** Alguns telemóveis anunciam StrongBox mas falham ao usá-lo: confirma antes de confiar na chave. */
    private fun selfTest(key: SecretKey): SecretKey {
        val probe = byteArrayOf(1, 2, 3, 4)
        val enc = Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, key) }
        val sealed = enc.doFinal(probe)
        val dec = Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_LEN, enc.iv)) }
        check(dec.doFinal(sealed).contentEquals(probe))
        return key
    }

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val DEFAULT_ALIAS = "reczi-pgp-vault"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val IV_LEN = 12
        const val TAG_LEN = 128
        const val FORMAT: Byte = 1
        val NAME = Regex("^[a-z]+(-[0-9A-F]{40,64})?$")
    }
}
