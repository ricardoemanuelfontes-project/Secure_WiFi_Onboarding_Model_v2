package app.reczi.pgp

import android.app.KeyguardManager
import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import app.reczi.pgp.core.Store
import app.reczi.pgp.core.StoreLockedException
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** A chave do Keystore desapareceu (p. ex. reposição do telemóvel) mas há ficheiros do cofre. */
class VaultKeyLostException : IOException("A chave de proteção do cofre deste telemóvel desapareceu.")

/** Onde vivem as chaves do cofre: no telemóvel, o Android Keystore ([AndroidVaultKeys]); nos testes, memória. */
internal interface VaultKeys {
    fun get(alias: String): SecretKey?

    /** Cria uma chave nova. [unlockedOnly]: só funciona com o telemóvel desbloqueado. */
    fun create(alias: String, unlockedOnly: Boolean): SecretKey
    fun delete(alias: String)
    fun aliases(): List<String>

    /** O telemóvel está bloqueado agora (o ecrã de bloqueio pede o PIN, o padrão ou o dedo). */
    fun deviceLocked(): Boolean

    /**
     * As chaves "só com o telemóvel desbloqueado" são seguras neste Android. Do 12 ao 14 tinham
     * erros graves: tirar o bloqueio de ecrã apagava-as (e com elas o cofre), e sem bloqueio de ecrã
     * nem se podiam usar. O Android 15 corrigiu-os (ver a documentação de
     * KeyGenParameterSpec.Builder.setUnlockedDeviceRequired).
     */
    val unlockedOnlySupported: Boolean
}

/** As chaves do cofre no Android Keystore (no StrongBox, quando existe e funciona). */
internal class AndroidVaultKeys(private val context: Context) : VaultKeys {
    private fun ks() = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    override fun get(alias: String): SecretKey? = ks().getKey(alias, null) as? SecretKey
    override fun delete(alias: String) = ks().deleteEntry(alias)
    override fun aliases(): List<String> = ks().aliases().toList()
    override fun deviceLocked(): Boolean = (context.getSystemService(Context.KEYGUARD_SERVICE) as? KeyguardManager)?.isDeviceLocked == true
    override val unlockedOnlySupported: Boolean get() = Build.VERSION.SDK_INT >= 35

    override fun create(alias: String, unlockedOnly: Boolean): SecretKey {
        // Tenta primeiro o StrongBox (chip de segurança dedicado); se não existir ou falhar, usa o TEE.
        if (Build.VERSION.SDK_INT >= 28) {
            try {
                return selfTest(generate(alias, strongBox = true, unlockedOnly))
            } catch (e: Exception) {
                ks().deleteEntry(alias) // só a chave acabada de criar, que falhou o teste
            }
        }
        return selfTest(generate(alias, strongBox = false, unlockedOnly))
    }

    private fun generate(alias: String, strongBox: Boolean, unlockedOnly: Boolean): SecretKey {
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(true)
        if (strongBox && Build.VERSION.SDK_INT >= 28) spec.setIsStrongBoxBacked(true)
        // Com o telemóvel bloqueado, o Android guarda esta chave cifrada e não a deixa usar.
        if (unlockedOnly && Build.VERSION.SDK_INT >= 35) spec.setUnlockedDeviceRequired(true)
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
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val TAG_LEN = 128
    }
}

/** Testes (o Robolectric não tem o Keystore): a mesma chave AES comum para qualquer nome. */
internal class FixedTestKeys(private var key: SecretKey) : VaultKeys {
    override fun get(alias: String) = key
    override fun create(alias: String, unlockedOnly: Boolean) = key

    /** Destruir a chave é passar a usar outra. */
    override fun delete(alias: String) {
        key = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
    }

    override fun aliases() = listOf("reczi-pgp-vault")
    override fun deviceLocked() = false
    override val unlockedOnlySupported = false
}

/**
 * Guarda cada entrada do cofre cifrada com AES-256-GCM, com uma chave que vive no Android Keystore
 * (no chip de segurança do telemóvel, quando existe) e nunca sai de lá. Os ficheiros ficam em
 * noBackupFilesDir, que o Android nunca inclui em cópias de segurança.
 *
 * Os nomes das entradas dizem muito (o fingerprint de cada contacto, se há código secreto com ele,
 * se há PIN de pânico), por isso não aparecem nos nomes dos ficheiros: cada entrada fica num
 * ficheiro com nome aleatório, com o nome dela lá dentro, cifrado, e um índice cifrado liga uns
 * aos outros. Quem copiar a pasta só vê ficheiros "v2-<aleatório>" e quantos são. Até à versão
 * 1.4.2 o nome do ficheiro era o nome da entrada; esses ficheiros passam para o formato novo na
 * primeira abertura.
 *
 * As chaves privadas já estão protegidas pela palavra-passe OpenPGP; esta é uma segunda
 * camada que liga os dados a este telemóvel.
 *
 * No Android 15 ou mais recente, a chave só funciona com o telemóvel desbloqueado (1.4.6): com ele
 * bloqueado, quem conseguir correr código como a app (uma ferramenta forense, por exemplo) não abre
 * o cofre. Os cofres que já existiam passam para uma chave assim na abertura seguinte ([upgradeKey]).
 * Nas versões anteriores do Android não se usa: tirar o bloqueio de ecrã apagava a chave.
 */
class KeystoreStore internal constructor(context: Context, private val keys: VaultKeys) : Store {
    constructor(context: Context) : this(context, AndroidVaultKeys(context.applicationContext))

    /** Testes: uma chave AES comum em vez da do Keystore. */
    internal constructor(context: Context, testKey: SecretKey) : this(context, FixedTestKeys(testKey))

    private val base = context.noBackupFilesDir
    private val dir = File(base, "vault").apply { mkdirs() }
    /** Nome da chave do Keystore deste cofre (um cofre novo usa sempre um nome novo). */
    private val aliasFile = File(base, "vault-alias")
    /** Durante a mudança para uma chave nova ([upgradeKey]): "nome da nova", "nome da antiga". */
    private val nextFile = File(base, "vault-alias-next")
    private var key: SecretKey? = null
    /** A chave nova, enquanto a mudança não acaba: escreve-se com ela e lê-se com as duas. */
    private var nextKey: SecretKey? = null
    /** Nome de cada entrada -> nome do ficheiro (o índice), lido na primeira utilização. */
    private var entries: LinkedHashMap<String, String>? = null
    /** Ficheiros do formato antigo que não se conseguiram ler: ficam como estão e aparecem como estragados. */
    private val legacy = HashMap<String, String>()
    private val random = SecureRandom()

    private fun alias(): String = aliasFile.takeIf { it.exists() }?.readText()?.trim()?.ifEmpty { null } ?: DEFAULT_ALIAS

    @Synchronized
    override fun names(): List<String> {
        val idx = index()
        return (idx.keys + legacy.keys).sorted()
    }

    /** true se há uma entrada com este nome (sem a decifrar). */
    @Synchronized
    fun contains(name: String): Boolean {
        val idx = index()
        return name in legacy || idx[name]?.let { File(dir, it).exists() } == true
    }

    @Synchronized
    override fun read(name: String): ByteArray? {
        checkName(name)
        val idx = index()
        legacy[name]?.let { return openLegacy(File(dir, it), name) }
        val f = File(dir, idx[name] ?: return null)
        if (!f.exists()) return null
        val (inside, data) = openEntry(f)
        // Um ficheiro posto no lugar de outro decifra, mas traz o nome errado.
        if (inside != name) throw IOException("Ficheiro do cofre trocado.")
        return data
    }

    @Synchronized
    override fun write(name: String, data: ByteArray) {
        checkName(name)
        val idx = index()
        idx[name]?.let { file ->
            sealEntry(file, name, data) // substitui o ficheiro de uma vez (temporário + mudar o nome)
            return
        }
        val file = newFileName()
        sealEntry(file, name, data)
        idx[name] = file
        try {
            saveIndex(idx)
        } catch (e: Exception) {
            idx.remove(name)
            File(dir, file).delete()
            throw e
        }
        legacy.remove(name)?.let { File(dir, it).delete() }
    }

    @Synchronized
    override fun delete(name: String) {
        checkName(name)
        val idx = index()
        legacy.remove(name)?.let { File(dir, it).delete() }
        val file = idx[name] ?: return
        // Primeiro o ficheiro: se a app parar a meio, o índice aponta para nada, que é o mesmo que apagado.
        File(dir, file).delete()
        idx.remove(name)
        saveIndex(idx)
    }

    /** Põe o ficheiro de lado (em noBackupFilesDir/vault-avariados, com um nome sem nada de pessoal). */
    @Synchronized
    override fun quarantine(name: String) {
        checkName(name)
        val idx = index()
        legacy.remove(name)?.let { return moveAside(File(dir, it)) }
        val file = idx.remove(name) ?: return
        saveIndex(idx)
        moveAside(File(dir, file))
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
        if (lost.exists()) {
            File(lost, "alias-antigo").writeText(alias())
            // Uma mudança de chave a meio: parte dos ficheiros pode estar já com a chave nova.
            if (nextFile.exists()) nextFile.copyTo(File(lost, "alias-seguinte"), overwrite = true)
        }
        nextFile.delete()
        dir.mkdirs()
        writeAtomically(aliasFile, if (keys.unlockedOnlySupported) "$UNLOCKED_ALIAS$stamp" else "$DEFAULT_ALIAS-$stamp")
        key = null
        nextKey = null
        entries = null
        legacy.clear()
    }

    /**
     * PIN de pânico: apaga tudo, sem volta. Além dos ficheiros (incluindo os postos de lado), destrói
     * as chaves do Keystore, por isso mesmo que alguém recupere os ficheiros do armazenamento do
     * telemóvel já não há chave para os abrir.
     */
    @Synchronized
    fun wipe() {
        key = null
        nextKey = null
        runCatching { keys.aliases().filter { it.startsWith(DEFAULT_ALIAS) }.forEach { keys.delete(it) } }
        base.listFiles()?.filter { it.name.startsWith("vault") }?.forEach { it.deleteRecursively() }
        dir.mkdirs()
        entries = null
        legacy.clear()
    }

    /** true se há ficheiros no cofre mas a chave do Keystore que os protegia desapareceu. */
    @Synchronized
    fun isKeyLost(): Boolean {
        if (key != null) return false
        return keys.get(alias()) == null && hasFiles()
    }

    /** A chave do cofre só funciona com o telemóvel desbloqueado (Android 15 ou mais recente). */
    @Synchronized
    fun isUnlockedOnly(): Boolean = nextKey == null && isUnlockedOnly(alias()) && keys.unlockedOnlySupported

    // ------------------------------------------------------------------ índice e ficheiros

    private fun checkName(name: String) = require(NAME.matches(name)) { "nome inválido" }

    /** Há alguma coisa guardada (sem precisar da chave para o saber). */
    private fun hasFiles(): Boolean = dir.listFiles()?.any { !it.name.endsWith(".tmp") } == true

    private fun newFileName(): String {
        while (true) {
            val name = "v2-" + ByteArray(16).also { random.nextBytes(it) }.joinToString("") { "%02x".format(it) }
            if (!File(dir, name).exists()) return name
        }
    }

    /**
     * O índice (nome de cada entrada -> ficheiro). Na primeira utilização: lê-o (ou refá-lo a partir
     * dos ficheiros, se faltar ou estiver estragado), põe de lado ficheiros de escritas que não
     * chegaram ao fim e passa os ficheiros do formato antigo para o novo.
     */
    private fun index(): LinkedHashMap<String, String> {
        entries?.let { return it }
        recoverUpgrade()
        val files = dir.listFiles().orEmpty().toList()
        files.filter { it.name.endsWith(".tmp") }.forEach { it.delete() } // escritas interrompidas
        val indexFile = File(dir, INDEX)
        val idx = LinkedHashMap<String, String>()
        var changed = false
        val stored = if (indexFile.exists()) {
            try {
                parseIndex(openSealed(indexFile))
            } catch (e: VaultKeyLostException) {
                throw e
            } catch (e: StoreLockedException) {
                throw e // telemóvel bloqueado: não é o índice que está estragado
            } catch (e: Exception) {
                null // estragado: refaz-se a partir dos ficheiros
            }
        } else {
            null
        }
        val onDisk = files.filter { ENTRY.matches(it.name) }
        if (stored != null) {
            idx.putAll(stored)
            // Entradas cujo ficheiro desapareceu (a app parou a meio de apagar): saem do índice.
            changed = idx.values.removeAll { !File(dir, it).exists() }
            // Ficheiros que o índice não conhece: escritas que não chegaram ao fim. Ficam de lado.
            val known = idx.values.toSet()
            onDisk.filter { it.name !in known }.forEach { moveAside(it) }
        } else {
            // Cada ficheiro sabe o seu nome: o índice refaz-se. Repetidos ou ilegíveis ficam de lado.
            val names = onDisk.sortedByDescending { it.lastModified() }.map { f ->
                f to try {
                    openEntry(f).first
                } catch (e: VaultKeyLostException) {
                    throw e
                } catch (e: StoreLockedException) {
                    throw e // nada vai para o lado por o telemóvel ter bloqueado a meio
                } catch (e: Exception) {
                    null
                }
            }
            // Nenhum se lê: o problema é a chave, não os ficheiros. Não se mexe em nada.
            if (names.isNotEmpty() && names.all { it.second == null }) throw IOException("Os ficheiros do cofre não se conseguem ler.")
            for ((f, name) in names) {
                if (name == null || name in idx) moveAside(f) else idx[name] = f.name
            }
            changed = idx.isNotEmpty() || indexFile.exists()
        }
        // Formato antigo (até à 1.4.2): o nome do ficheiro era o nome da entrada.
        legacy.clear()
        val migrated = mutableListOf<File>()
        for (f in files.filter { LEGACY.matches(it.name) }) {
            val name = f.name
            if (name in idx) {
                migrated += f // já tinha passado para o formato novo
                continue
            }
            val data = try {
                openLegacy(f, name)
            } catch (e: VaultKeyLostException) {
                throw e
            } catch (e: StoreLockedException) {
                throw e
            } catch (e: Exception) {
                legacy[name] = name // ilegível: fica como está
                continue
            }
            val file = newFileName()
            sealEntry(file, name, data)
            idx[name] = file
            migrated += f
            changed = true
        }
        entries = idx
        if (changed) saveIndex(idx)
        // Só depois de o índice novo estar guardado.
        migrated.forEach { it.delete() }
        maybeUpgradeKey(idx)
        return idx
    }

    // ------------------------------------------------------------------ chave só com o telemóvel desbloqueado

    private fun isUnlockedOnly(alias: String) = alias.startsWith(UNLOCKED_ALIAS)

    private fun readNext(): Pair<String, String>? {
        val lines = nextFile.takeIf { it.exists() }?.readText()?.lines()?.filter { it.isNotBlank() } ?: return null
        return if (lines.size == 2 && lines.all { it.startsWith(DEFAULT_ALIAS) }) lines[0] to lines[1] else null
    }

    /** Uma mudança de chave que ficou a meio (a app parou): arruma-se ou retoma-se com as duas chaves. */
    private fun recoverUpgrade() {
        val (newAlias, oldAlias) = readNext() ?: return
        if (alias() == newAlias) {
            // Já tinha mudado: faltava só destruir a chave antiga.
            runCatching { keys.delete(oldAlias) }
            nextFile.delete()
            return
        }
        // Sem a chave nova, nada chegou a ser escrito com ela (cria-se antes de escrever).
        nextKey = keys.get(newAlias) ?: run {
            nextFile.delete()
            return
        }
    }

    /** No Android 15 ou mais recente, um cofre com a chave antiga passa para uma "só desbloqueado". */
    private fun maybeUpgradeKey(idx: LinkedHashMap<String, String>) {
        if (!keys.unlockedOnlySupported) return
        if (nextKey == null && isUnlockedOnly(alias())) return
        if (nextKey == null && keys.get(alias()) == null) return // cofre por estrear: a chave nasce já assim
        if (legacy.isNotEmpty()) return // ficheiros antigos ilegíveis: não se destrói a chave que os poderia abrir
        if (keys.deviceLocked()) return
        // Se falhar (p. ex. o telemóvel bloqueou a meio), fica para a próxima: até lá lê-se com as duas.
        runCatching { upgradeKey(idx) }
    }

    /**
     * Passa o cofre para uma chave nova que só funciona com o telemóvel desbloqueado. Cada ficheiro é
     * reescrito com a chave nova, um a um, e cada escrita é atómica; se a app parar a meio, na abertura
     * seguinte lê-se com as duas chaves e continua-se. Só no fim o cofre passa a usar a chave nova, e
     * só depois disso a antiga é destruída.
     */
    private fun upgradeKey(idx: LinkedHashMap<String, String>) {
        val oldAlias = alias()
        key() // a antiga tem de existir (senão VaultKeyLostException, e não se mexe em nada)
        val newAlias = readNext()?.first ?: "$UNLOCKED_ALIAS${System.currentTimeMillis()}".also { writeAtomically(nextFile, "$it\n$oldAlias") }
        val next = nextKey ?: (keys.get(newAlias) ?: keys.create(newAlias, unlockedOnly = true)).also { nextKey = it }
        for ((name, file) in idx) {
            val f = File(dir, file)
            val (plain, withNew) = openSealedWith(f)
            try {
                if (withNew) continue // já tinha passado numa tentativa anterior
                if (entryName(plain) != name) throw IOException("Ficheiro do cofre trocado.")
                writeSealed(file, plain)
            } finally {
                plain.fill(0)
            }
        }
        saveIndex(idx)
        // A partir daqui o cofre usa a chave nova.
        writeAtomically(aliasFile, newAlias)
        key = next
        nextKey = null
        runCatching { keys.delete(oldAlias) }
        nextFile.delete()
    }

    /** Escreve um ficheiro pequeno de uma vez (temporário, sincronizado, renomeado). */
    private fun writeAtomically(target: File, text: String) {
        val tmp = File(target.parentFile, target.name + ".tmp")
        FileOutputStream(tmp).use { out ->
            out.write(text.toByteArray(Charsets.UTF_8))
            out.fd.sync()
        }
        if (!tmp.renameTo(target)) {
            tmp.delete()
            throw IOException("Não foi possível guardar ${target.name}.")
        }
    }

    private fun saveIndex(idx: Map<String, String>) =
        writeSealed(INDEX, idx.entries.joinToString("\n") { "${it.key}\t${it.value}" }.toByteArray(Charsets.UTF_8))

    private fun parseIndex(data: ByteArray): Map<String, String> =
        String(data, Charsets.UTF_8).lines().filter { it.isNotEmpty() }.associate { line ->
            val (name, file) = line.split('\t').also { if (it.size != 2) throw IOException("Índice do cofre inválido.") }
            if (!NAME.matches(name) || !ENTRY.matches(file)) throw IOException("Índice do cofre inválido.")
            name to file
        }

    /** Uma entrada: o nome dela (2 bytes de tamanho + UTF-8) e os dados, tudo cifrado. */
    private fun sealEntry(file: String, name: String, data: ByteArray) {
        val n = name.toByteArray(Charsets.UTF_8)
        val plain = ByteArray(2 + n.size + data.size)
        plain[0] = (n.size shr 8).toByte()
        plain[1] = n.size.toByte()
        n.copyInto(plain, 2)
        data.copyInto(plain, 2 + n.size)
        try {
            writeSealed(file, plain)
        } finally {
            plain.fill(0)
        }
    }

    private fun openEntry(f: File): Pair<String, ByteArray> {
        val plain = openSealed(f)
        try {
            val name = entryName(plain)
            val n = ((plain[0].toInt() and 0xff) shl 8) or (plain[1].toInt() and 0xff)
            return name to plain.copyOfRange(2 + n, plain.size)
        } finally {
            plain.fill(0)
        }
    }

    /** O nome que vai dentro de uma entrada já decifrada (2 bytes de tamanho + UTF-8). */
    private fun entryName(plain: ByteArray): String {
        if (plain.size < 2) throw IOException("Ficheiro do cofre inválido.")
        val n = ((plain[0].toInt() and 0xff) shl 8) or (plain[1].toInt() and 0xff)
        if (plain.size < 2 + n) throw IOException("Ficheiro do cofre inválido.")
        return String(plain, 2, n, Charsets.UTF_8)
    }

    /** Cifra e grava de uma vez: ficheiro temporário, sincronizado com o disco, depois renomeado. */
    private fun writeSealed(file: String, plain: ByteArray) {
        val (iv, sealed) = withKey {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, nextKey ?: key()) // o Keystore gera o IV
            cipher.updateAAD(file.toByteArray()) // o conteúdo fica preso a este ficheiro
            val out = cipher.doFinal(plain)
            cipher.iv to out
        }
        check(iv.size == IV_LEN)
        val target = File(dir, file)
        val tmp = File(dir, "$file.tmp")
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

    private fun openSealed(f: File): ByteArray = openSealedWith(f).first

    /** Decifra um ficheiro; o segundo valor diz se foi com a chave nova de uma mudança a meio. */
    private fun openSealedWith(f: File): Pair<ByteArray, Boolean> {
        val data = f.readBytes()
        if (data.size < 1 + IV_LEN + TAG_LEN / 8 || data[0] != FORMAT) throw IOException("Ficheiro do cofre inválido.")
        return decrypt(data, f.name.toByteArray())
    }

    /** Formato antigo (até à 1.4.2): o ficheiro tem o nome da entrada, que também é o AAD. */
    private fun openLegacy(f: File, name: String): ByteArray {
        val data = f.readBytes()
        if (data.size < 1 + IV_LEN + TAG_LEN / 8 || data[0] != LEGACY_FORMAT) throw IOException("Ficheiro do cofre inválido.")
        return decrypt(data, name.toByteArray()).first
    }

    /** A meio de uma mudança de chave experimenta a nova e depois a antiga; diz se foi a nova. */
    private fun decrypt(data: ByteArray, aad: ByteArray): Pair<ByteArray, Boolean> = withKey {
        val candidates = listOfNotNull(nextKey) + key()
        var wrong: AEADBadTagException? = null
        for (k in candidates) {
            try {
                val cipher = Cipher.getInstance(TRANSFORMATION)
                cipher.init(Cipher.DECRYPT_MODE, k, GCMParameterSpec(TAG_LEN, data, 1, IV_LEN))
                cipher.updateAAD(aad)
                return@withKey cipher.doFinal(data, 1 + IV_LEN, data.size - 1 - IV_LEN) to (k === nextKey)
            } catch (e: AEADBadTagException) {
                wrong = e // outra chave, ou ficheiro alterado
            }
        }
        throw wrong!!
    }

    /**
     * Uma operação com a chave do cofre. Com o telemóvel bloqueado (Android 15+), a chave não se
     * pode usar: falha com [StoreLockedException], nunca como "ficheiro estragado".
     */
    private inline fun <T> withKey(block: () -> T): T = try {
        block()
    } catch (e: VaultKeyLostException) {
        throw e
    } catch (e: StoreLockedException) {
        throw e
    } catch (e: Exception) {
        if (keys.deviceLocked()) throw StoreLockedException(e)
        throw e
    }

    /** Põe um ficheiro de lado sem o destruir, com um nome que não diz nada. */
    private fun moveAside(f: File) {
        val bad = File(base, "vault-avariados").apply { mkdirs() }
        val name = "${System.currentTimeMillis()}-" + ByteArray(6).also { random.nextBytes(it) }.joinToString("") { "%02x".format(it) }
        if (f.exists() && !f.renameTo(File(bad, name))) f.delete()
    }

    private fun key(): SecretKey = key ?: loadOrCreateKey().also { key = it }

    private fun loadOrCreateKey(): SecretKey {
        val alias = alias()
        keys.get(alias)?.let { return it }
        // Sem chave mas com ficheiros: não criar outra às escondidas (os ficheiros ficariam ilegíveis
        // para sempre e qualquer recuperação deixaria de ser possível).
        if (hasFiles()) throw VaultKeyLostException()
        // Cofre novo: no Android 15 ou mais recente, a chave já nasce "só com o telemóvel desbloqueado".
        val name = if (keys.unlockedOnlySupported && !isUnlockedOnly(alias)) {
            "$UNLOCKED_ALIAS${System.currentTimeMillis()}".also { writeAtomically(aliasFile, it) }
        } else {
            alias
        }
        return withKey { keys.create(name, unlockedOnly = isUnlockedOnly(name)) }
    }

    private companion object {
        const val DEFAULT_ALIAS = "reczi-pgp-vault"
        /** As chaves "só com o telemóvel desbloqueado" (Android 15+) têm este início de nome. */
        const val UNLOCKED_ALIAS = "$DEFAULT_ALIAS-u"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val IV_LEN = 12
        const val TAG_LEN = 128
        /** Formato atual: nome aleatório, com o nome da entrada lá dentro. */
        const val FORMAT: Byte = 2
        /** Até à 1.4.2: o nome do ficheiro era o nome da entrada. */
        const val LEGACY_FORMAT: Byte = 1
        const val INDEX = "v2-index"
        /** Nome de uma entrada (p. ex. "pub-<fingerprint>"); é também o nome dos ficheiros antigos. */
        val NAME = Regex("^[a-z]+(-[0-9A-F]{40,64})?$")
        val LEGACY = NAME
        val ENTRY = Regex("^v2-[0-9a-f]{32}$")
    }
}
