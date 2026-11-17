package app.reczi.pgp.core

import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.pgpainless.PGPainless

/** Armazenamento de pequenos ficheiros por nome. No Android, cada ficheiro é cifrado com o Keystore. */
interface Store {
    fun names(): List<String>
    fun read(name: String): ByteArray?
    fun write(name: String, data: ByteArray)
    fun delete(name: String)

    /** Põe de lado um ficheiro ilegível sem o destruir (por omissão, apaga-o). */
    fun quarantine(name: String) = delete(name)
}

class MemoryStore : Store {
    private val files = linkedMapOf<String, ByteArray>()
    override fun names() = files.keys.toList()
    override fun read(name: String) = files[name]?.copyOf()
    override fun write(name: String, data: ByteArray) { files[name] = data.copyOf() }
    override fun delete(name: String) { files.remove(name) }
}

data class MyKey(val ring: PGPSecretKeyRing, val info: KeyInfo)

data class Contact(
    val cert: PGPPublicKeyRing,
    val info: KeyInfo,
    val verified: Boolean,
    /** Se há um código secreto combinado com este contacto: os algarismos para o confirmar. */
    val codeCheck: String? = null,
)

/** Um texto disfarçado já convertido em PGP normal; [codeFpr] é o contacto cujo código secreto o abriu. */
data class Revealed(val armored: String, val codeFpr: String?)

/**
 * Um ficheiro do cofre que não foi possível ler ou avaliar. Se o ficheiro se leu mas a chave não
 * pôde ser avaliada (p. ex. relógio do telemóvel errado), [readable] traz a chave para backup.
 */
data class BrokenEntry(val name: String, val isPrivateKey: Boolean, val reason: String, val readable: PGPSecretKeyRing? = null)

/** Resultado de importar chaves públicas: as novas e as recusadas (com o motivo). */
data class ImportResult(val added: List<String>, val updated: Int, val rejected: List<String>)

/** Fotografia do cofre para a interface mostrar sem voltar a ler os ficheiros. */
data class Snapshot(
    val myKeys: List<MyKey>,
    val contacts: List<Contact>,
    val broken: List<BrokenEntry>,
    val notes: List<Note> = emptyList(),
)

/**
 * Uma nota guardada no cofre. O texto está encriptado (OpenPGP) para as tuas chaves; a [label]
 * é só para a reconheceres na lista e NÃO está protegida pela palavra-passe.
 */
data class Note(val id: String, val saved: java.util.Date, val label: String)

enum class PinResult { Ok, Panic, Wrong }

/** O que um backup completo acrescentou ao cofre (o que já existia não conta). */
data class RestoreResult(val keys: Int, val contacts: Int, val notes: Int, val codes: Int)

/**
 * As tuas chaves privadas e as chaves públicas dos destinatários. Só deixa encriptar
 * para destinatários cuja impressão digital confirmaste ([setVerified]).
 *
 * Um ficheiro estragado nunca impede o acesso aos outros: aparece em [Snapshot.broken].
 * Todos os métodos são sincronizados; os dados lidos ficam em memória.
 */
class Vault(private val store: Store) {
    private val cache = HashMap<String, ByteArray>()
    /** Preferências privadas em memória (ver [prefs]); têm bloqueio próprio, curto. */
    private val prefsLock = Any()
    private var prefs: Map<String, String>? = null

    @Synchronized
    fun snapshot(): Snapshot {
        val broken = mutableListOf<BrokenEntry>()
        val verified = try {
            verified()
        } catch (e: Exception) {
            broken += BrokenEntry(VERIFIED, false, "Lista de contactos verificados ilegível; todos ficam por verificar.")
            emptySet()
        }
        val myKeys = store.names().filter { it.startsWith(SEC) }.mapNotNull { name ->
            var ring: PGPSecretKeyRing? = null
            try {
                ring = PGPainless.readKeyRing().secretKeyRing(load(name) ?: return@mapNotNull null)
                    ?: throw PgpError("vazio")
                MyKey(ring, Pgp.info(ring))
            } catch (e: Exception) {
                broken += if (ring != null) {
                    BrokenEntry(name, true, "A chave lê-se, mas não pode ser usada agora: ${reason(e)} Confirma a data e a hora do telemóvel.", ring)
                } else {
                    BrokenEntry(name, true, reason(e))
                }
                null
            }
        }
        val mine = myKeys.map { it.info.fingerprint }.toSet()
        val contacts = store.names().filter { it.startsWith(PUB) }.mapNotNull { name ->
            try {
                val cert = PGPainless.readKeyRing().publicKeyRing(load(name) ?: return@mapNotNull null)
                    ?: throw PgpError("vazio")
                val info = Pgp.info(cert)
                if (info.fingerprint in mine) null
                else Contact(cert, info, info.fingerprint in verified, code(info.fingerprint)?.let(Disguise::checkDigits))
            } catch (e: Exception) {
                broken += BrokenEntry(name, false, reason(e))
                null
            }
        }
        val notes = store.names().filter { it.startsWith(NOTE) }.mapNotNull { name ->
            try {
                val (millis, label) = String(load(name) ?: return@mapNotNull null, Charsets.UTF_8).split("\n", limit = 3)
                Note(name.removePrefix(NOTE), java.util.Date(millis.toLong()), label)
            } catch (e: Exception) {
                broken += BrokenEntry(name, false, "Nota ilegível.")
                null
            }
        }.sortedByDescending { it.saved }
        prefs() // fica em memória: a interface lê-as sem tocar no armazenamento
        return Snapshot(myKeys, contacts, broken, notes)
    }

    fun myKeys(): List<PGPSecretKeyRing> = snapshot().myKeys.map { it.ring }

    fun myKey(fingerprint: String): PGPSecretKeyRing =
        snapshot().myKeys.firstOrNull { it.info.fingerprint == fingerprint }?.ring ?: throw PgpError("Chave não encontrada.")

    fun contacts(): List<Contact> = snapshot().contacts

    @Synchronized
    fun addMyKey(key: PGPSecretKeyRing) {
        Pgp.info(key)
        if (!Pgp.isProtected(key)) throw PgpError("Recuso guardar uma chave privada sem palavra-passe.")
        if (!Pgp.hasUsableSecret(key)) throw PgpError("Esta chave não contém a parte privada.")
        val fpr = Pgp.fingerprint(key)
        save(SEC + fpr, key.encoded)
        // Se a tinhas como destinatário, passa a ser tua.
        remove(PUB + fpr)
        setVerified(fpr, false)
    }

    @Synchronized
    fun deleteMyKey(fingerprint: String) {
        remove(SEC + fingerprint)
        forgetPrefs(fingerprint)
    }

    /**
     * Importa (ou atualiza) chaves públicas, uma a uma: as que não servem são recusadas com o
     * motivo, sem impedir as outras. As tuas próprias chaves são ignoradas. Uma chave nova tem
     * de ser válida e servir para encriptar; uma atualização é aceite mesmo que revogue a chave
     * (para saberes disso).
     */
    @Synchronized
    fun importContacts(certs: List<PGPPublicKeyRing>): ImportResult {
        val mine = snapshot().myKeys.map { it.info.fingerprint }.toSet()
        val added = mutableListOf<String>()
        val rejected = mutableListOf<String>()
        var updated = 0
        for (cert in certs) {
            val fpr = Pgp.fingerprint(cert)
            if (fpr in mine) continue
            try {
                val old = try {
                    load(PUB + fpr)?.let { PGPainless.readKeyRing().publicKeyRing(it) }
                } catch (e: Exception) {
                    null // ficheiro estragado: substitui-se pela chave nova
                }
                val result = if (old != null) {
                    Pgp.cleanCertificate(PGPainless.mergeCertificate(old, cert), requireUsable = false)
                } else {
                    Pgp.cleanCertificate(cert, requireUsable = true)
                }
                save(PUB + fpr, result.encoded)
                if (old == null) added += fpr else updated++
            } catch (e: PgpError) {
                rejected += "${fpr.takeLast(16)}: ${e.message}"
            }
        }
        if (added.isEmpty() && updated == 0 && rejected.isNotEmpty()) throw PgpError(rejected.joinToString("\n"))
        return ImportResult(added, updated, rejected)
    }

    @Synchronized
    fun deleteContact(fingerprint: String) {
        remove(PUB + fingerprint)
        remove(CODE + fingerprint)
        setVerified(fingerprint, false)
        forgetPrefs(fingerprint)
    }

    @Synchronized
    fun setVerified(fingerprint: String, verified: Boolean) {
        val set = try { verified().toMutableSet() } catch (e: Exception) { mutableSetOf() }
        val changed = if (verified) set.add(fingerprint) else set.remove(fingerprint)
        if (changed) save(VERIFIED, set.sorted().joinToString("\n").toByteArray())
    }

    /**
     * Guarda o código secreto combinado com um contacto (ver [Disguise]). Fica guardada só a chave
     * derivada da frase, não a frase. Devolve os algarismos de confirmação.
     */
    fun setCode(fingerprint: String, code: CharArray): String {
        val secret = Disguise.deriveSecret(code) // lento: fora do bloqueio do cofre
        synchronized(this) {
            if (snapshot().contacts.none { it.info.fingerprint == fingerprint }) throw PgpError("Destinatário desconhecido.")
            save(CODE + fingerprint, secret)
        }
        return Disguise.checkDigits(secret)
    }

    @Synchronized
    fun clearCode(fingerprint: String) = remove(CODE + fingerprint)

    private fun code(fingerprint: String): ByteArray? = load(CODE + fingerprint)?.takeIf { it.size == 32 }

    /**
     * Disfarça um texto PGP (mensagem ou chave). Com [codeFpr], usa o código secreto combinado
     * com esse contacto em vez da chave fixa da app.
     */
    @Synchronized
    fun disguise(armored: String, words: Boolean, codeFpr: String? = null): String =
        disguise(armored, if (words) Disguise.Style.Words else Disguise.Style.Code, codeFpr)

    @Synchronized
    fun disguise(armored: String, style: Disguise.Style, codeFpr: String? = null): String {
        val secret = codeFpr?.let { code(it) ?: throw PgpError("Não há código secreto combinado com este contacto.") }
        return Disguise.hide(Pgp.dearmor(armored), style, secret)
    }

    /**
     * Se [text] for um texto disfarçado (com a chave da app ou com o código secreto de um
     * contacto), devolve-o como PGP normal; caso contrário devolve null.
     */
    @Synchronized
    fun reveal(text: String): Revealed? {
        val codes = store.names().filter { it.startsWith(CODE) }.mapNotNull { n -> code(n.removePrefix(CODE))?.let { n.removePrefix(CODE) to it } }
        val (bytes, i) = Disguise.revealWith(text, codes.map { it.second }) ?: return null
        val armored = runCatching { Pgp.ensureArmored(bytes) }.getOrNull() ?: return null
        return Revealed(armored, codes.getOrNull(i)?.first)
    }

    /** Texto recebido → PGP normal, com uma explicação útil quando não se reconhece. */
    private fun normalize(text: String): Revealed {
        reveal(text)?.let { return it }
        if ("-----BEGIN PGP" !in text) {
            throw PgpError(
                "Não reconheço esta mensagem. Se foi enviada com código secreto, confirma que tens nesse contacto " +
                    "o mesmo código que o remetente (os algarismos de confirmação têm de ser iguais)."
            )
        }
        return Revealed(text, null)
    }

    // ------------------------------------------------------------------ notas

    /**
     * Guarda uma nota encriptada para todas as tuas chaves utilizáveis (não precisa de palavra-passe
     * para guardar; só para ler). Com [id], substitui essa nota. Devolve o id.
     */
    @Synchronized
    fun saveNote(id: String?, label: String, text: String): String {
        if (text.isBlank()) throw PgpError("Escreve primeiro a nota.")
        val mine = snapshot().myKeys.filter { it.info.canEncrypt }.map { Pgp.certificateOf(it.ring) }
        if (mine.isEmpty()) throw PgpError("Precisas de uma chave tua válida para guardar notas (separador Chaves).")
        val noteId = id ?: ByteArray(20).also { java.security.SecureRandom().nextBytes(it) }.joinToString("") { "%02X".format(it) }
        if (!Regex("[0-9A-F]{40}").matches(noteId)) throw PgpError("Nota desconhecida.")
        val clean = Pgp.displayName(label.ifBlank { "Nota" })
        val armored = Pgp.encrypt(text, mine, null, null)
        save(NOTE + noteId, "${System.currentTimeMillis()}\n$clean\n$armored".toByteArray(Charsets.UTF_8))
        return noteId
    }

    /** Desencripta o texto de uma nota. */
    fun readNote(id: String, passphrase: CharArray): String {
        val armored = synchronized(this) {
            String(load(NOTE + id) ?: throw PgpError("Nota desconhecida."), Charsets.UTF_8).split("\n", limit = 3).getOrNull(2)
        } ?: throw PgpError("Nota ilegível.")
        val myKeys = snapshot().myKeys.map { it.ring }
        return Pgp.decrypt(armored, myKeys, passphrase, myKeys.map { Pgp.certificateOf(it) }).text
    }

    @Synchronized
    fun deleteNote(id: String) = remove(NOTE + id)

    // ------------------------------------------------------------------ PIN da app

    @Synchronized
    fun hasPin(): Boolean = load(PIN) != null

    @Synchronized
    fun hasPanicPin(): Boolean = load(PANIC) != null

    /** Define o PIN que abre a app. Não pode ser igual ao PIN de pânico. */
    fun setPin(pin: CharArray) {
        if (matches(PANIC, pin)) throw PgpError("O PIN da app tem de ser diferente do PIN de pânico.")
        val hash = Lock.hash(pin)
        synchronized(this) { save(PIN, hash) }
    }

    /** Define o PIN de pânico (ver [checkPin]). Só com PIN da app definido, e diferente dele. */
    fun setPanicPin(pin: CharArray) {
        if (!hasPin()) throw PgpError("Define primeiro o PIN da app.")
        if (matches(PIN, pin)) throw PgpError("O PIN de pânico tem de ser diferente do PIN da app.")
        val hash = Lock.hash(pin)
        synchronized(this) { save(PANIC, hash) }
    }

    /** Tira o PIN da app (e, com ele, o de pânico). */
    @Synchronized
    fun clearPin() { remove(PIN); remove(PANIC) }

    @Synchronized
    fun clearPanicPin() = remove(PANIC)

    /**
     * Confere um PIN escrito no ecrã de bloqueio. [PinResult.Panic] quer dizer que foi escrito o
     * PIN de pânico: quem chama deve apagar tudo ([wipe] e a chave do armazenamento).
     */
    fun checkPin(pin: CharArray): PinResult {
        // Confere sempre os dois, para o tempo de resposta não denunciar qual foi.
        val ok = matches(PIN, pin)
        val panic = matches(PANIC, pin)
        return when { panic -> PinResult.Panic; ok -> PinResult.Ok; else -> PinResult.Wrong }
    }

    private fun matches(name: String, pin: CharArray): Boolean {
        val stored = synchronized(this) { load(name) }
        return Lock.matches(stored, pin)
    }

    /** Apaga TUDO o que está no cofre: chaves, contactos, códigos, notas, PINs e preferências. Não há volta. */
    @Synchronized
    fun wipe() {
        cache.clear()
        synchronized(prefsLock) {
            store.names().forEach { store.delete(it) }
            prefs = null
        }
    }

    // ------------------------------------------------------------------ preferências privadas

    /**
     * Preferências que dizem com quem e como comunicas: o formato usado com cada contacto, se usas
     * o código secreto, que chaves já têm backup, o formato escolhido. Ficam aqui, cifradas como o
     * resto do cofre, e não nas preferências do Android, que estão em claro no telemóvel (numa
     * extração forense mostrariam os fingerprints das pessoas a quem escreves). As que acabam em
     * "-<fingerprint>" saem quando esse contacto ou essa chave é apagado. Não vão nos backups.
     *
     * Têm um bloqueio próprio e curto, para a interface as poder ler sem esperar pelas operações
     * longas do cofre. Ficam em memória a partir do primeiro [snapshot].
     */
    fun prefs(): Map<String, String> = synchronized(prefsLock) { prefs ?: readPrefs().also { prefs = it } }

    /** Muda preferências privadas (null apaga) e guarda-as logo. */
    fun setPrefs(changes: Map<String, String?>) {
        for ((k, v) in changes) {
            require(isPrefName(k)) { "Nome de preferência inválido." }
            require(v == null || (v.isNotEmpty() && v.none { it == '\n' || it == '\r' })) { "Valor de preferência inválido." }
        }
        synchronized(prefsLock) {
            val now = prefs()
            val next = now.toMutableMap()
            for ((k, v) in changes) if (v == null) next.remove(k) else next[k] = v
            if (next == now) return
            if (next.isEmpty()) store.delete(PREFS) else store.write(PREFS, next.toSortedMap().entries.joinToString("\n") { "${it.key}=${it.value}" }.toByteArray())
            prefs = next
        }
    }

    /** Esquece as preferências ligadas a um contacto ou a uma chave tua. */
    private fun forgetPrefs(fingerprint: String) {
        val gone = prefs().keys.filter { it.endsWith("-$fingerprint") }
        if (gone.isNotEmpty()) setPrefs(gone.associateWith { null })
    }

    /** Um ficheiro estragado só faz perder preferências (o próximo [setPrefs] substitui-o). */
    private fun readPrefs(): Map<String, String> {
        val data = runCatching { store.read(PREFS) }.getOrNull() ?: return emptyMap()
        return String(data, Charsets.UTF_8).lines().mapNotNull { line ->
            val i = line.indexOf('=')
            if (i > 0 && i < line.length - 1 && isPrefName(line.substring(0, i))) line.substring(0, i) to line.substring(i + 1) else null
        }.toMap()
    }

    // ------------------------------------------------------------------ backup completo

    /**
     * Tudo o que está no cofre num só ficheiro cifrado com [passphrase] (ver [Backup]): chaves
     * privadas, contactos e verificações, códigos secretos e notas. Os PINs da app não vão: o
     * bloqueio é de cada telemóvel.
     */
    fun exportBackup(passphrase: CharArray): ByteArray {
        val entries = synchronized(this) {
            store.names().filter { name -> KINDS.any { name.startsWith(it) } || name == VERIFIED }
                .mapNotNull { name -> runCatching { load(name) }.getOrNull()?.let { name to it } }.toMap()
        }
        if (entries.keys.none { it.startsWith(SEC) }) throw PgpError("Ainda não tens nenhuma chave para pôr no backup.")
        return Backup.seal(entries, passphrase)
    }

    /**
     * Junta ao cofre o que vem num backup completo. Nada do que já cá está é apagado nem
     * substituído: chaves, notas e códigos que já existam ficam como estão; os contactos são
     * atualizados como numa importação normal. Cada entrada é validada antes de entrar.
     */
    fun importBackup(data: ByteArray, passphrase: CharArray): RestoreResult {
        val entries = Backup.open(data, passphrase) // lento (scrypt): fora do bloqueio do cofre
        synchronized(this) {
            val hex = Regex("[0-9A-F]{40,64}")
            var keys = 0
            var notes = 0
            var codes = 0
            for ((name, bytes) in entries.filterKeys { it.startsWith(SEC) }) {
                val ring = runCatching { PGPainless.readKeyRing().secretKeyRing(bytes) }.getOrNull() ?: continue
                if (name != SEC + Pgp.fingerprint(ring) || load(name) != null) continue
                if (runCatching { addMyKey(ring) }.isSuccess) keys++
            }
            val certs = entries.filterKeys { it.startsWith(PUB) }.mapNotNull { (name, bytes) ->
                runCatching { PGPainless.readKeyRing().publicKeyRing(bytes) }.getOrNull()?.takeIf { name == PUB + Pgp.fingerprint(it) }
            }
            val imported = if (certs.isEmpty()) ImportResult(emptyList(), 0, emptyList())
            else runCatching { importContacts(certs) }.getOrDefault(ImportResult(emptyList(), 0, emptyList()))
            val known = snapshot().contacts.map { it.info.fingerprint }.toSet()
            // O backup está autenticado pela palavra-passe: as verificações que lá vêm são as tuas.
            entries[VERIFIED]?.toString(Charsets.UTF_8)?.lines()?.filter { it in known }?.forEach { setVerified(it, true) }
            for ((name, bytes) in entries.filterKeys { it.startsWith(CODE) }) {
                val fpr = name.removePrefix(CODE)
                if (fpr in known && bytes.size == 32 && load(name) == null) { save(name, bytes); codes++ }
            }
            for ((name, bytes) in entries.filterKeys { it.startsWith(NOTE) }) {
                val parts = String(bytes, Charsets.UTF_8).split("\n", limit = 3)
                val ok = hex.matches(name.removePrefix(NOTE)) && parts.size == 3 && parts[0].toLongOrNull() != null && "BEGIN PGP MESSAGE" in parts[2]
                if (ok && load(name) == null) { save(name, bytes); notes++ }
            }
            return RestoreResult(keys, imported.added.size, notes, codes)
        }
    }

    // ------------------------------------------------------------------ assinar e ficheiros

    /** Assina um texto sem o encriptar (ver [Pgp.sign]). */
    fun sign(text: String, myFpr: String, passphrase: CharArray): String = Pgp.sign(text, myKey(myFpr), passphrase)

    /** Verifica um texto assinado e diz de quem é a assinatura. */
    fun verify(message: String): DecryptResult {
        val snap = snapshot()
        val d = Pgp.verify(message, trustOrder(snap))
        return result(d.text, d.signature, snap, null)
    }

    /** Encripta um ficheiro para os mesmos destinatários que [encrypt] aceitaria. */
    fun encryptFile(
        input: java.io.InputStream, output: java.io.OutputStream, fileName: String?,
        recipientFprs: List<String>, myFpr: String, sign: Boolean, passphrase: CharArray?,
    ) {
        val snap = snapshot()
        val me = snap.myKeys.firstOrNull { it.info.fingerprint == myFpr }?.ring ?: throw PgpError("Chave não encontrada.")
        Pgp.encryptFile(input, output, fileName, recipients(snap, recipientFprs, myFpr), if (sign) me else null, passphrase)
    }

    /** true se o ficheiro encriptado é para uma das tuas chaves (ou tem destinatário oculto). */
    fun isFileForMe(input: java.io.InputStream): Boolean {
        val ids = Pgp.recipientKeyIds(input)
        val mine = snapshot().myKeys.flatMap { Pgp.keyIds(it.ring) }.toSet()
        return ids.any { it == 0L || it in mine }
    }

    /**
     * Desencripta um ficheiro para [output]. Em [DecryptResult.text] vem o nome original, se houver.
     * Se lançar um erro, quem chamou tem de apagar o que ficou escrito (ver [Pgp.decryptFile]).
     */
    fun decryptFile(open: () -> java.io.InputStream, output: java.io.OutputStream, passphrase: CharArray): DecryptResult {
        val snap = snapshot()
        val myKeys = snap.myKeys.map { it.ring }
        if (myKeys.isEmpty()) throw PgpError("Ainda não tens nenhuma chave privada.")
        val d = Pgp.decryptFile(open, output, myKeys, passphrase, trustOrder(snap))
        return result(d.text, d.signature, snap, null)
    }

    /** Assina um ficheiro e devolve a assinatura à parte, em texto (ver [Pgp.signDetached]). */
    fun signDetached(input: java.io.InputStream, myFpr: String, passphrase: CharArray): String =
        Pgp.signDetached(input, myKey(myFpr), passphrase)

    /** Verifica um ficheiro com a assinatura à parte e diz de quem é. */
    fun verifyDetached(open: () -> java.io.InputStream, signature: ByteArray): DecryptResult {
        val snap = snapshot()
        return result("", Pgp.verifyDetached(open, signature, trustOrder(snap)), snap, null)
    }

    // ------------------------------------------------------------------ gerir as tuas chaves

    /** Muda a palavra-passe de uma chave tua. */
    @Synchronized
    fun changePassphrase(fingerprint: String, old: CharArray, new: CharArray) {
        save(SEC + fingerprint, Pgp.changePassphrase(myKey(fingerprint), old, new).encoded)
    }

    /** Certificado de revogação de uma chave tua, para guardar à parte (não revoga nada sozinho). */
    fun revocationCertificate(fingerprint: String, passphrase: CharArray): String =
        Pgp.revocationCertificate(myKey(fingerprint), passphrase)

    /** Revoga uma chave tua de vez. Devolve a chave pública revogada, para enviar aos contactos. */
    @Synchronized
    fun revoke(fingerprint: String, passphrase: CharArray, reason: Pgp.RevokeReason): String {
        val revoked = Pgp.revoke(myKey(fingerprint), passphrase, reason)
        save(SEC + fingerprint, revoked.encoded)
        return Pgp.armor(Pgp.certificateOf(revoked))
    }

    /**
     * As tuas chaves (impressões digitais) para as quais a mensagem foi encriptada, pela ordem das
     * tuas chaves. Com destinatário oculto, são todas.
     */
    fun myKeysFor(text: String): List<String> = myKeysFor(Pgp.recipientKeyIds(normalize(text).armored))

    fun myKeysForFile(input: java.io.InputStream): List<String> = myKeysFor(Pgp.recipientKeyIds(input))

    private fun myKeysFor(ids: List<Long>): List<String> {
        val mine = snapshot().myKeys
        if (0L in ids) return mine.map { it.info.fingerprint }
        return mine.filter { k -> Pgp.keyIds(k.ring).any { it in ids } }.map { it.info.fingerprint }
    }

    /** Esquece o que estava em memória (depois de começar um cofre novo). */
    @Synchronized
    fun clearCache() {
        cache.clear()
        synchronized(prefsLock) { prefs = null }
    }

    /** A chave privada para backup, incluindo uma que se lê mas não pode ser avaliada agora. */
    fun backupRing(fingerprint: String): PGPSecretKeyRing {
        val snap = snapshot()
        return snap.myKeys.firstOrNull { it.info.fingerprint == fingerprint }?.ring
            ?: snap.broken.mapNotNull { it.readable }.firstOrNull { Pgp.fingerprint(it) == fingerprint }
            ?: throw PgpError("Chave não encontrada.")
    }

    /** Põe de lado um ficheiro ilegível (as chaves privadas nunca são destruídas). */
    @Synchronized
    fun discardBroken(name: String) {
        cache.remove(name)
        store.quarantine(name)
    }

    private fun verified(): Set<String> =
        load(VERIFIED)?.toString(Charsets.UTF_8)?.lines()?.filter { it.isNotBlank() }?.toSet() ?: emptySet()

    /**
     * Encripta para os destinatários indicados e para ti próprio, para conseguires reler o que
     * enviaste. Os destinatários podem ser contactos (têm de estar verificados) ou chaves tuas
     * (p. ex. para guardar uma nota só para ti). Assina se [sign].
     *
     * Modo compacto: com [toSelf] a false a mensagem vai só para os destinatários escolhidos (fica
     * mais curta, mas tu deixas de a conseguir reler); sem [sign] poupa-se também a assinatura.
     */
    fun encrypt(
        text: String, recipientFprs: List<String>, myFpr: String, sign: Boolean, passphrase: CharArray?, toSelf: Boolean = true,
    ): String {
        if (text.isEmpty()) throw PgpError("Escreve primeiro a mensagem.")
        val snap = snapshot()
        val me = snap.myKeys.firstOrNull { it.info.fingerprint == myFpr }?.ring ?: throw PgpError("Chave não encontrada.")
        return Pgp.encrypt(text, recipients(snap, recipientFprs, myFpr, toSelf), if (sign) me else null, passphrase)
    }

    private fun recipients(snap: Snapshot, recipientFprs: List<String>, myFpr: String, toSelf: Boolean = true): List<PGPPublicKeyRing> {
        if (recipientFprs.isEmpty()) throw PgpError("Escolhe pelo menos um destinatário.")
        val contacts = snap.contacts.associateBy { it.info.fingerprint }
        val mine = snap.myKeys.associateBy { it.info.fingerprint }
        if (myFpr !in mine) throw PgpError("Chave não encontrada.")
        return (if (toSelf) recipientFprs + myFpr else recipientFprs).distinct().map { fpr ->
            val own = mine[fpr]
            if (own != null) {
                if (!own.info.canEncrypt) throw PgpError("A tua chave ${own.info.userId} expirou ou foi revogada.")
                return@map Pgp.certificateOf(own.ring)
            }
            val c = contacts[fpr] ?: throw PgpError("Destinatário desconhecido.")
            if (!c.verified) throw PgpError("Ainda não verificaste a chave de ${c.info.userId}.")
            if (c.info.revoked) throw PgpError("A chave de ${c.info.userId} foi REVOGADA.")
            if (!c.info.canEncrypt) throw PgpError("A chave de ${c.info.userId} expirou.")
            c.cert
        }
    }

    /** Chaves para verificar assinaturas, por ordem de confiança: as tuas, contactos verificados, os restantes. */
    private fun trustOrder(snap: Snapshot): List<PGPPublicKeyRing> =
        snap.myKeys.map { Pgp.certificateOf(it.ring) } + snap.contacts.filter { it.verified }.map { it.cert } +
            snap.contacts.filterNot { it.verified }.map { it.cert }

    private fun result(text: String, signature: SignatureStatus, snap: Snapshot, codeFpr: String?): DecryptResult {
        val signer = when (signature) {
            is SignatureStatus.Valid -> signature.fingerprint
            is SignatureStatus.Rejected -> signature.fingerprint
            else -> null
        }
        val mine = snap.myKeys.firstOrNull { it.info.fingerprint == signer }
        val contact = snap.contacts.firstOrNull { it.info.fingerprint == signer }
        return DecryptResult(
            text = text,
            signature = signature,
            signerName = mine?.info?.userId ?: contact?.info?.userId,
            signerVerified = signature is SignatureStatus.Valid && (mine != null || contact?.verified == true),
            secretCodeWith = codeFpr?.let { fpr -> snap.contacts.firstOrNull { it.info.fingerprint == fpr }?.info?.userId },
        )
    }

    /**
     * true se a mensagem foi encriptada para uma das tuas chaves (ou para um destinatário oculto).
     * Aceita mensagens normais e disfarçadas (ver [reveal]).
     */
    fun isForMe(text: String): Boolean {
        val message = normalize(text).armored
        val ids = Pgp.recipientKeyIds(message)
        val mine = snapshot().myKeys.flatMap { Pgp.keyIds(it.ring) }.toSet()
        return ids.any { it == 0L || it in mine }
    }

    /** Desencripta uma mensagem normal ou disfarçada (ver [Disguise]). */
    fun decrypt(text: String, passphrase: CharArray): DecryptResult {
        val revealed = normalize(text)
        val message = revealed.armored
        val snap = snapshot()
        val myKeys = snap.myKeys.map { it.ring }
        if (myKeys.isEmpty()) throw PgpError("Ainda não tens nenhuma chave privada.")
        if (!isForMe(message)) throw PgpError("Esta mensagem não foi encriptada para nenhuma das tuas chaves.")
        val d = Pgp.decrypt(message, myKeys, passphrase, trustOrder(snap))
        return result(d.text, d.signature, snap, revealed.codeFpr)
    }

    private fun load(name: String): ByteArray? {
        cache[name]?.let { return it }
        val data = store.read(name) ?: return null
        cache[name] = data
        return data
    }

    private fun save(name: String, data: ByteArray) {
        store.write(name, data)
        cache[name] = data
    }

    private fun remove(name: String) {
        cache.remove(name)
        store.delete(name)
    }

    private fun reason(e: Exception) = (e as? PgpError)?.message ?: "Ficheiro ilegível (${e.javaClass.simpleName})."

    companion object {
        private const val SEC = "sec-"
        private const val PUB = "pub-"
        private const val VERIFIED = "verified"
        private const val CODE = "code-"
        private const val NOTE = "note-"
        private const val PIN = "pin"
        private const val PANIC = "panic"
        private const val PREFS = "prefs"
        private val PREF_NAME = Regex("^[a-z][A-Za-z]*(-[0-9A-F]{40,64})?$")

        /** Nome aceite para uma preferência privada: letras, opcionalmente seguidas de "-<fingerprint>". */
        fun isPrefName(name: String) = PREF_NAME.matches(name)
        /** O que entra num backup completo (além da lista de verificados). */
        private val KINDS = listOf(SEC, PUB, CODE, NOTE)
    }
}

data class DecryptResult(
    val text: String,
    val signature: SignatureStatus,
    val signerName: String?,
    /** A assinatura é de uma chave tua ou de um destinatário que verificaste. */
    val signerVerified: Boolean,
    /** Se a mensagem vinha disfarçada com um código secreto: o contacto com quem está combinado. */
    val secretCodeWith: String? = null,
)
