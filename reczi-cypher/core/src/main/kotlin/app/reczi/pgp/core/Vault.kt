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

data class Contact(val cert: PGPPublicKeyRing, val info: KeyInfo, val verified: Boolean)

/**
 * Um ficheiro do cofre que não foi possível ler ou avaliar. Se o ficheiro se leu mas a chave não
 * pôde ser avaliada (p. ex. relógio do telemóvel errado), [readable] traz a chave para backup.
 */
data class BrokenEntry(val name: String, val isPrivateKey: Boolean, val reason: String, val readable: PGPSecretKeyRing? = null)

/** Resultado de importar chaves públicas: as novas e as recusadas (com o motivo). */
data class ImportResult(val added: List<String>, val updated: Int, val rejected: List<String>)

/** Fotografia do cofre para a interface mostrar sem voltar a ler os ficheiros. */
data class Snapshot(val myKeys: List<MyKey>, val contacts: List<Contact>, val broken: List<BrokenEntry>)

/**
 * As tuas chaves privadas e as chaves públicas dos destinatários. Só deixa encriptar
 * para destinatários cuja impressão digital confirmaste ([setVerified]).
 *
 * Um ficheiro estragado nunca impede o acesso aos outros: aparece em [Snapshot.broken].
 * Todos os métodos são sincronizados; os dados lidos ficam em memória.
 */
class Vault(private val store: Store) {
    private val cache = HashMap<String, ByteArray>()

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
                if (info.fingerprint in mine) null else Contact(cert, info, info.fingerprint in verified)
            } catch (e: Exception) {
                broken += BrokenEntry(name, false, reason(e))
                null
            }
        }
        return Snapshot(myKeys, contacts, broken)
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
    fun deleteMyKey(fingerprint: String) = remove(SEC + fingerprint)

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
        setVerified(fingerprint, false)
    }

    @Synchronized
    fun setVerified(fingerprint: String, verified: Boolean) {
        val set = try { verified().toMutableSet() } catch (e: Exception) { mutableSetOf() }
        val changed = if (verified) set.add(fingerprint) else set.remove(fingerprint)
        if (changed) save(VERIFIED, set.sorted().joinToString("\n").toByteArray())
    }

    /** Esquece o que estava em memória (depois de começar um cofre novo). */
    @Synchronized
    fun clearCache() = cache.clear()

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
     */
    fun encrypt(text: String, recipientFprs: List<String>, myFpr: String, sign: Boolean, passphrase: CharArray?): String {
        if (text.isEmpty()) throw PgpError("Escreve primeiro a mensagem.")
        if (recipientFprs.isEmpty()) throw PgpError("Escolhe pelo menos um destinatário.")
        val snap = snapshot()
        val contacts = snap.contacts.associateBy { it.info.fingerprint }
        val mine = snap.myKeys.associateBy { it.info.fingerprint }
        val me = mine[myFpr]?.ring ?: throw PgpError("Chave não encontrada.")
        val recipients = (recipientFprs + myFpr).distinct().map { fpr ->
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
        return Pgp.encrypt(text, recipients, if (sign) me else null, passphrase)
    }

    /**
     * true se a mensagem foi encriptada para uma das tuas chaves (ou para um destinatário oculto).
     * Aceita mensagens normais e disfarçadas (ver [Disguise]).
     */
    fun isForMe(text: String): Boolean {
        val message = Pgp.undisguise(text) ?: text
        val ids = Pgp.recipientKeyIds(message)
        val mine = snapshot().myKeys.flatMap { Pgp.keyIds(it.ring) }.toSet()
        return ids.any { it == 0L || it in mine }
    }

    /** Desencripta uma mensagem normal ou disfarçada (ver [Disguise]). */
    fun decrypt(text: String, passphrase: CharArray): DecryptResult {
        val message = Pgp.undisguise(text) ?: text
        val snap = snapshot()
        val myKeys = snap.myKeys.map { it.ring }
        if (myKeys.isEmpty()) throw PgpError("Ainda não tens nenhuma chave privada.")
        if (!isForMe(message)) throw PgpError("Esta mensagem não foi encriptada para nenhuma das tuas chaves.")
        // Por ordem de confiança: as tuas chaves, contactos verificados, os restantes.
        val certs = mutableListOf<PGPPublicKeyRing>()
        myKeys.forEach { certs.add(Pgp.certificateOf(it)) }
        snap.contacts.filter { it.verified }.forEach { certs.add(it.cert) }
        snap.contacts.filterNot { it.verified }.forEach { certs.add(it.cert) }
        val d = Pgp.decrypt(message, myKeys, passphrase, certs)
        val signer = when (val s = d.signature) {
            is SignatureStatus.Valid -> s.fingerprint
            is SignatureStatus.Rejected -> s.fingerprint
            else -> null
        }
        val mine = snap.myKeys.firstOrNull { it.info.fingerprint == signer }
        val contact = snap.contacts.firstOrNull { it.info.fingerprint == signer }
        return DecryptResult(
            text = d.text,
            signature = d.signature,
            signerName = mine?.info?.userId ?: contact?.info?.userId,
            signerVerified = d.signature is SignatureStatus.Valid && (mine != null || contact?.verified == true),
        )
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
    }
}

data class DecryptResult(
    val text: String,
    val signature: SignatureStatus,
    val signerName: String?,
    /** A assinatura é de uma chave tua ou de um destinatário que verificaste. */
    val signerVerified: Boolean,
)
