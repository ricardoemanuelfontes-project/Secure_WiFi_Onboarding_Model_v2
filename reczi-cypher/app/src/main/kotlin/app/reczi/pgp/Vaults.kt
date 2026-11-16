package app.reczi.pgp

import android.content.Context
import app.reczi.pgp.core.Vault
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/**
 * Um único cofre e uma única fila de trabalho para todo o processo: se a atividade for recriada
 * a meio de uma operação, a nova vê o que a anterior escreveu (mesma cache, mesma fila).
 */
object Vaults {
    private var store: KeystoreStore? = null
    private var vault: Vault? = null
    val worker: ExecutorService = Executors.newSingleThreadExecutor()

    @Synchronized
    fun store(context: Context): KeystoreStore =
        store ?: KeystoreStore(context.applicationContext).also { store = it }

    @Synchronized
    fun vault(context: Context): Vault = vault ?: Vault(store(context)).also { vault = it }

    /** Testes: um cofre novo, com uma chave AES comum em vez da do Keystore. */
    @Synchronized
    internal fun useForTests(context: Context, key: javax.crypto.SecretKey) {
        store = KeystoreStore(context.applicationContext, key)
        vault = Vault(store!!)
    }
}
