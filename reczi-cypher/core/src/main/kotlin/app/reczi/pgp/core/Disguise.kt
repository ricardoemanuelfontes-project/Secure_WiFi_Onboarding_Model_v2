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
 * Há duas formas de escrever o resultado: "código" (Base64 URL-safe, curto) e "palavras"
 * (uma palavra portuguesa por byte: fica muito mais comprido, mas parece texto solto e não um código).
 *
 * Formato dos bytes: nonce(16) || AES-256-CTR(nonce, pgp) || etiqueta(4).
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
    fun hide(pgp: ByteArray, words: Boolean = false): String {
        val nonce = ByteArray(NONCE).also { random.nextBytes(it) }
        val body = ctr(nonce, pgp)
        val raw = nonce + body + tag(nonce, body)
        return if (words) raw.joinToString(" ") { WORDS[it.toInt() and 0xff] }
        else Base64.getUrlEncoder().withoutPadding().encodeToString(raw)
    }

    /**
     * Tira o disfarce. Devolve os bytes PGP binários, ou null se [text] não for um texto disfarçado
     * válido (p. ex. um texto normal, uma mensagem PGP normal, ou uma cópia cortada).
     */
    fun reveal(text: String): ByteArray? =
        sequenceOf(::fromCode, ::fromWords).firstNotNullOfOrNull { decode -> decode(text)?.let(::open) }

    private fun open(raw: ByteArray): ByteArray? {
        if (raw.size <= NONCE + TAG) return null
        val nonce = raw.copyOfRange(0, NONCE)
        val body = raw.copyOfRange(NONCE, raw.size - TAG)
        val tag = raw.copyOfRange(raw.size - TAG, raw.size)
        if (!MessageDigest.isEqual(tag, tag(nonce, body))) return null
        return ctr(nonce, body)
    }

    private fun fromCode(text: String): ByteArray? {
        val compact = text.filterNot { it.isWhitespace() }
        if (compact.length < 32 || compact.any { !(it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' || it == '-' || it == '_') }) return null
        return try {
            Base64.getUrlDecoder().decode(compact)
        } catch (e: IllegalArgumentException) {
            null
        }
    }

    private fun fromWords(text: String): ByteArray? {
        val tokens = text.lowercase().split(Regex("[\\s.,;:!?]+")).filter { it.isNotEmpty() }
        if (tokens.size <= NONCE + TAG) return null
        val out = ByteArray(tokens.size)
        for ((i, t) in tokens.withIndex()) out[i] = (WORD_INDEX[t] ?: return null).toByte()
        return out
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

    /** 256 palavras portuguesas simples, sem acentos: uma por cada valor de byte. */
    internal val WORDS: List<String> = """
        casa mesa porta janela rua ponte rio mar sol lua ceu nuvem chuva vento neve fogo
        agua terra pedra areia monte vale campo flor rosa folha ramo raiz fruta figo uva pera
        limao laranja banana melao queijo leite manteiga ovo sal doce mel bolo sopa arroz massa peixe
        carne frango pato gato lobo urso rato vaca boi porco cabra burro cavalo pombo galo coelho
        sapo cobra aranha abelha mosca formiga livro papel caneta lapis carta jornal quadro foto filme musica
        piano viola flauta tambor sino voz canto festa jogo bola rede barco navio vela remo porto
        praia ilha costa farol onda mapa viagem mala comboio carro mota pneu roda motor estrada caminho
        cidade aldeia vila bairro jardim parque fonte praca torre igreja castelo museu escola aula mestre aluno
        amigo vizinho primo tio avo pai filho neto irmao colega chefe medico padeiro pastor pintor poeta
        dia noite manha tarde hora minuto semana ano ontem hoje cedo logo sempre nunca agora depois
        verde azul branco preto cinza roxo dourado claro escuro alto baixo largo curto longo novo velho
        grande pequeno gordo magro forte fraco quente frio seco limpo sujo cheio vazio certo errado calmo
        feliz triste lento veloz bonito feio rico pobre perto longe dentro fora cima fundo meio lado
        comer beber dormir andar correr saltar nadar voar ler falar ouvir olhar abrir fechar subir descer
        comprar vender pagar levar trazer mandar pedir dar ficar sair entrar voltar chegar partir esperar pensar
        dedo perna braco rosto olho nariz boca dente cabelo pele osso sangue chapeu casaco camisa sapato
    """.trim().split(Regex("\\s+"))

    private val WORD_INDEX: Map<String, Int> = WORDS.withIndex().associate { (i, w) -> w to i }
}
