package app.reczi.pgp.core

import java.text.Normalizer
import kotlin.random.Random
import kotlin.random.asKotlinRandom

/**
 * Motor dos disfarces em texto corrido (crónica, diário de viagem, relato de futebol, letra de rap).
 *
 * Um formato é um conjunto de moldes de frase com espaços, e cada espaço tem a sua lista de
 * opções, à medida daquele sítio da frase (na praça compra-se fruta, não parafusos). Cada lista
 * tem 2, 4, 8… 256 opções, por isso cada espaço guarda 1 a 8 bits. Os bits vêm dos bytes já
 * encriptados (que parecem aleatórios), e por isso as escolhas também parecem ao acaso. O molde
 * de cada frase é escolhido ao acaso e não guarda nada.
 *
 * Cada opção tem exatamente uma palavra-chave (marcada com "_" quando a opção tem mais do que uma
 * palavra, p. ex. "a _feira de Natal"). Todas as outras palavras, nos moldes e nas opções, são de
 * ligação. Para ler, ignora-se tudo menos as palavras-chave, pela ordem em que aparecem. Por isso o
 * texto sobrevive ao que as apps de mensagens fazem: tirar acentos, juntar linhas, mudar
 * maiúsculas, acrescentar pontuação. Uma palavra que não seja nem chave nem de ligação faz
 * a leitura falhar (o texto não é deste formato, ou foi alterado).
 *
 * Gramática:
 * - "{LISTA}" põe uma opção da lista; "{em:LISTA}" junta a preposição ao artigo (no, na, à, do, pelo…).
 * - "{LISTA/g}" usa a lista LISTA_f ou LISTA_m conforme o género da última opção com género
 *   (o artigo "o"/"a" no início, ou uma lista terminada em _f/_m): "a tia _Rosa … voltou cansada".
 * - "{R1:RIMA}" e "{R2:RIMA}" (com preposição opcional, "{R2:de:RIMA}"): rimas. As rimas são 16
 *   famílias de 16 palavras. R1 escolhe a família e a palavra (8 bits); R2, no mesmo molde, rima
 *   com ela: é uma das 8 palavras seguintes da mesma família (3 bits), nunca a mesma.
 *
 * Fim da mensagem: a última frase é sempre acabada; o que falta é preenchido ao acaso. Ao ler, o
 * comprimento certo é o que tem a etiqueta do [Disguise] válida, por isso [read] devolve as
 * poucas hipóteses de comprimento possíveis.
 *
 * As listas, a sua ordem e os moldes (só as palavras de ligação) são o formato: NUNCA alterar nem
 * reordenar as listas, nem acrescentar palavras de ligação que sejam chaves, ou as mensagens
 * antigas deixam de abrir. Os testes fixam-nas com um resumo SHA-256.
 */
internal class Prose(
    val name: String,
    lists: Map<String, List<String>>,
    templates: List<String>,
    rhymes: List<List<String>> = emptyList(),
    private val openings: List<String> = emptyList(),
    private val closings: List<String> = emptyList(),
    /** Frases (ou pares de barras) por parágrafo. */
    private val perParagraph: Int = 4,
    /** true: cada molde vai em linhas próprias (letra); false: frases seguidas em parágrafos. */
    private val lines: Boolean = false,
) {
    private class Item(val text: String, val key: String, val gender: Char?)
    private class Slot(val list: String, val prep: String?, val gendered: Boolean, val rhyme: Int)
    private class Entry(val bits: Int, val value: Int, val family: Int)

    private val lists: Map<String, List<Item>> = lists.mapValues { (name, raw) -> raw.map { item(it, name) } }
    private val rhymes: List<List<Item>> = rhymes.map { fam -> fam.map { item(it, "") } }

    /** Cada molde: texto fixo e espaços, alternados. */
    private val templates: List<List<Any>> = templates.map(::parse)

    /** Palavra-chave -> o que vale. */
    private val index = HashMap<String, Entry>()

    /** Palavras de ligação (não levam dados). */
    val glue: Set<String>

    /** Bits que o molde mais comprido leva; diz quantos bytes de enchimento pode haver no fim. */
    private val maxTemplateBits: Int

    /**
     * Resumo SHA-256 de tudo o que define o formato (listas, rimas, moldes, aberturas e fechos),
     * para os testes o fixarem: mudar uma palavra de ligação também pode impedir textos antigos de abrir.
     */
    val digest: String = java.security.MessageDigest.getInstance("SHA-256").digest(
        (lists.toSortedMap().map { (k, v) -> "$k=" + v.joinToString("|") } + rhymes.map { it.joinToString("|") } +
            templates + openings + closings).joinToString("\n").toByteArray(Charsets.UTF_8),
    ).joinToString("") { "%02x".format(it) }

    init {
        for ((name, items) in this.lists) {
            val bits = bitsFor(items.size, name)
            for ((v, it) in items.withIndex()) put(it.key, Entry(bits, v, -1), name)
        }
        if (this.rhymes.isNotEmpty()) {
            require(this.rhymes.size == 16 && this.rhymes.all { it.size == 16 }) { "$name: as rimas são 16 famílias de 16" }
            for ((f, fam) in this.rhymes.withIndex()) for ((w, it) in fam.withIndex()) put(it.key, Entry(8, f * 16 + w, f), "rima")
        }
        val g = HashSet<String>()
        // Sem expressões regulares com chavetas: o Android (ICU) rejeita "}" sem escape, o Java não.
        this.templates.forEach { t -> t.forEach { p -> if (p is String) g += words(p) } }
        (openings + closings).forEach { g += words(it) }
        (this.lists.values.flatten() + this.rhymes.flatten()).forEach { g += glueOf(it) }
        CONTRACTIONS.values.forEach { m -> m.values.forEach { g += words(it) } }
        g += CONTRACTIONS.keys
        g += listOf("com", "para")
        val clash = g.filter { it in index }
        require(clash.isEmpty()) { "$name: palavras que são chave e ligação ao mesmo tempo: $clash" }
        glue = g
        for ((i, t) in this.templates.withIndex()) {
            var open = false
            for (s in t.filterIsInstance<Slot>()) {
                require(s.gendered || s.rhyme > 0 || s.list in this.lists) { "$name: lista ${s.list} em falta (molde $i)" }
                if (s.gendered) require(s.list + "_f" in this.lists && s.list + "_m" in this.lists) { "$name: ${s.list}_f/_m em falta" }
                if (s.gendered) require(this.lists.getValue(s.list + "_f").size == this.lists.getValue(s.list + "_m").size) { "$name: ${s.list}_f/_m de tamanhos diferentes" }
                if (s.rhyme == 1) { require(!open) { "$name: R1 sem R2 (molde $i)" }; open = true }
                if (s.rhyme == 2) { require(open) { "$name: R2 sem R1 (molde $i)" }; open = false }
            }
            require(!open) { "$name: R1 sem R2 (molde $i)" }
        }
        maxTemplateBits = this.templates.maxOf { t -> t.filterIsInstance<Slot>().sumOf { bitsOf(it) } }
    }

    private fun put(key: String, e: Entry, list: String) {
        val old = index[key]
        // A mesma palavra em listas gémeas (_f/_m, p. ex. "feliz") vale o mesmo: não há ambiguidade.
        require(old == null || (old.bits == e.bits && old.value == e.value && old.family == e.family)) { "$name: chave repetida \"$key\" ($list)" }
        index[key] = e
    }

    private fun bitsFor(size: Int, list: String): Int {
        val bits = Integer.numberOfTrailingZeros(size)
        require(size >= 2 && size <= 256 && 1 shl bits == size) { "$name: a lista $list tem $size opções (tem de ser 2, 4, 8… 256)" }
        return bits
    }

    private fun bitsOf(s: Slot): Int = when (s.rhyme) {
        1 -> 8
        2 -> 3
        else -> bitsFor(lists.getValue(if (s.gendered) s.list + "_m" else s.list).size, s.list)
    }

    private fun item(raw: String, list: String): Item {
        val text = raw.replace("_", "")
        val marked = Regex("_(\\p{L}+)").findAll(raw).map { fold(it.groupValues[1]) }.toList()
        val ws = words(text)
        val key = when {
            marked.size == 1 -> marked[0]
            marked.isEmpty() && ws.size == 1 -> ws[0]
            marked.isEmpty() && ws.size == 2 && ws[0] in ARTICLES -> ws[1]
            else -> throw IllegalArgumentException("$name: opção \"$raw\" sem uma palavra-chave clara")
        }
        val first = ws.firstOrNull()
        val gender = when {
            list.endsWith("_f") -> 'f'
            list.endsWith("_m") -> 'm'
            first == "o" || first == "os" || first == "um" -> 'm'
            first == "a" || first == "as" || first == "uma" -> 'f'
            else -> null
        }
        return Item(text, key, gender)
    }

    private fun glueOf(it: Item): List<String> {
        val ws = words(it.text).toMutableList()
        ws.remove(it.key)
        return ws
    }

    private fun parse(t: String): List<Any> {
        val out = ArrayList<Any>()
        var i = 0
        while (i < t.length) {
            val a = t.indexOf('{', i)
            if (a < 0) { out += t.substring(i); break }
            if (a > i) out += t.substring(i, a)
            val b = t.indexOf('}', a)
            require(b > a) { "$name: molde mal fechado: $t" }
            out += slot(t.substring(a + 1, b))
            i = b + 1
        }
        return out
    }

    private fun slot(spec: String): Slot {
        val parts = spec.split(":")
        var i = 0
        val rhyme = when (parts[0]) { "R1" -> 1; "R2" -> 2; else -> 0 }
        if (rhyme > 0) i++
        val prep = if (parts.size - i == 2) parts[i++] else null
        require(prep == null || prep in CONTRACTIONS || prep == "com" || prep == "para") { "$name: preposição desconhecida \"$prep\"" }
        val l = parts[i]
        return Slot(l.removeSuffix("/g"), prep, l.endsWith("/g"), rhyme)
    }

    // ---------------------------------------------------------------------------------- escrever

    fun write(raw: ByteArray, random: Random = SECURE): String {
        val bits = Bits(raw)
        val pieces = ArrayList<String>()
        var last = -1
        while (bits.left > 0) {
            var t = random.nextInt(templates.size)
            if (t == last && templates.size > 1) t = (t + 1) % templates.size
            last = t
            pieces += render(templates[t], bits, random)
        }
        val out = StringBuilder()
        if (openings.isNotEmpty()) out.append(openings[random.nextInt(openings.size)]).append("\n\n")
        var inPar = 0
        var target = paragraphSize(random)
        for ((i, p) in pieces.withIndex()) {
            out.append(p)
            inPar++
            if (i == pieces.lastIndex) break
            if (inPar >= target) {
                out.append("\n\n")
                inPar = 0
                target = paragraphSize(random)
            } else {
                out.append(if (lines) "\n" else " ")
            }
        }
        if (closings.isNotEmpty()) out.append("\n\n").append(closings[random.nextInt(closings.size)])
        return out.toString()
    }

    private fun paragraphSize(random: Random) = if (lines) perParagraph else (perParagraph - 1 + random.nextInt(3)).coerceAtLeast(1)

    private fun render(t: List<Any>, bits: Bits, random: Random): String {
        val sb = StringBuilder()
        var gender: Char? = null
        var family = -1
        var word = -1
        for (p in t) {
            if (p is String) { sb.append(p); continue }
            val s = p as Slot
            val item = when (s.rhyme) {
                1 -> bits.take(8, random).let { v -> family = v shr 4; word = v and 15; rhymes[family][word] }
                2 -> { word = (word + 1 + bits.take(3, random)) % 16; rhymes[family][word] }
                else -> {
                    val list = lists.getValue(if (s.gendered) s.list + "_" + (gender ?: 'm') else s.list)
                    list[bits.take(Integer.numberOfTrailingZeros(list.size), random)]
                }
            }
            item.gender?.let { gender = it }
            sb.append(withPrep(s.prep, item.text))
        }
        return capitalize(sb.toString())
    }

    private fun withPrep(prep: String?, text: String): String {
        if (prep == null) return text
        val sp = text.indexOf(' ')
        val merged = if (sp > 0) CONTRACTIONS[prep]?.get(text.substring(0, sp)) else null
        return if (merged != null) merged + text.substring(sp) else "$prep $text"
    }

    /** Maiúscula no início de cada frase e de cada linha. */
    private fun capitalize(s: String): String {
        val c = s.toCharArray()
        var start = true
        for (i in c.indices) {
            if (start && c[i].isLetter()) { c[i] = c[i].uppercaseChar(); start = false }
            if (c[i] == '\n' || ((c[i] == '.' || c[i] == '!' || c[i] == '?') && i + 1 < c.size && c[i + 1] == ' ')) start = true
        }
        return String(c)
    }

    // ------------------------------------------------------------------------------------- ler

    /**
     * Os bytes escondidos em [text], em todas as hipóteses de comprimento (da mais comprida para a
     * mais curta), ou null se o texto não for deste formato.
     */
    fun read(text: String): List<ByteArray>? {
        val tokens = words(text)
        if (tokens.isEmpty()) return null
        val out = BitWriter()
        var family = -1
        var word = -1
        var keys = 0
        for (t in tokens) {
            val e = index[t]
            if (e == null) {
                if (t in glue) continue
                return null
            }
            keys++
            when {
                e.family < 0 -> out.write(e.value, e.bits)
                family < 0 -> { family = e.family; word = e.value and 15; out.write(e.value, 8) }
                else -> {
                    if (e.family != family) return null
                    val v = ((e.value and 15) - word - 1 + 32) % 16
                    if (v >= 8) return null
                    out.write(v, 3)
                    family = -1
                }
            }
        }
        if (keys == 0 || family >= 0) return null
        val full = out.size / 8
        val shortest = maxOf(1, (out.size - maxTemplateBits) / 8)
        return (full downTo shortest).map { out.bytes(it) }
    }

    /** Quantas frases (ou barras) um texto deste formato tem, para mostrar o tamanho. */
    fun units(text: String): Int =
        if (lines) text.lines().count { l -> words(l).any { it in index } }
        else Regex("[.!?](\\s|$)").findAll(text).count()

    private class Bits(private val data: ByteArray) {
        private var pos = 0
        val left get() = data.size * 8 - pos

        /** [n] bits; no fim dos dados, o que falta é ao acaso. */
        fun take(n: Int, random: Random): Int {
            var v = 0
            for (k in 0 until n) {
                val bit = if (pos < data.size * 8) (data[pos / 8].toInt() shr (7 - pos % 8)) and 1 else random.nextInt(2)
                if (pos < data.size * 8) pos++
                v = (v shl 1) or bit
            }
            return v
        }
    }

    private class BitWriter {
        private val bits = java.util.BitSet()
        var size = 0
            private set

        fun write(v: Int, n: Int) {
            for (k in n - 1 downTo 0) {
                if ((v shr k) and 1 == 1) bits.set(size)
                size++
            }
        }

        fun bytes(n: Int): ByteArray = ByteArray(n) { i ->
            var b = 0
            for (k in 0 until 8) b = (b shl 1) or (if (bits.get(i * 8 + k)) 1 else 0)
            b.toByte()
        }
    }

    companion object {
        /**
         * As escolhas que não levam dados (molde, parágrafos, abertura, enchimento do fim) também
         * vêm de um gerador criptográfico: não revelam nada, mas assim não há nenhum gerador fraco
         * na app. Os testes passam um gerador com semente, para serem repetíveis.
         */
        val SECURE: Random = java.security.SecureRandom().asKotlinRandom()

        private val ARTICLES = setOf("o", "a", "os", "as", "um", "uma")

        private val CONTRACTIONS = mapOf(
            "a" to mapOf("o" to "ao", "a" to "à", "os" to "aos", "as" to "às"),
            "de" to mapOf("o" to "do", "a" to "da", "os" to "dos", "as" to "das"),
            "em" to mapOf("o" to "no", "a" to "na", "os" to "nos", "as" to "nas", "um" to "num", "uma" to "numa"),
            "por" to mapOf("o" to "pelo", "a" to "pela", "os" to "pelos", "as" to "pelas"),
        )

        fun fold(word: String): String =
            Normalizer.normalize(word.lowercase(), Normalizer.Form.NFD).filter { Character.getType(it) != Character.NON_SPACING_MARK.toInt() }

        /** As palavras de um texto, sem acentos nem maiúsculas; tudo o que não é letra separa. */
        fun words(text: String): List<String> = fold(text).split(Regex("[^a-z]+")).filter { it.isNotEmpty() }
    }
}
