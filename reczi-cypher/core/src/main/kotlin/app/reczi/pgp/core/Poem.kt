package app.reczi.pgp.core

import java.text.Normalizer

/**
 * Disfarce em forma de poema: os bytes viram versos em português.
 *
 * Há três listas de 256 palavras (substantivos masculinos, adjetivos no masculino e verbos na
 * 3.ª pessoa), sem palavras repetidas entre elas. Cada byte é escrito com a palavra da lista que o
 * molde do verso pede naquele sítio ("O [subst.] [adj.] [verbo]"), e por isso os versos concordam
 * em género e têm ar de frase. As palavras de ligação (o, um, sem, como...) não levam dados.
 *
 * Para ler, ignora-se tudo o que não é palavra das listas: maiúsculas, acentos, pontuação, quebras
 * de linha e palavras de ligação. Cada palavra das listas vale um byte, seja qual for o molde.
 *
 * As listas e a sua ordem são o formato: NUNCA alterar nem reordenar (as mensagens antigas
 * deixariam de abrir). Um verso leva 3 a 5 bytes, por isso uma mensagem curta dá um poema longo.
 */
internal object Poem {
    val NOUNS: List<String> = """
        rio mar sol céu vento fogo campo monte vale lago bosque jardim
        caminho barco navio porto farol sonho medo desejo segredo silêncio tempo dia
        mês ano século instante momento destino acaso mundo país reino povo irmão
        pai filho avô amigo viajante pastor pescador poeta pintor músico mestre rei
        príncipe soldado marinheiro lobo cão gato cavalo pássaro corvo melro cisne peixe
        touro cordeiro leão tigre urso veado grilo sapo rouxinol pombo falcão carvalho
        pinheiro salgueiro cedro lírio cravo jasmim trigo milho fruto ramo tronco espinho
        musgo orvalho nevoeiro trovão relâmpago raio temporal inverno verão outono abril maio
        dezembro domingo sábado crepúsculo luar horizonte deserto abismo rochedo penedo cais muro
        telhado portão quintal pátio poço moinho castelo mosteiro sino relógio espelho retrato
        livro poema verso canto fado grito sussurro riso choro suspiro beijo abraço
        olhar gesto passo rasto sinal nome rosto corpo peito coração sangue osso
        braço dedo ombro joelho cabelo lábio sorriso pranto luto perdão pecado milagre
        mistério enigma labirinto pensamento juízo engano erro acerto lucro preço ouro ferro
        cobre vidro papel linho veludo manto chapéu casaco sapato anel colar lenço
        pão vinho sal mel leite queijo café açúcar azeite fumo cheiro sabor
        calor gelo granizo lume carvão barro pó chão degrau corredor quarto leito
        berço túmulo jazigo altar templo claustro convento navegante marujo remo leme mastro
        convés casco naufrágio tesouro mapa rumo norte sul oeste nascente poente fim
        começo regresso adeus encontro acordo pacto juramento voto brinde banquete baile cortejo
        desfile combate cerco exílio degredo cárcere grilhão trono cetro brasão estandarte escudo
        punhal sabre arco tambor
    """.trim().split(Regex("\\s+"))

    val ADJECTIVES: List<String> = """
        calmo frio quente azul verde branco negro dourado cinzento pálido escuro claro
        triste alegre feliz sereno bravo manso lento veloz antigo novo velho jovem
        eterno breve longo curto alto baixo fundo raso largo estreito doce amargo
        salgado ácido suave áspero macio duro mole leve pesado fraco forte frágil
        firme sólido vazio cheio perdido achado esquecido lembrado amado odiado temido querido
        solitário distante próximo vizinho estranho secreto oculto nu vestido cansado desperto adormecido
        vivo morto ferido curado livre preso mudo surdo cego louco sábio tolo
        prudente ousado tímido altivo humilde nobre vil pobre rico avaro generoso fiel
        traidor leal falso verdadeiro puro impuro limpo sujo sagrado profano bendito maldito
        santo divino humano mortal imortal terreno celeste marinho silvestre bravio agreste rude
        gentil cortês amável cruel piedoso severo brando rígido torto direito redondo quadrado
        agudo rombo fino grosso magro gordo esguio robusto gigante pequeno imenso mínimo
        vasto infinito profundo sombrio luminoso radiante brilhante baço turvo límpido cristalino húmido
        seco molhado árido fértil estéril maduro tenro podre fresco morno gelado ardente
        fumegante sonoro silencioso quieto inquieto agitado tranquilo sossegado aflito ansioso contente saudoso
        magoado zangado furioso risonho choroso sonhador errante vagabundo peregrino fugitivo exilado regressado
        tardio precoce súbito repentino demorado apressado derradeiro primeiro último único raro comum
        vulgar singular simples complexo subtil óbvio incerto certo duvidoso seguro perigoso audaz
        cobarde valente destemido medroso orgulhoso vaidoso modesto discreto sincero fingido astuto ingénuo
        inocente culpado justo injusto honesto prateado rubro roxo rosado amarelo castanho ruivo
        loiro moreno grisalho encarnado anil escarlate carmesim nevado enevoado nublado ensolarado chuvoso
        ventoso tempestuoso outonal invernal
    """.trim().split(Regex("\\s+"))

    val VERBS: List<String> = """
        dorme canta chora ri sonha espera parte chega volta foge corre anda
        voa nada cai sobe desce arde brilha treme geme grita cala fala
        escuta olha vê sente pensa lembra esquece ama odeia teme deseja procura
        encontra perde ganha guarda esconde revela mostra abre fecha rompe quebra nasce
        morre vive cresce murcha floresce amadurece envelhece desperta adormece acorda descansa trabalha
        luta vence resiste cede desiste insiste persiste hesita duvida acredita confia promete
        jura mente engana trai perdoa castiga salva condena liberta prende solta amarra
        desata tece borda costura pinta desenha escreve lê apaga risca grava rasga
        dobra estende recolhe semeia colhe planta rega ceifa lavra cava enterra desenterra
        constrói destrói ergue derruba levanta baixa empurra puxa arrasta carrega leva traz
        entrega recebe oferece pede tira rouba devolve empresta paga vende compra troca
        conta mede pesa divide soma junta separa une afasta aproxima abraça beija
        acena sorri suspira respira sopra bebe come prova cheira toca fere cura
        mata ressuscita reza pragueja bendiz maldiz chama responde pergunta murmura sussurra clama
        brada uiva ladra ruge mia pia zumbe estala ressoa ecoa vibra oscila
        balança gira roda rola desliza escorre goteja jorra transborda inunda seca molha
        queima gela derrete ferve fumega apodrece renasce regressa embarca navega naufraga flutua
        afunda mergulha emerge atravessa percorre vagueia erra tropeça salta dança marcha fica
        passa cruza segue persegue alcança escapa some aparece desaparece surge irrompe desaba
        desmorona vacila cintila reluz resplandece escurece clareia amanhece anoitece entardece chove neva
        troveja relampeja venta caminha viaja demora tarda aguarda vigia observa contempla admira
        estranha recorda imagina inventa
    """.trim().split(Regex("\\s+"))

    /** Palavras de ligação: não levam dados e são ignoradas ao ler. */
    val FILLERS = setOf("o", "um", "e", "no", "sem", "como", "meu", "teu", "sob", "que", "onde", "do", "com", "este", "nem", "ao", "pelo", "num", "mas", "quando", "sobre")

    /** Moldes de verso: N = substantivo, A = adjetivo, V = verbo; o resto são palavras de ligação. */
    private val TEMPLATES = listOf(
        "o N A V", "V o N A sob o N", "um N V sem N", "e o N A V no N A", "meu N V como um N A",
        "onde o N V, o N V", "no N A o N V", "que N A V ao N", "nem o N nem o N V", "V, V o N A",
        "sobre o N A V um N", "quando o N V, V o N", "este N A V pelo N", "mas o N V com o N A",
    ).map { it.split(" ") }

    private fun fold(word: String): String =
        Normalizer.normalize(word.lowercase(), Normalizer.Form.NFD).filter { Character.getType(it) != Character.NON_SPACING_MARK.toInt() }

    private val INDEX: Map<String, Int> =
        (NOUNS + ADJECTIVES + VERBS).withIndex().associate { (i, w) -> fold(w) to (i % 256) }

    fun write(raw: ByteArray): String {
        val out = StringBuilder()
        val random = Prose.SECURE
        var i = 0
        var verse = 0
        var last = -1
        while (i < raw.size) {
            var t = random.nextInt(TEMPLATES.size)
            if (t == last) t = (t + 1) % TEMPLATES.size // nunca o mesmo molde duas vezes seguidas
            last = t
            val words = mutableListOf<String>()
            var end = 0 // até onde o verso tem dados (o que sobra do molde no fim da mensagem é cortado)
            for (token in TEMPLATES[t]) {
                val list = when (token.trimEnd(',')) { "N" -> NOUNS; "A" -> ADJECTIVES; "V" -> VERBS; else -> null }
                if (list == null) { words += token; continue }
                if (i >= raw.size) break
                words += list[raw[i++].toInt() and 0xff] + if (token.endsWith(",")) "," else ""
                end = words.size
            }
            val line = words.take(end).joinToString(" ").trimEnd(',').replaceFirstChar { it.uppercase() }
            verse++
            val done = i >= raw.size
            out.append(line).append(if (verse % 4 == 0 || done) "." else if (verse % 2 == 0) "," else "")
            if (!done) out.append(if (verse % 4 == 0) "\n\n" else "\n")
        }
        return out.toString()
    }

    /** Os bytes de um poema, ou null se [text] tiver palavras que não são das listas nem de ligação. */
    fun read(text: String): ByteArray? {
        val tokens = fold(text).split(Regex("[^a-z]+")).filter { it.isNotEmpty() && it !in FILLERS }
        if (tokens.isEmpty()) return null
        val out = ByteArray(tokens.size)
        for ((i, t) in tokens.withIndex()) out[i] = (INDEX[t] ?: return null).toByte()
        return out
    }
}
