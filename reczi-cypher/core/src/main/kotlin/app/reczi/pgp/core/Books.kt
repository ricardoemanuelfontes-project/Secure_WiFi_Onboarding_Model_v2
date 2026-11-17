package app.reczi.pgp.core

/**
 * Os formatos de texto corrido do disfarce (ver [Prose] para as regras).
 *
 * As listas e a sua ordem são o formato: NUNCA alterar, reordenar ou apagar opções, ou as
 * mensagens antigas deixam de abrir (os testes fixam-nas com um resumo). Para melhorar um formato,
 * cria-se outro com um nome novo. As listas evitam palavras de duplo sentido (nada de pó, erva,
 * dose, carga, entrega, fronteira…) e números.
 */
internal object Books {
    private fun l(s: String): List<String> = s.split('|', '\n').map { it.trim() }.filter { it.isNotEmpty() }

    private val NAMES_F = l("""
        Rosa | Lurdes | Fernanda | Graça | Conceição | Fátima | Manuela | Teresa | Isabel | Helena | Luísa | Paula
        Carla | Sílvia | Marta | Rita | Inês | Joana | Sofia | Catarina | Beatriz | Margarida | Leonor | Mariana
        Filipa | Cristina | Sandra | Patrícia | Susana | Alice | Clara | Lúcia | Ana | Maria | Rosário | Celeste
        Glória | Natália | Emília | Olga | Irene | Ilda | Amélia | Aurora | Benedita | Carolina | Daniela | Diana
        Eduarda | Francisca | Gabriela | Joaquina | Laura | Madalena | Matilde | Mafalda | Raquel | Rute | Tânia | Vera
        Vânia | Zulmira | Adelaide | Bárbara
    """)

    private val NAMES_M = l("""
        Zé | Armando | Joaquim | Manel | Tiago | Nuno | Hugo | Bruno | Filipe | Pedro | Miguel | Duarte
        Gonçalo | Rodrigo | Afonso | Vasco | Henrique | Jorge | Luís | Carlos | Paulo | Sérgio | Vítor | Fernando
        António | Francisco | Alberto | Raul | Fausto | Óscar | Mário | Daniel | João | José | Manuel | Rui
        André | Diogo | Gil | Simão | Tomás | Martim | Lourenço | Salvador | Rafael | Gabriel | Leonardo | Renato
        Artur | Abel | Adriano | Álvaro | Amândio | Augusto | Bernardo | Custódio | Edgar | Eduardo | Fábio | Gaspar
        Horácio | Ivo | Jaime | Lucas
    """)

    private val DISHES = l("""
        _bacalhau com natas | arroz de _pato | _caldo verde | _cozido à portuguesa | _frango assado | _febras grelhadas
        _sardinhas assadas | _polvo à lagareiro | carne de _porco à alentejana | uma _francesinha | _alheira | _feijoada
        _rojões | um _bitoque | _lulas grelhadas | arroz de _marisco | _empadão | _bifanas
        _caracóis | _chanfana | _leitão | _cabrito assado | _migas | _açorda
        _carapaus fritos | _dourada grelhada | _canja | _tripas à moda do Porto | sopa de _legumes | _pataniscas
        _amêijoas | _caldeirada | _pescada cozida | _robalo grelhado | _salmão no forno | _costeletas
        _favas | _ervilhas guisadas | _esparguete à bolonhesa | _lasanha | _pizza | _hambúrgueres
        _jardineira | _rancho | _feijão com couve | arroz de _cabidela | papas de _sarrabulho | arroz de _tamboril
        _choco frito | _cataplana | _espetadas | _entrecosto | _moelas | _lombo assado
        _peru assado | uma _omelete | _cogumelos salteados | arroz _doce | _pudim | _mousse de chocolate
        _filhós | _rabanadas | _sonhos | _croquetes
    """)

    // ------------------------------------------------------------------------------- crónica

    val chronicle = Prose(
        "crónica",
        mapOf(
            "QUANDO" to l("""
                _ontem de manhã | _anteontem à tarde | no _domingo | no _sábado à noite | na _segunda | na _terça à tarde
                na _quarta | na _quinta de manhã | na _sexta à noite | _hoje cedo | de _madrugada | no _feriado
                à hora do _almoço | ao _fim da tarde | há uns _dias | ao _serão
            """),
            "ABRE" to l("_entretanto | _depois | _logo a seguir | nesse _mesmo dia"),
            "KIN" to l("""
                a tia | o tio | a prima | o primo | a vizinha | o vizinho | a avó | o padrinho
                a madrinha | o cunhado | a cunhada | o senhor | a dona | o professor | a professora | o doutor
            """),
            "NOME_f" to NAMES_F,
            "NOME_m" to NAMES_M,
            "IR" to l("_foi | deu um _salto | deu um _pulo | _correu"),
            "ONDE" to l("""
                a praça | o mercado | a padaria | o café | a farmácia | os correios | a biblioteca | o jardim
                a praia | a _junta de freguesia | o cabeleireiro | a feira | a igreja | o talho | a peixaria | a mercearia
                o quiosque | a oficina | o banco | a escola | o ginásio | a costureira | o dentista | a florista
                o sapateiro | a lavandaria | o parque | a estação | a horta | o pinhal | a capela | a pastelaria
                o supermercado | a _loja de ferragens | o _centro de saúde | a câmara | o lar | a piscina | o largo | o miradouro
                a tasca | o restaurante | a papelaria | a retrosaria | a sapataria | a livraria | o clube | a associação
                o coreto | o adro | o cais | a marina | o hospital | o cinema | o teatro | a universidade
                o museu | a ribeira | o lagar | a adega | o moinho | a fonte | o pomar | o barbeiro
            """),
            "PARA" to l("e _aproveitou para | _só para | e _lembrou-se de | e _ainda quis"),
            "FAZER" to l("""
                comprar _pão | comprar _fruta | buscar os _óculos | levar o _relógio a arranjar | aviar uma _receita | pagar a _luz
                devolver um _livro | cortar o _cabelo | tomar uma _bica | ver as _montras | comprar _flores | marcar uma _consulta
                mandar um _postal | pôr uma _carta no correio | tirar _fotocópias | experimentar uns _sapatos | comprar um _presente | provar um _vestido
                regar as _plantas | apanhar _laranjas | comprar _castanhas | buscar o _neto | comprar o _jornal | comprar _selos
                trocar uma _camisola | arranjar um _fecho | comprar _sementes | comprar _queijadas | comprar _pastéis de nata | comprar _bolachas
                levar o _cão ao veterinário | comprar _vinho | comprar _azeite | comprar _ovos | comprar _leite | encher o _depósito
                pedir um _orçamento | renovar o _cartão de cidadão | pagar as _quotas | comprar _velas | levar a _roupa a lavar | comprar _pilhas
                arranjar a _bicicleta | comprar _lâmpadas | comprar um _bolo | comprar _rebuçados | ver o _horário dos comboios | tratar do _seguro
                deixar um _recado | comprar _gelados | comprar um _chapéu | buscar as _fotografias | ver a _exposição | comprar _tecido
                levar o _carro à revisão | comprar _tinta | comprar o _passe | comprar _cebolas | comprar _batatas | apanhar o _autocarro
                comprar _botões | comprar uma _prenda | comprar _sabonete | comprar _mel
            """),
            "CLIMA" to l("""
                começou a chover a _cântaros | levantou-se um _vento frio | o _sol abriu | caiu um _nevoeiro cerrado
                estava um calor de _ananases | desabou uma _trovoada | caiu _granizo | o céu ficou _carregado
                começou a _morrinhar | fez um dia de _primavera | estava um frio de _rachar | a _chuva parou
                caiu uma _geada | a _nortada apertou | caiu uma _bátega de água | o céu _limpou
            """),
            "VOLTOU" to l("_voltou para casa | _regressou a casa | _chegou a casa | _veio para casa"),
            "ESTADO_f" to l("""
                contente | cansada | encharcada | feliz | radiante | satisfeita | de _rastos | com _fome
                a _cantarolar | a _assobiar | pensativa | bem-_disposta | constipada | com _sono | de mãos a _abanar | com a pulga atrás da _orelha
                sorridente | aliviada | orgulhosa | preocupada | animada | calada | intrigada | emocionada
                esfomeada | encantada | de _alma cheia | com _dor de cabeça | desconfiada | impaciente | nervosa | apressada
            """),
            "ESTADO_m" to l("""
                contente | cansado | encharcado | feliz | radiante | satisfeito | de _rastos | com _fome
                a _cantarolar | a _assobiar | pensativo | bem-_disposto | constipado | com _sono | de mãos a _abanar | com a pulga atrás da _orelha
                sorridente | aliviado | orgulhoso | preocupado | animado | calado | intrigado | emocionado
                esfomeado | encantado | de _alma cheia | com _dor de cabeça | desconfiado | impaciente | nervoso | apressado
            """),
            "ENCONTRO" to l("_encontrou-se com | _cruzou-se com | _esteve com | _viu"),
            "CONVERSA" to l("e ficaram à _conversa sobre | e estiveram a _falar sobre | e _discutiram | e _comentaram"),
            "ASSUNTO" to l("""
                o casamento | as _obras da rua | o batizado | as férias | os netos | as vindimas | a procissão | as eleições
                a novela | o telhado | a reforma | o _exame de condução | o concerto | a romaria | a excursão | a mudança
                a colheita | o arraial | o campeonato | o trânsito | as portagens | o baile | o aniversário | o Natal
                a Páscoa | o Carnaval | os _Santos Populares | a sardinhada | o magusto | o passeio | os preços | a quermesse
                a pesca | o torneio | a missa | o jogo | a greve | a herança | o _namorado da neta | o bebé
                o quintal | a desfolhada | o cruzeiro | a peregrinação | o crisma | a comunhão | a promoção | o _emprego novo
                o apartamento | a renda | o condomínio | a limpeza | a seca | as inundações | o mau _tempo | as notas
                o festival | a maratona | o desfile | o leilão | a corrida | o gato | a dieta | o _telemóvel novo
            """),
            "COMER" to l("ao jantar _comeram | ao jantar _houve | para o jantar _fizeram | ao jantar _provaram"),
            "COMIDA" to DISHES,
            "DIZ" to l("_jura que | _garante que | _costuma dizer que | _acha que"),
            "DITO" to l("""
                mais vale tarde do que _nunca | devagar se vai ao _longe | quem não arrisca não _petisca | o que não mata _engorda
                águas passadas não movem _moinhos | a cavalo dado não se olha o _dente | em casa de ferreiro, espeto de _pau | quem espera sempre _alcança
                cada macaco no seu _galho | não há bela sem _senão | a pressa é inimiga da _perfeição | Deus escreve direito por linhas _tortas
                quem vê caras não vê _corações | filho de peixe sabe _nadar | de pequenino se torce o _pepino | à noite todos os gatos são _pardos
                quem semeia ventos colhe _tempestades | o hábito não faz o _monge | quem tem boca vai a _Roma | grão a grão enche a galinha o _papo
                a união faz a _força | mais vale prevenir do que _remediar | diz-me com quem andas, dir-te-ei quem _és | em terra de cegos, quem tem um olho é _rei
                quem sai aos seus não _degenera | não há mal que sempre _dure | água mole em pedra dura tanto bate até que _fura | a mentira tem perna _curta
                o saber não ocupa _lugar | as aparências _iludem | não se pode agradar a _gregos e a troianos | Deus ajuda quem cedo _madruga
            """),
            "LIGOU" to l("_ligou | _telefonou | mandou uma _mensagem | _escreveu"),
            "CAUSA" to l("por _causa | a _propósito | por _conta | por _motivo"),
            "ATE" to l("até às _tantas | o _resto da noite | _horas a fio | um bom _bocado"),
        ),
        listOf(
            "{QUANDO}, {KIN} {NOME/g} {IR} {a:ONDE} {PARA} {FAZER}.",
            "{ABRE}, {KIN} {NOME/g} {ENCONTRO} {KIN} {NOME/g} {em:ONDE} {CONVERSA} {ASSUNTO}.",
            "{ABRE}, {CLIMA}, e {KIN} {NOME/g} {VOLTOU} {ESTADO/g}.",
            "{COMER} {COMIDA} e falaram {de:ASSUNTO} {ATE}.",
            "{QUANDO}, {KIN} {NOME/g} {LIGOU} {a:KIN} {NOME/g} {CAUSA} {de:ASSUNTO}.",
            "{KIN} {NOME/g} {DIZ} {DITO}.",
            "{QUANDO}, {CLIMA}.",
            "{ABRE}, {KIN} {NOME/g} passou {por:ONDE} {PARA} {FAZER}.",
            "{KIN} {NOME/g} anda {ESTADO/g} {CAUSA} {de:ASSUNTO}.",
            "{QUANDO}, {KIN} {NOME/g} fez {COMIDA} para toda a família.",
        ),
        openings = listOf(
            "Olá! Tenho imensas novidades para te contar.",
            "Então, tudo bem por aí? Por cá vai-se andando.",
            "Aqui vão as novidades desta semana.",
            "Olá, como estás? Deixa-me contar-te as novidades.",
        ),
        closings = listOf("Beijinhos e até breve!", "Um abraço grande e manda notícias.", "Por agora é tudo. Beijinhos!", "Fica bem e dá notícias."),
    )

    // ------------------------------------------------------------------------ diário de viagem

    val trip = Prose(
        "viagem",
        mapOf(
            "PARTIDA" to l("""
                logo de _manhã | _cedinho | depois do _pequeno-almoço | ao _nascer do sol | mal _acordámos | depois do _lanche
                a meio da _tarde | ao _fim do dia | no dia _seguinte | no _domingo | na _sexta | no _sábado
                com a _fresca | ainda de _noite | sem _pressa | _finalmente
            """),
            "TERRA" to l("""
                Lisboa | Braga | Coimbra | Viseu | Aveiro | Leiria | Évora | Beja | Faro | Lagos | Tavira | Silves
                Olhão | Setúbal | Sesimbra | Sintra | Cascais | Óbidos | Peniche | Alcobaça | Fátima | Santarém | Tomar | Abrantes
                Elvas | Marvão | Estremoz | Monsaraz | Mértola | Serpa | Moura | Portalegre | Bragança | Chaves | Mirandela | Mogadouro
                Amarante | Penafiel | Barcelos | Guimarães | Caminha | Valença | Melgaço | Monção | Esposende | Espinho | Ovar | Ílhavo
                Mira | Penacova | Buçaco | Luso | Anadia | Águeda | Tondela | Mangualde | Gouveia | Seia | Manteigas | Monsanto
                Penamacor | Sabugal | Almeida | Pinhel | Trancoso | Belmonte | Sortelha | Lamego | Alijó | Sabrosa | Murça | Vinhais
                Montalegre | Boticas | Vidago | Fafe | Felgueiras | Lousada | Valongo | Matosinhos | Gaia | Almada | Seixal | Palmela
                Grândola | Sines | Odemira | Aljezur | Monchique | Portimão | Albufeira | Loulé | Alcoutim | Mafra | Lourinhã | Ourém
                Constância | Coruche | Arraiolos | Borba | Redondo | Reguengos | Barrancos | Ourique | Almodôvar | Viana | Arouca | Vouzela
                Sátão | Penedono | Armamar | Tabuaço | Resende | Baião | Cinfães | Alenquer | Cadaval | Bombarral | Azambuja | Benavente
                Almeirim | Alpiarça | Chamusca | Cartaxo | Cantanhede | Vagos | Murtosa | Estarreja
            """),
            "CAMINHO" to l("""
                pela estrada _nacional | pela _costa | pelo _interior | por estradas _secundárias | pela _autoestrada | de _comboio
                de _autocarro | pela _marginal | por caminhos de _terra | pela _montanha | ao longo do _rio | por entre _pinhais
                por _estradinhas | sempre a _subir | pelo _planalto | por _atalhos
            """),
            "VER" to l("_visitámos | fomos _ver | _conhecemos | _explorámos | _descobrimos | _fotografámos | _admirámos | _espreitámos"),
            "SITIO" to l("""
                o castelo | a sé | o mosteiro | o convento | o santuário | o miradouro | a _ponte romana | o aqueduto
                a muralha | o museu | o _mercado municipal | a _praia fluvial | a cascata | o forno _comunitário | o forte | a judiaria
                o pelourinho | a _igreja matriz | o _jardim botânico | as termas | a barragem | as grutas | o palácio | o _paço dos duques
                a _torre de menagem | o açude | o parque de _merendas | a lagoa | o solar | o chafariz | a fonte | a quinta
                os socalcos | o castro | as _ruínas romanas | o _templo romano | a _calçada romana | o largo | a alameda | o cruzeiro
                o coreto | as arcadas | a estação | o _bairro histórico | a misericórdia | a biblioteca | o cineteatro | o anfiteatro
                a capela | a ermida | o passadiço | o baloiço | o moinho | a azenha | o lagar | a adega
                a _reserva natural | o lago | a levada | a _feira semanal | o pinhal | o penedo | o monte | o claustro
            """),
            "ADJ" to l("""
                de cortar a _respiração | de _postal | que vale a _pena | com muita _história | de _sonho | impressionante
                inesquecível | imponente | deslumbrante | espetacular | imperdível | de perder de _vista
                enorme | brutal | fenomenal | de _cair o queixo
            """),
            "COMIDA" to DISHES,
            "PERTO" to l("""
                junto à _ribeira | ao pé da _praça | no _centro | à saída da _vila | escondida numa _ruela | com _esplanada
                debaixo de uma _parreira | recomendada pelo _taxista
            """),
            "COMENT" to l("""
                e estava _divinal | e soube pela _vida | e ainda _repetimos | e saímos de lá a _rebolar | de comer e _chorar por mais | a preço de _amigo
                e o _dono ainda nos ofereceu café | e a _sobremesa estava ainda melhor | à moda _antiga | que nem a _avó fazia
                e o _vinho da região era ótimo | e não _sobrou nada | e _pagámos uma ninharia | _bem servido | e _lambemos os dedos | e ficámos de _barriga cheia
            """),
            "PASSEIO" to l("demos uma _volta | fomos _passear | _andámos | _deambulámos"),
            "ACAO" to l("""
                tirámos _fotografias | comprámos _recordações | provámos o _queijo | ficámos a apreciar o _poente | molhámos os _pés | comemos um _gelado
                bebemos uma _limonada | conversámos com os _locais | perdemo-nos no _labirinto de ruas | descansámos à _sombra | fizemos um _piquenique | dormimos uma _sesta
                comprámos _mel | comprámos _artesanato | vimos um _concerto de rua | assistimos a uma _procissão | ouvimos _fado | fizemos um passeio de _barco
                subimos ao _topo | aprendemos _imenso | escrevemos _postais | demos de comer aos _patos | vimos as _estrelas | jogámos às _cartas
                pedimos _indicações | comprámos _pão | provámos _ginjinha | nadámos na _piscina | fomos à _missa | falámos com um _pastor
                fomos às _compras | apanhámos _conchas
            """),
            "DORMIR" to l("""
                numa _pensão simpática | num parque de _campismo | numa casa de _turismo rural | numa _pousada | num _hostel | num hotel com _spa
                em casa de _amigos | numa _tenda | na _autocaravana | num _quarto com varanda | num _celeiro recuperado | numa _cabana
                num _palheiro | numa _residencial | num _alojamento local | ao _relento
            """),
            "VISTA" to l("""
                passámos por _vinhedos enormes | vimos _cegonhas nos postes | parámos para comprar _cerejas | atravessámos _aldeias de xisto
                demos _boleia a um peregrino | cruzámo-nos com um _rebanho | parámos numa _tasquinha de aldeia | o _carro começou a aquecer
                cantámos _músicas antigas | vimos _eólicas no alto da serra | comprámos _fruta à beira da estrada | fizemos uma _pausa para esticar as pernas
                seguimos um _trator durante quilómetros | ouvimos o _relato no rádio | perdemo-nos e tivemos de _perguntar o caminho | o _nevoeiro tapava tudo
            """),
        ),
        listOf(
            "{PARTIDA}, saímos de {TERRA} e seguimos {CAMINHO} até {TERRA}.",
            "Em {TERRA}, {VER} {SITIO}, {ADJ}.",
            "Almoçámos {COMIDA} numa tasca {PERTO}, {COMENT}.",
            "{PARTIDA}, {PASSEIO} {por:SITIO} e {ACAO}.",
            "Dormimos {DORMIR} em {TERRA}.",
            "Pelo caminho, {VISTA}.",
            "{PARTIDA}, {VER} {SITIO} de {TERRA}, {ADJ}.",
            "Em {TERRA}, {ACAO} e depois {VER} {SITIO}.",
        ),
        openings = listOf(
            "Aqui fica o diário da nossa viagem por Portugal.",
            "Prometi contar tudo, por isso aqui vai.",
            "Para não me esquecer de nada, fui escrevendo pelo caminho.",
        ),
        closings = listOf("E pronto, já estamos com saudades.", "Para o ano há mais!", "Venham as próximas férias!"),
    )

    // ------------------------------------------------------------------------ relato de futebol

    val football = Prose(
        "futebol",
        mapOf(
            "NOME" to NAMES_M,
            "APELIDO" to l("""
                Silva | Santos | Ferreira | Pereira | Oliveira | Costa | Rodrigues | Martins | Sousa | Fernandes | Gonçalves | Gomes
                Lopes | Marques | Alves | Almeida | Ribeiro | Pinto | Carvalho | Teixeira | Moreira | Correia | Mendes | Nunes
                Soares | Vieira | Monteiro | Cardoso | Rocha | Raposo | Neves | Coelho | Cruz | Cunha | Pires | Ramos
                Reis | Simões | Antunes | Matos | Fonseca | Morais | Lima | Freitas | Machado | Araújo | Barbosa | Tavares
                Batista | Barros | Brito | Campos | Castro | Faria | Figueiredo | Leite | Magalhães | Miranda | Moura | Nogueira
                Paiva | Quintela | Sampaio | Valente
            """),
            "MINUTO" to l("""
                logo a _abrir | ainda na _primeira parte | perto do _intervalo | já em tempo de _compensação | no _arranque da segunda parte | a _meio da segunda parte
                nos minutos _finais | _pouco depois | na _resposta | _instantes depois | no _lance seguinte | na _jogada seguinte
                mesmo antes do _apito | ao cair do _pano | depois de muita _insistência | num contra-ataque _rápido
            """),
            "JOGADA" to l("""
                _arranca pela esquerda | _foge pela direita | _ganha a bola no miolo | _recupera a bola | _constrói desde trás | _conduz a bola
                _dribla um adversário | _tira um defesa do caminho | _aguenta a carga | _roda sobre o defesa | _aparece entre linhas | _penetra na área
                _recebe de costas | faz uma _finta de corpo | _rompe pela ala | _progride pelo corredor central | _segura a bola | _levanta os olhos
                _acelera | _desmarca-se nas costas da defesa | _pede a bola | _rouba a bola | _interceta a saída | bate o _livre
                _lança o ataque | _vence o duelo | _aproveita o ressalto | _salta mais alto | _isola-se | _trabalha bem na esquerda
                _combina pela direita | _surge na área
            """),
            "PASSE" to l("_cruza para | _passa para | _mete para | _toca para | _atrasa para | _solta para | _serve | _descobre"),
            "FINAL" to l("""
                cabeceia à _barra | remata ao _lado | atira por _cima | remata e o guarda-redes _defende | atira à _figura do guarda-redes | remata _cruzado e marca
                faz o _golo da tarde | desvia ao _poste | remata _rasteiro e a bola sai | faz um _chapéu ao guarda-redes | tenta em _arco, sem sorte | remata ao primeiro _toque
                tenta o _pontapé de bicicleta | cai na área e o árbitro manda _jogar | é travado em _falta | fica em _fora de jogo | falha _escandalosamente | marca de _cabeça
                obriga o guarda-redes a _voar | acerta no _ferro | remata de _longe | atira _rente à trave | faz o _gosto ao pé | deixa os _adeptos de pé
                remata, mas a defesa _corta | atira para a _malha lateral | remata contra as _pernas de um defesa | tenta o _remate acrobático | assina um _golaço | obriga a uma grande _intervenção
                remata e a bola _sobe demasiado | _reclama penálti
            """),
            "FALTA" to l("_derruba | _agarra | _carrega | _trava | _empurra | _atropela | _pisa | _abalroa"),
            "CARTAO" to l("mostra _amarelo | manda _seguir | puxa do _vermelho | dá a _vantagem | fala com o _capitão | consulta o _VAR | _acalma os ânimos | nem _hesita"),
            "ELOGIO" to l("""
                está _endiabrado | está a fazer um jogo de _sonho | não para _quieto | parece ter _pulmões de aço | está em _todas | joga de olhos _fechados
                anda a pedir a _convocatória | tem o miolo no _bolso | é um autêntico _maestro | corre por _todos | está _imparável | não falha um _passe
                é o _patrão lá atrás | anda _inspirado | parece um relógio _suíço | joga com _classe
            """),
            "RESULTADO" to l("""
                os da casa vão à _frente | está tudo _empatado | os _visitantes estão a vencer | continua tudo _igual
                o _nulo mantém-se | a _reviravolta está feita | a diferença é _mínima | o jogo está _partido
            """),
            "BANCADA" to l("""
                as bancadas vêm _abaixo | o estádio _explode | ouve-se um _assobio | a claque não para de _cantar
                o público _aplaude de pé | há _lenços brancos na bancada | o _treinador não quer acreditar | o mister _gesticula
                o _banco vibra | faz-se _silêncio | a _onda percorre o estádio | há _olés na bancada
                os _suplentes aquecem | a _equipa avança no terreno | o _relvado está pesado | o _vento complica
            """),
        ),
        listOf(
            "{MINUTO}, {NOME} {APELIDO} {JOGADA} e {PASSE} {NOME} {APELIDO}, que {FINAL}!",
            "{NOME} {APELIDO} {FALTA} {NOME} {APELIDO} e o árbitro {CARTAO}.",
            "{MINUTO}, {NOME} {APELIDO} {JOGADA} e {FINAL}!",
            "Substituição: sai {NOME} {APELIDO}, entra {NOME} {APELIDO}.",
            "{BANCADA}, e {NOME} {APELIDO} {ELOGIO}.",
            "{MINUTO}, {RESULTADO}.",
        ),
        openings = listOf("Boa tarde e bem-vindos a mais um relato!", "Está tudo pronto para o jogo, e a bola já rola."),
        closings = listOf("E o árbitro apita para o fim do jogo!", "Acabou! Que jogo!"),
    )

    // ----------------------------------------------------------------------------- letra de rap

    private val BARS = listOf(
        "{DEUS} {em:GEN}, {DEUS} {em:FUT}, {VERBO} {R}",
        "{de:GEN} {a:GEN}, {VERBO} {R}",
        "{VERBO} {IMG} {em:FUT} e {VERBO} {R}",
        "como {DEUS} {em:IMG}, {VERBO} {R}",
        "{FUT} de {DEUS}, {IMG} de {DEUS}, {VERBO} {R}",
        "{VERBO} {IMG} e {IMG} {em:R}",
        "{GEN} {em:IMG}, {DEUS} {em:FUT}, {VERBO} {R}",
        "{IMG} {de:GEN}, {VERBO} {IMG}, {VERBO} {R}",
        "sou {DEUS} {em:GEN}, {VERBO} {R}",
        "com {IMG} na mão e {DEUS} {em:FUT}, {VERBO} {R}",
    )

    private fun bar(b: String, n: Int) = b.replace("{R}", "{R$n:RIMA}").replace("{em:R}", "{R$n:em:RIMA}")

    val lyrics = Prose(
        "letra",
        mapOf(
            "DEUS" to l("""
                Hermes | Apolo | Atena | Ares | Poseidon | Hades | Afrodite | Ártemis | Dioniso | Hefesto | Hera | Deméter
                Perséfone | Prometeu | Hércules | Aquiles | Ulisses | Orfeu | Medusa | Ícaro | Pégaso | Cronos | Atlas | Pandora
                Eros | Morfeu | Hélio | Selene | Éolo | Quíron | Odin | Thor | Loki | Freya | Tyr | Balder
                Heimdall | Frigg | Fenrir | Zeus | Rá | Osíris | Ísis | Hórus | Anúbis | Seth | Thot | Bastet
                Amon | Hathor | Júpiter | Marte | Vénus | Mercúrio | Neptuno | Minerva | Baco | Cupido | Jano | Saturno
                Adamastor | Endovélico | Marduk | Ishtar
            """),
            "FUT" to l("""
                o golo | a baliza | o penálti | o livre | o canto | o remate | o cabeceamento | o relvado
                o balneário | o apito | o cartão | a finta | o drible | o passe | a assistência | a bancada
                a claque | o estádio | o dérbi | a taça | o mister | o capitão | a braçadeira | o golaço
                a trivela | a rabona | o calcanhar | o miolo | o prolongamento | a barreira | o poste | a trave
            """),
            "GEN" to l("""
                o rap | o trap | o drill | o boom _bap | o grime | o fado | o kuduro | a kizomba
                o semba | o funaná | a morna | o afrobeat | o reggae | o dancehall | o soul | o funk
                o jazz | o blues | o samba | o rock | o punk | o techno | o house | o zouk
                o gospel | a salsa | o tango | o flamenco | o amapiano | o freestyle | o beatbox | o vinil
            """),
            "IMG" to l("""
                a coroa | o trono | o escudo | a fénix | o lobo | o corvo | a águia | o tigre
                a pantera | o falcão | o oráculo | o labirinto | o Olimpo | o Valhala | o Nilo | a pirâmide
                a esfinge | o relâmpago | a tormenta | o eclipse | o cometa | a lua | o sol | o mármore
                o ouro | o bronze | a bigorna | a forja | a âncora | o farol | o deserto | a selva
                o asfalto | o betão | o bairro | a esquina | o microfone | o caderno | a caneta | o palco
                o holofote | a sombra | a luz | o fogo | a cinza | a brasa | o diamante | a pérola
                o espelho | a máscara | a chave | o mapa | a bússola | o horizonte | a montanha | a ponte
                o comboio | a muralha | a ampulheta | o pergaminho | o enigma | o néctar | o tridente | a lira
            """),
            "VERBO" to l("""
                rimo | risco | rasgo | carrego | acendo | levanto | ergo | solto
                escrevo | desenho | construo | conquisto | atravesso | desafio | invoco | chamo
                guardo | sigo | celebro | piso | quebro | mudo | toco | desperto
                abraço | sonho | domino | acordo | grito | trago | levo | liberto
            """),
        ),
        BARS.flatMapIndexed { i, a -> BARS.filterIndexed { j, _ -> j != i }.map { b -> bar(a, 1) + "\n" + bar(b, 2) } },
        rhymes = listOf(
            "o trovão | o refrão | a canção | o dragão | o leão | o coração | a missão | a visão | o vulcão | o furacão | a nação | o chão | a ilusão | a razão | o campeão | a paixão",
            "as multidões | as emoções | as lições | as orações | as estações | as gerações | as tradições | as revoluções | as constelações | os pulmões | os portões | os sermões | as canções | os trovões | os corações | os dragões",
            "a verdade | a cidade | a saudade | a vontade | a liberdade | a eternidade | a idade | a metade | a tempestade | a lealdade | a humildade | a realidade | a amizade | a felicidade | a claridade | a majestade",
            "a vida | a batida | a partida | a saída | a subida | a corrida | a avenida | a medida | a despedida | a guarida | a investida | a descida | a ermida | a margarida | a ferida | a lida",
            "a gente | a mente | a frente | a semente | a serpente | a corrente | o presente | o continente | o poente | o nascente | o ambiente | o oriente | o ocidente | o expoente | o crente | o valente",
            "a poesia | a magia | a melodia | a harmonia | a energia | a sabedoria | o dia | a alegria | a sinfonia | a mitologia | a filosofia | a fantasia | a ousadia | a maresia | a utopia | a epifania",
            "o amor | a dor | a flor | a cor | o valor | o rumor | o tambor | o suor | o motor | o clamor | o fervor | o esplendor | o calor | o sabor | o ardor | o vapor",
            "a estrada | a jornada | a madrugada | a alvorada | a balada | a escalada | a morada | a fada | a chegada | a entrada | a largada | a pegada | a armada | a cavalgada | a toada | a noitada",
            "o mar | o luar | o lugar | o altar | o olhar | o lar | o pilar | o azar | o paladar | o pomar | o solar | o tear | o limiar | o manjar | o lagar | o despertar",
            "a altura | a loucura | a cultura | a aventura | a armadura | a escultura | a postura | a ternura | a censura | a fartura | a leitura | a partitura | a abertura | a moldura | a criatura | a mistura",
            "o momento | o vento | o talento | o tormento | o firmamento | o pensamento | o sentimento | o movimento | o fundamento | o testamento | o lamento | o alimento | o instrumento | o argumento | o juramento | o elemento",
            "o final | o sinal | o ritual | o cristal | o portal | o metal | o temporal | o canal | o vendaval | o vitral | o ideal | o sal | o carnaval | o astral | o festival | o coral",
            "o abismo | o sismo | o misticismo | o heroísmo | o otimismo | o realismo | o lirismo | o magnetismo | o simbolismo | o paganismo | o batismo | o egoísmo | o cinismo | o altruísmo | o idealismo | o romantismo",
            "o castelo | o martelo | o duelo | o apelo | o elo | o novelo | o selo | o cabelo | o modelo | o flagelo | o paralelo | o belo | o atropelo | o gelo | o zelo | o pesadelo",
            "a esperança | a dança | a lembrança | a herança | a balança | a aliança | a criança | a confiança | a mudança | a trança | a bonança | a festança | a andança | a temperança | a liderança | a segurança",
            "a estrela | a janela | a vela | a novela | a tela | a donzela | a sentinela | a aquarela | a capela | a cidadela | a caravela | a gazela | a viela | a procela | a Cinderela | a parcela",
        ).map(::l),
        openings = listOf("Yeah… mais uma, beat a rolar.", "Isto é para quem percebe."),
        closings = listOf("Paz.", "É isto. Até à próxima."),
        perParagraph = 4,
        lines = true,
    )

    /** Todos, pela ordem em que se tenta ler. */
    val all: List<Prose> get() = listOf(chronicle, trip, football, lyrics)
}
