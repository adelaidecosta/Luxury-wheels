# Importa as ferramentas necessárias para a aplicação:
# - Flask: cria a aplicação web.
# - render_template: apresenta páginas HTML com os dados enviados pelo Python.
# - request: permite consultar os dados recebidos nos pedidos e formulários.
# - redirect e url_for: encaminham o utilizador para outra rota.
# - session: guarda dados entre pedidos, como o identificador do cliente.
# - flash: prepara mensagens de sucesso ou erro para mostrar nas páginas.
# - abort: interrompe um pedido com um erro HTTP, como o erro 404.
# - SQLAlchemy: permite trabalhar com a base de dados através de classes Python.
# - os: permite trabalhar com caminhos e variáveis de ambiente.
# - date, datetime e timedelta: permitem trabalhar com datas e intervalos de tempo.
# - generate_password_hash e check_password_hash: permitem guardar e verificar
#   palavras-passe sem as guardar em texto simples.
# - validate_email e EmailNotValidError: permitem validar o formato dos emails.
# - IntegrityError: permite tratar erros de integridade da base de dados.
# - CSRFProtect: ajuda a proteger os formulários contra pedidos forjados.
from flask import Flask, render_template, request, redirect, url_for, session, flash,abort
from flask_sqlalchemy import SQLAlchemy
import os
from datetime import date, datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from email_validator import validate_email, EmailNotValidError
from sqlalchemy.exc import IntegrityError
from flask_wtf.csrf import CSRFProtect

# Define a taxa de IVA utilizada no cálculo do valor das reservas.
TAXA_IVA= 0.23   # 23% de IVA


# Cria a pasta database caso ainda não exista.
# exist_ok=True evita um erro se a pasta já estiver criada.
os.makedirs(os.path.join(os.path.dirname(__file__), 'database'), exist_ok=True)

# Obtém o caminho absoluto da pasta onde se encontra este ficheiro.
# Depois, constrói o caminho para a base de dados luxurywheels.db.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'database', 'luxurywheels.db')

# Cria a aplicação Flask e configura a ligação à base de dados SQLite.
#
# A SECRET_KEY é obtida a partir de uma variável de ambiente.
# É utilizada para assinar os dados da sessão e na proteção CSRF.
# A assinatura permite detetar alterações não autorizadas nos dados da sessão;
# não serve para esconder ou encriptar esses dados.
# Se a variável SECRET_KEY não estiver definida, a aplicação não arranca.
#
# SQLALCHEMY_DATABASE_URI indica onde está a base de dados.
# SQLALCHEMY_TRACK_MODIFICATIONS=False desativa um mecanismo adicional
# de acompanhamento de alterações que esta aplicação não utiliza.
# SQLAlchemy(app) associa a gestão da base de dados à aplicação.
app= Flask(__name__)    #Em app encontra se o nosso servidor web de Flask
app.secret_key= os.environ["SECRET_KEY"]
app.config["debug"] = True
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_PATH}'
app.config[ 'SQLALCHEMY_TRACK_MODIFICATIONS' ] = False
db= SQLAlchemy(app)

# Desativa a verificação automática global de CSRF.
# Neste projeto, a proteção é chamada explicitamente na função
# proteger_formularios_autenticacao, para as rotas aí indicadas.
# Os formulários POST dessas rotas devem enviar um token CSRF válido.
app.config["WTF_CSRF_CHECK_DEFAULT"] = False
csrf = CSRFProtect(app)

# Executa esta função antes de cada pedido, antes da função da rota.
#
# 1. Identifica se o pedido se destina a uma rota de reservas.
# 2. Obtém o identificador do cliente guardado na sessão.
# 3. Confirma que é um número inteiro e que o cliente existe na base de dados.
# 4. Se não existir um cliente válido, limpa a sessão e encaminha para o login.
# 5. Nas rotas de reservas, registo e login, chama a proteção CSRF.
#
# csrf.protect() verifica o token nos métodos protegidos, como POST;
# por defeito, não exige um token para pedidos GET.
# O token ajuda a impedir que outro site envie pedidos em nome do utilizador.
@app.before_request
def proteger_formularios_autenticacao():
    rotas_reservas = {
        "efetuar_aluguer",
        "pagamento",
        "lista_reservas",
        "alteracao_reserva",
        "anular_reserva",
        "reserva_realizada",
        "minhas_reservas",
    }

    # Primeiro, verificar a autenticação nas rotas de reservas.
    if request.endpoint in rotas_reservas:
        id_cliente = session.get("id_cliente")

        cliente = None
        if isinstance(id_cliente, int):
            cliente = db.session.get(Cliente, id_cliente)

        if cliente is None:
            session.clear()
            flash("Tens de iniciar sessão para efetuar um aluguer.", "erro")
            return redirect(url_for("login"))

    # Depois, validar o token dos pedidos que alteram dados.
    if request.endpoint in rotas_reservas | {"register", "login"}:
        csrf.protect()

#===== Rotas do Website=====
# Associa o endereço "/" à página inicial.
# Um pedido GET devolve o template index.html.
@app.route('/', methods=['GET'])
def home():
    return render_template("index.html")


# Permite apresentar o formulário de registo e criar uma conta.
#
# GET: apresenta o formulário.
# POST: recebe os dados introduzidos e executa as seguintes validações:
# - Verifica se todos os campos obrigatórios foram preenchidos.
# - Junta o nome e o apelido e verifica o tamanho do nome completo.
# - Valida e normaliza o email, sem verificar se a caixa de correio existe.
# - Confirma que as palavras-passe coincidem e têm o tamanho permitido.
# - Procura uma conta que já utilize o mesmo email.
#
# Se os dados forem válidos, cria um cliente com o hash da palavra-passe.
# add() prepara a inserção e commit() guarda a alteração na base de dados.
# Se ocorrer um erro de integridade, rollback() desfaz a transação.
# Após o registo, encaminha o utilizador para a página de login.
# As respostas com código 400 indicam dados inválidos no pedido.
@app.route("/register", methods=['GET', 'POST'])
def register():
    #GET mostra o formulário
    if request.method == "GET":
        return render_template("register.html")

    #POST-recebe os dados enviados pelo formulário

    nome= request.form.get("nome", "").strip()
    apelido= request.form.get("apelido","").strip()
    email_recebido= request.form.get("email","").strip()

    # Não retiramos espaços nem alteramos as palavras-passe.
    password= request.form.get("password", "")
    confirmar_password= request.form.get("confirmar_password", "")

    # 1. Verificar campos obrigatórios.
    if not all([nome, apelido, email_recebido, password, confirmar_password]):
        flash("Preenche todos os campos.", "erro")
        return render_template("register.html"), 400

    # 2. Construir o nome completo.
    nome_completo=f"{nome} {apelido}"

    if len(nome_completo) > 100:
        flash("O nome completo não pode ultrapassar 100 caracteres.", "erro")
        return render_template("register.html"), 400

    # 3. Validar o formato e normalizar o email.
    try:
        email = validate_email(
            email_recebido,
            check_deliverability=False
        ).normalized.lower()
    except EmailNotValidError:
        flash("Introduz um endereço de email válido.", "erro")
        return render_template("register.html"), 400

    if len(email) > 100:
        flash("O email não pode ultrapassar 100 caracteres.", "erro")
        return render_template("register.html"), 400

    # 4. Comparar as palavras-passe.
    if password != confirmar_password:
        flash("As palavras-passe não coincidem.", "erro")
        return render_template("register.html"), 400

    if not 9 <= len(password) <= 128:
        flash("A palavra-passe deve ter entre 9 e 128 caracteres.", "erro")
        return render_template("register.html"), 400

    # 5. Verificar se o email já está registado.
    cliente_existente = Cliente.query.filter(
        db.func.lower(db.func.trim(Cliente.email)) == email
    ).first()

    if cliente_existente:
        flash("Já existe uma conta com este email.", "erro")
        return render_template("register.html"), 400

    # 6. Criar o cliente, guardando apenas o hash da palavra-passe.
    novo_cliente = Cliente(
            nome=nome_completo,
            email=email,
            password_hash=generate_password_hash(password)
    )

    db.session.add(novo_cliente)

    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        flash(
            "Não foi possível criar a conta. Verifica se o email já está registado.",
            "erro"
            )
        return render_template("register.html"), 400

        # 7. Após guardar, encaminhar para o login.
    flash("Conta criada com sucesso! Já podes iniciar sessão.", "sucesso")
    return redirect(url_for("login"))


# Permite autenticar um cliente já registado.
#
# GET: apresenta o formulário de login.
# POST: recebe o email e a palavra-passe.
#
# Valida o email, procura o cliente e compara a palavra-passe introduzida
# com o hash guardado na base de dados.
# Usa uma mensagem de erro genérica para não revelar se a conta existe.
#
# Quando as credenciais estão corretas, limpa os dados da sessão anterior
# e guarda o identificador do cliente em session["id_cliente"].
# Este identificador será usado para reconhecer o cliente nos pedidos seguintes.
# Por fim, encaminha o cliente para a página inicial.

@app.route("/login", methods=["GET", "POST"])
def login():
        # GET: mostra o formulário.
        if request.method == "GET":
            return render_template("login.html")

        # POST: recebe as credenciais.
        if request.method == "POST":
            email_recebido = request.form.get("email", "").strip()
            password = request.form.get("password", "")

        mensagem_erro = "Email ou palavra-passe incorretos."

        # Validar os dados sem revelar se a conta existe.
        if not email_recebido or not password or len(password) > 128:
            flash(mensagem_erro, "erro")
            return render_template("login.html"), 400

        try:
            email = validate_email(
                email_recebido,
                check_deliverability=False
            ).normalized.lower()
        except EmailNotValidError:
            flash(mensagem_erro, "erro")
            return render_template("login.html"), 400

        if len(email) > 100:
            flash(mensagem_erro, "erro")
            return render_template("login.html"), 400

        # Procurar a conta.
        cliente = Cliente.query.filter(
            db.func.lower(db.func.trim(Cliente.email)) == email
        ).first()

        # Verificar o hash guardado.
        if (
                cliente is None
                or not cliente.password_hash
                or not check_password_hash(cliente.password_hash, password)
        ):
            flash(mensagem_erro, "erro")
            return render_template("login.html"), 400

        # Autenticação válida: eliminar o conteúdo da sessão anterior.
        session.clear()

        # Nova chave de sessão para identificar o cliente autenticado.
        session["id_cliente"] = cliente.id

        return redirect(url_for("home"))

# Guarda na sessão o identificador do cliente autenticado.
# Este valor não é uma nova SECRET_KEY nem uma palavra-passe.

# Define a estrutura dos veículos na base de dados.
# Cada objeto Veiculo corresponde a um registo da tabela.
#
# id: identificador único do veículo.
# Os restantes campos guardam os dados de identificação, imagem, preço,
# características, quilometragem e datas de revisão e legalização.
# O campo imagem guarda o nome/caminho da imagem, não o ficheiro em si.
# disponivel indica se o veículo está marcado como disponível para aluguer.
#
# primary_key=True identifica a chave primária.
# nullable=False indica que o campo não pode ter o valor NULL.
# default=True define o valor inicial quando não é indicado outro.

class Veiculo(db.Model):
    id=db.Column(db.Integer, primary_key=True)
    marca= db.Column(db.String(100), nullable=False)
    modelo= db.Column(db.String(100), nullable=False)
    ano= db.Column(db.Integer, nullable=True)
    imagem = db.Column(db.String(200), nullable=True)  # campo imagem
    preco_dia = db.Column(db.Float,  nullable=False)                     # na classe Veiculo
    tipo= db.Column(db.String(100),  nullable=False)                     # ex.: SUV, Citadino..
    lugares= db.Column(db.Integer,  nullable=False)                     # quantidade de pessoas
    ultima_revisao= db.Column(db.Date,  nullable=False)                 # data da última revisão
    proxima_revisao= db.Column(db.Date,  nullable=False)                # data da próxima revisão
    ultima_legalizacao= db.Column(db.Date,  nullable=False)             # data da última legalização
    kms= db.Column(db.Float,  nullable=False)                           #quantidade de Km's que o carro tem percorridos
    disponivel=db.Column(db.Boolean, default=True)



# Verifica se o veículo cumpre as regras de datas definidas neste projeto.
# Considera-o inapto se passaram mais de 365 dias desde a última legalização
# ou se a data da próxima revisão já passou.
# Devolve True se passar nas duas verificações e False caso contrário.
# Esta função não verifica se o veículo já está reservado.
def veiculo_apto(veiculo):
    data= date.today()

    #Condição 1: caso a data de legalização seja há mais de um ano- não apto
    limite_legalizacao = veiculo.ultima_legalizacao + timedelta(days=365)
    if limite_legalizacao < data:
        return False

    #Condição 2: caso a data da próxima revisão seja menor que hoje- não apto
    if veiculo.proxima_revisao < data:
        return False

    return True     # passou nas duas condições - apto


# Consulta os veículos e marca como indisponíveis os que não estão aptos.
# Guarda essas alterações e apresenta apenas os veículos disponíveis.
# Esta rotina não volta a marcar automaticamente um veículo como disponível
# quando as suas datas são corrigidas.
@app.route("/veiculos", methods=["GET"])
def veiculos():

    # Atualiza a disponibilidade de todos os veículos com base nas datas
    for v in Veiculo.query.all():
        if not veiculo_apto(v):
            v.disponivel = False
    db.session.commit()

    #Depois vai buscar apenas os que ficaram disponíveis
    lista_veiculos= Veiculo.query.filter_by(disponivel= True).all()

    return render_template("veiculos.html", veiculos= lista_veiculos)




# Recebe o identificador do veículo através do endereço da página.
# Procura esse veículo e envia os seus dados para detalhes.html.
# Se não existir, get_or_404() devolve um erro 404.

@app.route("/detalhes/<int:veiculo_id>")
def detalhes(veiculo_id):
    veiculo= Veiculo.query.get_or_404(veiculo_id)
    return render_template("detalhes.html", veiculo= veiculo)

# Define os dados dos clientes.
# Guarda o nome, email, hash da palavra-passe, telefone e NIF.
# O identificador id permite associar cada cliente às suas reservas.
class Cliente(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome= db.Column(db.String(100))
    email=db.Column(db.String(100))
    password_hash = db.Column(db.String(300), nullable=False)
    telefone=db.Column(db.Integer)
    nif=db.Column(db.Integer)           # número de contribuinte

# Define as formas de pagamento disponíveis.
# Cada registo tem um identificador e uma descrição do tipo de pagamento.
class Forma_pagamento(db.Model):
    id= db.Column(db.Integer, primary_key=True)
    tipo= db.Column(db.String(50))          # ex.: "Cartão", "MB Way", "Transferência"



# Define os dados de cada reserva.
# As chaves estrangeiras associam a reserva a um cliente, a um veículo
# e a uma forma de pagamento.
#
# Guarda as datas do aluguer, o número de dias e o valor total calculado.
# realizada indica se a reserva foi confirmada.
# cancelada indica se a reserva foi anulada.
# Estes dois campos começam com o valor False.
class Reservas(db.Model):
    id_reserva = db.Column(db.Integer, primary_key=True)
    id_cliente= db.Column(db.Integer, db.ForeignKey("cliente.id"))     # --- ligações a outras tabelas (chaves estrangeiras) ---
    id_veiculo= db.Column(db.Integer, db.ForeignKey("veiculo.id"))
    id_forma_pagamento= db.Column(db.Integer, db.ForeignKey("forma_pagamento.id"))
    data_inicio=db.Column(db.Date,nullable=False)              # --- dados próprios da reserva ---
    data_final=db.Column(db.Date,nullable=False)
    total_dias = db.Column(db.Integer)  #  calculado e guardado
    valor_total = db.Column(db.Float)  # calculado e guardado
    realizada= db.Column(db.Boolean , default=False)
    cancelada= db.Column(db.Boolean, default=False)




# Converte as datas recebidas em texto no formato ano-mês-dia
# para objetos date, que permitem comparar datas e calcular intervalos.
#
# Rejeita datas vazias ou inválidas, um início no passado
# e uma data de fim igual ou anterior à data de início.
# Em caso de erro, lança ValueError com uma mensagem explicativa.
# Se estiver tudo correto, devolve as duas datas convertidas.
def validar_datas(inicio, fim):
    try:
        data_inicio = datetime.strptime(inicio or "", "%Y-%m-%d").date()
        data_final = datetime.strptime(fim or "", "%Y-%m-%d").date()
    except (ValueError, TypeError):
        raise ValueError("Preenche as duas datas com valores válidos.")

    if data_inicio < date.today():
        raise ValueError("A data de início não pode estar no passado.")

    if data_final <= data_inicio:
        raise ValueError("A data de fim deve ser posterior à data de início.")

    return data_inicio, data_final

# Calcula a duração do aluguer pela diferença entre as datas.
# Multiplica o número de dias pelo preço diário para obter o valor sem IVA.
# Calcula o IVA e soma-o ao valor sem IVA para obter o total.
# Arredonda os valores monetários a duas casas decimais.
# Devolve o número de dias, o valor sem IVA, o IVA e o valor total.
def calcular_valores(veiculo, data_inicio, data_final):
    total_dias = (data_final - data_inicio).days
    valor_liquido = round(total_dias * veiculo.preco_dia, 2)
    valor_iva = round(valor_liquido * TAXA_IVA, 2)
    valor_total = round(valor_liquido + valor_iva, 2)

    return total_dias, valor_liquido, valor_iva, valor_total

# Procura uma reserva pelo seu identificador e pelo cliente autenticado.
# Assim, um cliente não consegue consultar ou alterar uma reserva de outro
# cliente apenas mudando o número da reserva no endereço.
# Se não encontrar uma reserva correspondente, devolve um erro 404.
def obter_reserva_do_cliente(id_reserva):
    # Devolve 404 se não existir ou se pertencer a outro cliente.
    return Reservas.query.filter_by(
        id_reserva=id_reserva,
        id_cliente=session["id_cliente"],
    ).first_or_404()



# Inicia o processo de aluguer de um veículo.
# Confirma que o veículo existe, está disponível e cumpre as regras de aptidão.
#
# GET: apresenta o formulário de escolha das datas.
# POST: elimina escolhas anteriores da sessão e valida as novas datas.
#
# Depois de validar, calcula o valor do aluguer e guarda na sessão
# as datas em formato de texto e o identificador do veículo escolhido.
# Apresenta o resumo dos valores no template.
# Nesta fase, ainda não cria uma reserva na base de dados.
@app.route("/efetuar_aluguer/<int:veiculo_id>", methods=["GET", "POST"])
def efetuar_aluguer(veiculo_id):
    veiculo = Veiculo.query.get_or_404(veiculo_id)

    if not veiculo.disponivel or not veiculo_apto(veiculo):
        flash("Este veículo não está disponível para aluguer.", "erro")
        return redirect(url_for("veiculos"))

    if request.method == "POST":
        # Eliminar uma escolha anterior antes de validar a nova.
        session.pop("data_inicio", None)
        session.pop("data_final", None)
        session.pop("veiculo_aluguer_id", None)

        try:
            data_inicio, data_final = validar_datas(
                request.form.get("data_inicio"),
                request.form.get("data_final"),
            )
        except ValueError as erro:
            flash(str(erro), "erro")
            return render_template(
                "efetuar_aluguer.html", veiculo=veiculo
            ), 400

        total_dias, valor_liquido, valor_iva, valor_total = calcular_valores(
            veiculo, data_inicio, data_final
        )

        session["data_inicio"] = data_inicio.isoformat()
        session["data_final"] = data_final.isoformat()

        # Associa as datas ao veículo escolhido.
        session["veiculo_aluguer_id"] = veiculo.id

        return render_template(
            "efetuar_aluguer.html",
            veiculo=veiculo,
            data_inicio=data_inicio,
            data_final=data_final,
            total_dias=total_dias,
            valor_total=valor_total,
        )

    return render_template("efetuar_aluguer.html", veiculo=veiculo)



# Verifica novamente a disponibilidade e a aptidão do veículo.
# Confirma que as datas guardadas na sessão pertencem a este veículo.
# Volta a validar as datas e a calcular os valores no servidor.
#
# GET: apresenta os valores e as formas de pagamento disponíveis.
# POST: confirma que a forma de pagamento escolhida existe.
#
# Tenta marcar o veículo como indisponível apenas se ainda estiver disponível.
# Se não conseguir atualizar exatamente um veículo, desfaz a transação.
#
# Cria a reserva associada ao cliente autenticado e guarda-a juntamente
# com a alteração da disponibilidade do veículo na mesma transação.
# Depois, remove os dados temporários da sessão e mostra os dados da reserva.
#
# Esta rota regista a forma de pagamento escolhida;
# não efetua uma cobrança através de um serviço de pagamentos.
@app.route("/pagamento/<int:veiculo_id>", methods=["GET", "POST"])
def pagamento(veiculo_id):
    veiculo = Veiculo.query.get_or_404(veiculo_id)

    if not veiculo.disponivel or not veiculo_apto(veiculo):
        flash("Este veículo já não está disponível para aluguer.", "erro")
        return redirect(url_for("veiculos"))

    if session.get("veiculo_aluguer_id") != veiculo.id:
        flash("Escolhe primeiro as datas para este veículo.", "erro")
        return redirect(url_for("efetuar_aluguer", veiculo_id=veiculo.id))

    try:
        data_inicio, data_final = validar_datas(
            session.get("data_inicio"),
            session.get("data_final"),
        )
    except ValueError as erro:
        flash(str(erro), "erro")
        return redirect(url_for("efetuar_aluguer", veiculo_id=veiculo.id))

    total_dias, valor_liquido, valor_iva, valor_total = calcular_valores(
        veiculo, data_inicio, data_final
    )

    formas = Forma_pagamento.query.all()

    if request.method == "POST":
        id_forma_pagamento = request.form.get("id_forma_pagamento", type=int)

        forma = None
        if id_forma_pagamento is not None:
            forma = db.session.get(Forma_pagamento, id_forma_pagamento)

        if forma is None:
            flash("Seleciona uma forma de pagamento válida.", "erro")
            return redirect(url_for("pagamento", veiculo_id=veiculo.id))

        # Só reserva o veículo se ainda estiver disponível na base de dados.
        # A alteração e a criação da reserva são guardadas na mesma transação.
        atualizado = Veiculo.query.filter_by(
            id=veiculo.id,
            disponivel=True,
        ).update(
            {Veiculo.disponivel: False},
            synchronize_session=False,
        )

        if atualizado != 1:
            db.session.rollback()
            flash("O veículo acabou de ficar indisponível.", "erro")
            return redirect(url_for("veiculos"))

        nova_reserva = Reservas(
            id_cliente=session["id_cliente"],
            id_veiculo=veiculo.id,
            id_forma_pagamento=forma.id,
            data_inicio=data_inicio,
            data_final=data_final,
            total_dias=total_dias,
            valor_total=valor_total,
        )

        db.session.add(nova_reserva)
        db.session.commit()

        session.pop("data_inicio", None)
        session.pop("data_final", None)
        session.pop("veiculo_aluguer_id", None)

        return redirect(
            url_for("lista_reservas", id_reserva=nova_reserva.id_reserva)
        )

    return render_template(
        "pagamento.html",
        veiculo=veiculo,
        formas=formas,
        total_dias=total_dias,
        valor_liquido=valor_liquido,
        valor_iva=valor_iva,
        valor_total=valor_total,
    )

# Obtém uma reserva pertencente ao cliente autenticado.
# Procura o veículo associado e envia os dois objetos para o template,
# que apresenta os dados da reserva.
@app.route("/lista_reservas/<int:id_reserva>", methods=["GET"])
def lista_reservas(id_reserva):
    reserva = obter_reserva_do_cliente(id_reserva)
    veiculo = Veiculo.query.get_or_404(reserva.id_veiculo)

    return render_template(
        "lista_reservas.html",
        veiculo=veiculo,
        reserva=reserva,
    )

# Permite alterar as datas de uma reserva do cliente autenticado.
# Impede a alteração de reservas canceladas, com início anterior a hoje
# ou cujo veículo não cumpra as regras de aptidão.
#
# GET: apresenta o formulário de alteração.
# POST: valida as novas datas e recalcula a duração e o valor total.
#
# Atualiza a reserva, guarda as alterações e apresenta uma mensagem de sucesso.
@app.route("/alteracao_reserva/<int:id_reserva>", methods=["GET", "POST"])
def alteracao_reserva(id_reserva):
    reserva = obter_reserva_do_cliente(id_reserva)
    veiculo = Veiculo.query.get_or_404(reserva.id_veiculo)

    if reserva.cancelada:
        flash("Não é possível alterar uma reserva cancelada.", "erro")
        return redirect(url_for("lista_reservas", id_reserva=id_reserva))

    if reserva.data_inicio < date.today():
        flash("Não é possível alterar uma reserva já iniciada.", "erro")
        return redirect(url_for("lista_reservas", id_reserva=id_reserva))

    if not veiculo_apto(veiculo):
        flash("O veículo não está apto para este aluguer.", "erro")
        return redirect(url_for("lista_reservas", id_reserva=id_reserva))

    if request.method == "POST":
        try:
            data_inicio, data_final = validar_datas(
                request.form.get("data_inicio"),
                request.form.get("data_final"),
            )
        except ValueError as erro:
            flash(str(erro), "erro")
            return render_template(
                "alteracao_reserva.html",
                veiculo=veiculo,
                reserva=reserva,
            ), 400

        total_dias, valor_liquido, valor_iva, valor_total = calcular_valores(
            veiculo, data_inicio, data_final
        )

        reserva.data_inicio = data_inicio
        reserva.data_final = data_final
        reserva.total_dias = total_dias
        reserva.valor_total = valor_total

        db.session.commit()

        flash("Reserva alterada com sucesso.", "sucesso")
        return redirect(url_for("lista_reservas", id_reserva=id_reserva))

    return render_template(
        "alteracao_reserva.html",
        veiculo=veiculo,
        reserva=reserva,
    )

# Cancela uma reserva do cliente autenticado através de um pedido POST.
# Rejeita reservas já canceladas ou com data de início anterior a hoje.
#
# Marca a reserva como cancelada, sem a apagar da base de dados.
# Procura outras reservas não canceladas para o mesmo veículo.
# Só volta a disponibilizar o veículo se não existir outra reserva
# não cancelada e se o veículo estiver apto.
#
# Guarda as alterações e encaminha o cliente para a lista de veículos.
@app.route("/anular_reserva/<int:id_reserva>", methods=["POST"])
def anular_reserva(id_reserva):
    reserva = obter_reserva_do_cliente(id_reserva)
    veiculo = Veiculo.query.get_or_404(reserva.id_veiculo)

    if reserva.cancelada:
        flash("Esta reserva já está cancelada.", "erro")
        return redirect(url_for("lista_reservas", id_reserva=id_reserva))

    if reserva.data_inicio < date.today():
        flash("Não é possível cancelar uma reserva já iniciada.", "erro")
        return redirect(url_for("lista_reservas", id_reserva=id_reserva))

    reserva.cancelada = True

    # Não disponibiliza o veículo se existir outra reserva não cancelada.
    outra_reserva = Reservas.query.filter(
        Reservas.id_veiculo == veiculo.id,
        Reservas.id_reserva != reserva.id_reserva,
        Reservas.cancelada.is_(False),
    ).first()

    veiculo.disponivel = (
        outra_reserva is None and veiculo_apto(veiculo)
    )

    db.session.commit()

    flash("Reserva cancelada com sucesso.", "sucesso")
    return redirect(url_for("veiculos"))

# Gere a confirmação de uma reserva do cliente autenticado.
# Não permite confirmar uma reserva cancelada.
#
# POST: verifica a data de início e a aptidão do veículo,
# marca a reserva como confirmada e guarda a alteração.
# Depois, redireciona para a mesma página através de um pedido GET,
# evitando repetir o envio do formulário ao atualizar o navegador.
#
# GET: apresenta a página de confirmação apenas se a reserva
# já estiver confirmada; caso contrário, devolve um erro 404.
@app.route("/reserva_realizada/<int:id_reserva>", methods=["GET", "POST"])
def reserva_realizada(id_reserva):
    reserva = obter_reserva_do_cliente(id_reserva)
    veiculo = Veiculo.query.get_or_404(reserva.id_veiculo)

    if reserva.cancelada:
        flash("Não é possível confirmar uma reserva cancelada.", "erro")
        return redirect(url_for("lista_reservas", id_reserva=id_reserva))

    if request.method == "POST":
        if reserva.data_inicio < date.today() or not veiculo_apto(veiculo):
            flash("Verifica as datas e a aptidão do veículo.", "erro")
            return redirect(url_for("lista_reservas", id_reserva=id_reserva))

        reserva.realizada = True
        db.session.commit()

        # Evita repetir o POST ao atualizar a página.
        return redirect(url_for("reserva_realizada", id_reserva=id_reserva))

    if not reserva.realizada:
        abort(404)

    return render_template(
        "reserva_realizada.html",
        veiculo=veiculo,
        reserva=reserva,
    )

# Apresenta todas as reservas associadas ao cliente autenticado.
# A verificação da sessão repete uma proteção já feita no before_request.
# Filtra as reservas pelo identificador do cliente e ordena-as
# por número de reserva, do maior para o menor.
# Envia a lista para o template minhas_reservas.html.
@app.route("/minhas_reservas", methods=["GET"])
def minhas_reservas():
    if "id_cliente" not in session:
        flash("Tens de iniciar sessão para consultar as tuas reservas.", "erro")
        return redirect(url_for("login"))

    reservas = Reservas.query.filter_by(
        id_cliente=session["id_cliente"]
    ).order_by(Reservas.id_reserva.desc()).all()

    return render_template(
        "minhas_reservas.html",
        reservas=reservas
    )


# Este bloco só é executado quando o ficheiro é iniciado diretamente,
# e não quando é importado por outro ficheiro Python.
#
# app.app_context() disponibiliza o contexto necessário para trabalhar
# com a base de dados fora de um pedido HTTP.
#
# create_all() cria as tabelas que ainda não existem.
# Não atualiza automaticamente a estrutura de tabelas já existentes.
#
# Se a tabela de veículos estiver vazia, insere os veículos iniciais.
# Se a tabela de formas de pagamento estiver vazia, insere essas opções.
# Estas verificações evitam repetir a inserção inicial em cada arranque.
#
# add_all() prepara a inserção de vários registos.
# commit() guarda as alterações na base de dados.
# print() apresenta uma mensagem na consola.
if __name__=='__main__':
    with app.app_context():
        db.create_all() # Cria as tabelas se não existirem

        # Verifica se a tabela está vazia antes de inserir para não duplicar
        if Veiculo.query.count()==0:
            v1= Veiculo(marca="BMW", modelo="Serie 3", ano= 2019, imagem="BMW.jpg",preco_dia=20, tipo="Berlina", lugares=5, ultima_revisao=date(2026,1,10), proxima_revisao=date(2027,1,31), ultima_legalizacao=date(2026,1,31),kms=100000, disponivel=True)
            v2= Veiculo(marca="Porche", modelo="911 Sperdstu", ano=2019, imagem="porche.jpg",preco_dia=20, tipo="Cabriolet", lugares=2, ultima_revisao=date(2026,2,10), proxima_revisao=date(2027,2,28), ultima_legalizacao=date(2026,2,28),kms=100000,disponivel=True)
            v3= Veiculo(marca="Tesla", modelo="Modelo 3", ano= 2019, imagem="tesla.jpg",preco_dia=20,tipo="Berlina", lugares=5, ultima_revisao=date(2026,3,10), proxima_revisao=date(2027,3,31), ultima_legalizacao=date(2026,3, 31),kms=100000,disponivel=True)
            v4=Veiculo(marca="Volkswagen", modelo="Golf Sportsvan", ano=2018, imagem="Volkswagen.jpg",preco_dia=20,tipo="Familiar", lugares=5, ultima_revisao=date(2026,4,10), proxima_revisao=date(2027,4,30), ultima_legalizacao=date(2026,4,30),kms=100000,disponivel=True)
            v5=Veiculo(marca="Mercedes-Benz", modelo="Classe A Hatchbaok",ano=2018,imagem="mercedes.jpg",preco_dia=20,tipo="Berlina", lugares=5, ultima_revisao=date(2026,5,10), proxima_revisao=date(2027,5,31), ultima_legalizacao=date(2026,5,31),kms=100000,disponivel=True)
            v6=Veiculo(marca="Rolls Royce", modelo="Ghost", ano=2020, imagem="RollsRoyce.jpg",preco_dia=20,tipo="Berlina", lugares=5, ultima_revisao=date(2026,6,10), proxima_revisao=date(2027,6,30), ultima_legalizacao=date(2026,6,30),kms=100000,disponivel=True)
            v7=Veiculo(marca="Nissan", modelo="Qashqai", ano=2021, imagem="Nissan.jpg",preco_dia=20,tipo="Sub", lugares=5, ultima_revisao=date(2026,7,10), proxima_revisao=date(2027,7,31), ultima_legalizacao=date(2026,7,31),kms=100000,disponivel=True)
            v8=Veiculo(marca="Volvo", modelo="VC90", ano=2022, imagem="Volvo.jpg",preco_dia=20, tipo="Sub", lugares=5, ultima_revisao=date(2026,8,10), proxima_revisao=date(2027,8,31), ultima_legalizacao=date(2026,8,31),kms=100000,disponivel=True)
            v9=Veiculo(marca="Audi", modelo="A5 Sportback", ano=2020, imagem="audi.jpg",preco_dia=20,tipo="Berlina", lugares=5, ultima_revisao=date(2026,9,10), proxima_revisao=date(2027,9,30), ultima_legalizacao=date(2026,9,30),kms=100000,disponivel=True)
            v10=Veiculo(marca="Aston Martin", modelo="DBS Superleggera", ano=2023, imagem="aston.jpg",preco_dia=20,tipo="Berlina", lugares=2, ultima_revisao=date(2026,10,10), proxima_revisao=date(2027,10,31), ultima_legalizacao=date(2026,10,31),kms=100000,disponivel=True)


            db.session.add_all([v1,v2,v3,v4,v5,v6,v7,v8,v9,v10])# Adiciona a lista à sessão
            db.session.commit() # Guarda as alterações no ficheiro .db
            print("Carros inseridos com sucesso!")

        #Inserir as formas de pagamento (só se a tabela estiver vazia)
        if Forma_pagamento.query.count()==0:
            f1= Forma_pagamento(tipo="Cartão de Crédito")
            f2= Forma_pagamento(tipo="MB Way")
            f3= Forma_pagamento(tipo="Transferência Bancária")
            f4= Forma_pagamento(tipo="Multibanco")

            db.session.add_all([f1,f2,f3,f4])  #Adiciona a lista à sessão
            db.session.commit()  #Guarda as alterações no ficheiro .db
            print("Forma de pagamento inserida com sucesso!")

    # Inicia o servidor de desenvolvimento do Flask.
    # debug=True ativa a depuração e, por defeito, o recarregamento automático
    # quando são detetadas alterações nos ficheiros de código.
    # Este modo destina-se ao desenvolvimento e não deve ser usado em produção.
    app.run(debug=True)  # O debug=True faz com que cada vez que reiniciemos o
    # servidor ou modifiquemos o código, o servidor de Flask reinicia-se sozinho
