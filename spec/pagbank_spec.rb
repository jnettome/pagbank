# frozen_string_literal: true

RSpec.describe Pagbank do
  before(:all) do
    Pagbank.config.api_client_id = 'dsadasdasdas'
    Pagbank.config.api_client_secret = 'dsadasdasdasdas'
    Pagbank.config.api_test_token = "10F47062DBD1416398dsadasdasdas"
    Pagbank.config.environment = :sandbox # :live
    Pagbank.config.certfile = './data/chave_pagseguro_sand.pem'
    Pagbank.config.keyfile = './data/chave_pagseguro_sand.key'
  end

  it "has a version number" do
    expect(Pagbank::VERSION).not_to be nil
  end

  # it "does something useful" do
  #   # expect(false).to eq(true)
  #   # expect(Pagbank::Pix.new).to be nil
  #   expect(Pagbank::Pix.instance.webhooks('chave')).to be nil
  # end

  # eh necessario realizar o teste dos 08 passos e nos encaminhar os logs de requisição e resposta.

  # Criar uma autenticação;
  # Criar uma cobrança;
  # Recuperar uma cobrança (utilizando pixurlaccesstoken);
  # Pagar cobrança;
  # Consultar cobrança;
  # Consultar recebimento;
  # Realizar uma devolução com sucesso;
  # Realizar uma devolução com retorno de erro.
  it "Criar uma autenticação" do
  end

  # it "Criar um webhook" do
  #   expect(Pagbank::Pix.instance.put_webhook("32918392018321908312908321", "https://meusite.me/pix/webhooks")).to be nil
  # end

  
  it "Criar uma cobrança" do
    # Pagbank::Pix.instance.put_webhook("32918392018321908312908321", "https://meusite.me/pix/webhooks")
    # sleep 5

    charge = Pagbank::Pix.instance.charge_pix('1a8ae8d442e04d90b3908758c5af8a11', '%.2f' % 34.00, "32918392018321908312908321", nil, nil, [{ "nome": 'cob de testes', "valor": "homolog" }])
    puts charge.inspect

    sleep 5

    payload = Pagbank::Pix.instance.get_payload("https://#{charge["location"]}" )
    puts payload.inspect

    sleep 5

    pay = Pagbank::Pix.instance.simulate_pay_pix('1a8ae8d442e04d90b3908758c5af8a11')
    puts pay.inspect

    sleep 5

    consult = Pagbank::Pix.instance.get_pix('1a8ae8d442e04d90b3908758c5af8a11')
    puts consult.inspect

    sleep 5

    receb = Pagbank::Pix.instance.get_pix_e2e(consult["pix"][0]["endToEndId"])
    puts receb.inspect

    sleep 5

    devolv = Pagbank::Pix.instance.refund(consult["pix"][0]["endToEndId"], 'ida32189dd8s33a9', '%.2f' % 31.00)
    puts devolv.inspect

    sleep 5
    
    expect(nil).to be nil
  end
  # it "Recuperar uma cobrança (utilizando pixurlaccesstoken);" do
  #   expect(Pagbank::Pix.instance.get_payload("https://api-h.pagseguro.com/pix/v2/8B34DB80-6-49B8-A2AE-963E151E5415")).to be nil
  # end

  # it "Pagar cobrança;" do
    # expect().to be nil
  # end

  # it "Consultar cobrança;" do
  #   expect().to be nil
  # end

  # acho que depende de receber um webhook pra ter o e2e
  # it "Consultar recebimento;" do
  #   # expect(Pagbank::Pix.instance.get_received((DateTime.now.to_time - 3600 * 24 * 10).to_datetime, DateTime.now)).to be nil
  #   # Consultar um PIX
  #   # get_devolution(e2eid, devolution_id)
  #   expect(Pagbank::Pix.instance.get_pix_e2e('3cc97b21a5f2267bdd8')).to be nil
  # end

  # it "Realizar uma devolução com sucesso;" do
  #   expect(Pagbank::Pix.instance.refund('d47ed43cc97b21a5f2267bdd8', 'dev123123', '%.2f' % 422.00)).to be nil
  # end

  # # Endpoint para solicitar devolução total de um PIX. Caso o valor informado na requisição de devolução seja
  # # diferente do valor original da cobrança é possível simular o cenário de devolução NÃO REALIZADA em Sandbox.
  # # O ID da devolução é único e criado exclusivamente pelo usuário recebedor e está sob sua responsabilidade.
  # it "Realizar uma devolução com retorno de erro." do
  #   expect(Pagbank::Pix.instance.refund('d47ed43cc97b21a5f2267bdd8', 'dev123123', '%.2f' % 200.00)).to be nil
  # end
end
