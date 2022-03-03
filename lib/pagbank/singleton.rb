# frozen_string_literal: true

require 'cacheable'
require 'singleton'

module Pagbank
  class Pix
    include Singleton

    include Cacheable

    # Rails.cache.fetch('pagseg-cached', expires_in: ) do
    # cacheable :access_token, cache_options: { expires_in: current_env == :sandbox ? 1.year : 24.hours }
    cacheable :access_token, cache_options: { expires_in: 3_600 * 24 * 31 * 3 } # 3 months
    # self.clear_access_token_cache

    # Our Pix integration class
    DEFAULT_HEADERS = {
      'Content-Type': 'application/json;encoding=utf-8',
      'X-Api-Version': '2',
      'Accept': 'application/json',
      'Api-SDK': 'jnettome-pagbank-v1'
    }.freeze
  
    API_BASE_URLS = {
      'sandbox': 'https://secure.sandbox.api.pagseguro.com/',
      'live': 'https://secure.api.pagseguro.com/'
    }.freeze

    def self.current_env
      Pagbank.config.environment
    end

    def initialize
      logger = Logger.new($stdout)
      @certfile = File.read(Pagbank.config.certfile)
      @keyfile = File.read(Pagbank.config.keyfile)
      @http = HTTP.use(logging: { logger: logger })
      @auth = Base64.strict_encode64("#{Pagbank.config.api_client_id}:#{Pagbank.config.api_client_secret}")
    end
  
    def ssl_context
      OpenSSL::SSL::SSLContext.new.tap do |ctx|
        ctx.set_params(
          verify_mode: OpenSSL::SSL::VERIFY_PEER,
          cert: OpenSSL::X509::Certificate.new(@certfile), key: OpenSSL::PKey::RSA.new(@keyfile)
        )
      end
    end
    # Send pix from someone to another one
    # @param amount String \d{1,10}.\d{2} example "12.34"
    # @param from_key String PIX key originating from (eg "19974764017")
    # @param to_key String PIX key amount`s going to (eg "chave@pix.com")
    # @param extra_info String extra info Informação do pagador sobre o Pix a ser enviado. string < 140
    #
    # Returns
    #
    # {
    #   "e2eId": "dsadsadasdas6202011251226APIff82f2e5",
    #   "valor": "12.31",
    #   "horario": {
    #     "solicitacao": "2020-11-25T12:26:42.905Z"
    #   },
    #   "status": {
    #     "type": "EM_PROCESSAMENTO"
    #   }
    # }
    # "EM_PROCESSAMENTO","REALIZADO","NAO_REALIZADO"
    # def send_pix(amount, from_key, to_key, extra_info = nil)
    #   params = {
    #     "valor": amount,
    #     "pagador": {
    #       "chave": from_key,
    #       "infoPagador": extra_info
    #     },
    #     "favorecido": { "chave": to_key }
    #   }

    #   post_json("#{API_BASE_URLS[Pagbank.config.environment]}v2/pix", params, request_headers)
    # rescue Pagbank::RequestError => e
    #   # TODO acho que esta caindo aqui porem nao eh um JSON valido entao nao consegue ler - ACHO
    #   # FIXME 8 janeiro
    #   if (e.error_body['nome'] && e.error_body['nome'] == 'erro_aplicacao' && e.error_body['mensagem'] && e.error_body['mensagem'] == 'Ocorreu um erro ao buscar os dados da chave') || (e.error_body['nome'] == 'chave_nao_encontrada') || (e.error_body['nome'] == 'valor_invalido')
    #     raise PagseguroTipaTransferError, 'Erro na transferência do Pix. Chave Pix recebedora não encontrada.'
    #   elsif (e.error_body['nome'] && e.error_body['nome'] == 'json_invalido')
    #     raise PagseguroTipaTransferError, 'Erro na transferência do Pix. Chave Pix muito grande.'
    #   elsif (e.error_body['nome'] && e.error_body['nome'] == 'pedido_pagamento_negado')
    #     raise PagseguroTipaLimitTransferError, 'Erro na transferência do Pix. Iremos transferir na próxima manhã por conta dos limites.'
    #   else
    #     raise Pagbank::RequestError.new(e.message, e.error_body)
    #   end
    # end

    # def create_loc
    #   params = {
    #     "tipoCob": 'cob'
    #   }

    #   post_json("#{API_BASE_URLS[Pagbank.config.environment]}v2/loc", params, request_headers)
    # end

    # Create a charge by PIX
    # @param amount String
    # @param receiver_key String PIX Key for generating charge eg '312321321-c695-4e3c-b010-abb521a3f1be'
    # @param payer_cpf String Payer CPF eg '12345678909'
    # @param payer_name String Payer Name eg'Francisco da Silva'
    # @param extra_info Array[Object] eg [{ "nome": 'Pagamento em', "valor": 'Nome da sua empresa' }]
    #
    # SUCESSO 201
    # {
    #   "calendario": {
    #     "criacao": "2020-09-09T20:15:00.358Z",
    #     "expiracao": 3600
    #   },
    #   "txid": "7978c0c97ea847e78e8849634473c1f1",
    #   "revisao": 0,
    #   "loc": {
    #     "id": 789,
    #     "location": "pix.example.com/qr/v2/9d36b84fc70b478fb95c12729b90ca25",
    #     "tipoCob": "cob"
    #   },
    #   "location": "pix.example.com/qr/v2/9d36b84fc70b478fb95c12729b90ca25",
    #   "status": "ATIVA",
    #   "devedor": {
    #     "cnpj": "12345678000195",
    #     "nome": "Empresa de Serviços SA"
    #   },
    #   "valor": {
    #     "original": "567.89"
    #   },
    #   "chave": "a1f4102e-a446-4a57-bcce-6fa48899c1d1",
    #   "solicitacaoPagador": "Indagação ao pagador",
    #   "infoAdicionais": [
    #     {
    #       "nome": "Pagamento em",
    #       "valor": "Nome da sua empresa"
    #     },
    #     {
    #       "nome": "Número do Pedido",
    #       "valor": "ID do pedido"
    #     }
    #   ]
    # }
    #
    # {"calendario":{"criacao":"2021-05-25T14:01:45.358Z","expiracao":3600},"txid":"7e27467308a64841a85f03ccd89d2fb7","revisao":0,"loc":{"id":1,"location":"qrcodes-pix-h.gerencianet.com.br/v2/dsadsadas","tipoCob":"cob",#"criacao":"2021-05-25T14:01:45.427Z"},"location":"qrcodes-pix-h.gerencianet.com.br/v2/e9e80d200a794ca483d15c0ef596a8fa","status":"ATIVA","devedor":{"cpf":"12345678909","nome":"João Pedro"},"valor":{"original":"5.00"},"chave":"4589","infoAdicionais":[{"nome":"doação para","valor":"dsadas@dsadas.com"}]}
    # ERRO 400
    # InvalidOperationError
    #   {
    #     "nome": "documento_bloqueado",
    #     "mensagem": "O documento desta conta tem bloqueios que impedem a emissão"
    #   }
    #   {
    #     "nome": "chave_invalida",
    #     "mensagem": "A chave informada não faz referência à conta Pagbank autenticada"
    #   }
    #   {
    #     "nome": "valor_invalido",
    #     "mensagem": "Campo valor.original deve ser maior que zero"
    #   }
    #   {
    #     "nome": "valor_invalido",
    #     "mensagem": "Campo calendario.expiracao deve ser maior que zero"
    #   }
    #   {
    #     "nome": "valor_invalido",
    #     "mensagem": "Documento CPF em devedor.cpf é inválido"
    #   }
    #   {
    #     "nome": "valor_invalido",
    #     "mensagem": "Documento CNPJ em devedor.cnpj é inválido"
    #   }
    # https://dev.gerencianet.com.br/docs/api-pix#section-requisitar-envio-de-pix-
    def charge_pix(txid, amount, receiver_key, _payer_cpf, _payer_name, extra_info = [])
      # "devedor": { "cpf": payer_cpf, "nome": payer_name },
      params = {
        "calendario": { "expiracao": 864000 },
        "valor": { "original": amount },
        "chave": receiver_key,
        "infoAdicionais": extra_info
      }

      put_json("#{API_BASE_URLS[Pagbank.config.environment]}instant-payments/cob/#{txid}", params, request_headers)
    end

    # https://dev.pagseguro.uol.com.br/reference/pix-charge-pay-sandbox
    # Endpoint criado para que em Sandbox, o usuário recebedor possa simular o pagamento de uma cobrança imediata. Assim que simulado o pagamento, a cobrança antes ATIVA terá o seu status atualizado para CONCLUÍDA.
    # Após conclusão, a cobrança não aceita um novo pagamento.
    # O TOKEN para simulação de pagamento é DIFERENTE do token client_credencials, ele pode ser recuperado no ambiente de SANDBOX da PagSeguro:
    # https://sandbox.pagseguro.uol.com.br
    # Após login e senha > Perfis de Integração > Vendedor > Credenciais "Seu Token é".
    def simulate_pay_pix(txid)
      params = {
        "status": "PAID",
        "tx_id": txid
      }
      post_json_noparse("https://sandbox.api.pagseguro.com/pix/pay/#{txid}", params, { Authorization: "Bearer #{Pagbank.config.api_test_token}", 'Content-Type': 'application/json', 'Accept': '*/*' })
    end

    # temos que fazer uma request para o api-h
    def get_payload(location_url)
      # instant-payments/cob/
      get_content(location_url, request_headers)
    end

    def get_devolution(e2eid, devolution_id)
      get_json("#{API_BASE_URLS[Pagbank.config.environment]}instant-payments/pix/#{e2eid}/devolucao/#{devolution_id}", request_headers)
    end

    # Get info from a pix via txid
    # @param txid String PIX Charge ID (txid)
    # {
    #   "status": "ATIVA",
    #   "calendario": {
    #     "criacao": "2020-09-09T20:15:00.358Z",
    #     "expiracao": "3600"
    #   },
    #   "location": "pix.example.com/qr/9d36b84f-c70b-478f-b95c-12729b90ca25",
    #   "txid": "esadasdasdas8849634473c1f1",
    #   "revisao": 1,
    #   "devedor": {
    #     "cnpj": "12345678000195",
    #     "nome": "Empresa de Serviços SA"
    #   },
    #   "valor": {
    #     "original": "567.89"
    #   },
    #   "chave": "dsadasdasdas-a446-4a57-bcce-dasdsadas",
    #   "solicitacaoPagador": "Indagação ao pagador."
    # }
    # OR
    # {
    #   "status": "CONCLUIDA",
    #   "calendario": {
    #     "criacao": "2020-09-09T20:15:00.358Z",
    #     "expiracao": "3600"
    #   },
    #   "location": "qrcodes-pix.gerencianet.com.br/1d8e-4172-8702-8dc33e21a403",
    #   "txid": "655dfdb1-a451-4b8f-bb58-25",
    #   "revisao": 1,
    #   "devedor": {
    #     "cnpj": "12345678000195",
    #     "nome": "Empresa de Serviços SA"
    #   },
    #   "valor": {
    #     "original": "100.00"
    #   },
    #   "chave": "40a0932d-1918-4eee-845d-35a2da1690dc",
    #   "solicitacaoPagador": "Informe o número ou identificador do pedido.",
    #   "pix": [
    #     {
    #       "endToEndId": "E123402009091221kkkkkkkkkkk",
    #       "txid": "655dfdb1-a451-4b8f-bb58-254b958913fb",
    #       "valor": "110.00",
    #       "horario": "2020-09-09T20:15:00.358Z",
    #       "pagador": {
    #         "cnpj": "12345678000195",
    #         "nome": "Empresa de Serviços SA"
    #       },
    #       "infoPagador": "0123456789",
    #       "devolucoes": [
    #         {
    #           "id": "123ABC",
    #           "rtrId": "Dxxxxxxxx202009091221kkkkkkkkkkk",
    #           "valor": "10.00",
    #           "horario": {
    #             "solicitacao": "2020-09-09T20:15:00.358Z"
    #           },
    #           "status": "EM_PROCESSAMENTO"
    #         }
    #       ]
    #     }
    #   ]
    # }
    #
    # OR ERROR 400
    # {
    #   "nome": "cobranca_nao_encontrada",
    #   "mensagem": "Nenhuma cobrança encontrada para o txid informado"
    # }
    def get_pix(txid)
      get_json("#{API_BASE_URLS[Pagbank.config.environment]}instant-payments/cob/#{txid}", request_headers)
    end
    
    def get_pix_e2e(e2eid)
      get_json("#{API_BASE_URLS[Pagbank.config.environment]}instant-payments/pix/#{e2eid}", request_headers)
    end
    
    # Consultar uma lista de PIX recebidos
    # GET
    # https://secure.sandbox.api.pagseguro.com/instant-payments/pix?{fim}&{inicio}
    # Endpoint para consultar um Pix através dos parâmetros: Data inicio, data fim, txid, se existe uma devolução ou não, cpf e cnpj.
    def get_received(start_date, end_date)
      get_json("#{API_BASE_URLS[Pagbank.config.environment]}instant-payments/pix?fim=#{end_date}&inicio=#{start_date}", request_headers)
    end

    # e2eid
    # string
    # required
    # O parâmetro, obrigatório, representa o ID fim a fim da transação que transita na PACS002, PACS004 e PACS008. O e2eid fica disponível após uma cobrança estar concluída e você pode encontrá-lo no response da consulta da cobrança get/cob

    # id
    # string
    # required
    # ID que representa uma devolução e é único por CPF/CNPJ do usuário recebedor. O objetivo desse campo é ser um elemento que possibilite ao usuário recebedor a funcionalidade de conciliação de pagamentos. O ID é criado exclusivamente pelo usuário recebedor e está sob sua responsabilidade
    def refund(e2eid, id, amount)
      params = {
        "valor": amount
      }
      put_json("#{API_BASE_URLS[Pagbank.config.environment]}instant-payments/pix/#{e2eid}/devolucao/#{id}", params, request_headers)
    end

    # GET qr code
    # @param location_id String Id da location cadastrada para servir um payload - vem no .loc.id ao gerar cobranca
    #
    # {
    #     "qrcode": "00020126880014BR.GOV.BCB.qrcodes.pagseguro.com.b...",
    #     "imagemQrcode": "data:image/png;base64,iVBORw0KGgoAAAAOQAAADkCAYAAACIV4s..."
    # }
    def generate_pix_qrcode(url)
      # get_json("#{API_BASE_URLS[Pagbank.config.environment]}instant-payments/loc/#{location_id}/qrcode", request_headers)
      # amount: amount,
      # transaction_id: '0503***',

      pix = QrcodePixRuby::Payload.new(
        url: url,
        merchant_code: '8999',
        merchant_name: 'Pagseguro Internet SA', # ate 25
        merchant_city: 'SAO PAULO', # ate 15
        currency: '986',
        country_code: 'BR',
        repeatable: false
      )

      ActiveSupport::HashWithIndifferentAccess.new({ "qrcode": pix.payload, "imagemQrcode": pix.base64 })
      #  if response.code == "400"
    end

    # Create random pix key
    #
    # 200 {
    #   "chave": "345e4568-e89b-12d3-a456-006655440001"
    # }
    # 400 {
    #   "nome": "limite_criacao_chave_atingido",
    #   "mensagem": "O limite de criação de chaves foi atingido"
    # }
    # 500 {
    #   "nome": "erro_aplicacao",
    #   "mensagem": "Ocorreu um erro ao solicitar a criação da chave"
    # }
    # def create_evp_key
    #   params = {}

    #   post_json("#{API_BASE_URLS[Pagbank.config.environment]}v2/gn/evp", params, request_headers)
    # end

    # List all random pix keys
    # {
    #   "chaves": [
    #     "355e4568-e89b-1243-a456-006655410001",
    #     "133e4568-e89b-1243-a456-006655410000"
    #   ]
    # }
    # OR 500
    # def get_evp_keys
    #   get_json("#{API_BASE_URLS[Pagbank.config.environment]}v2/gn/evp", request_headers)
    # end

    def webhooks(key)
      get_json("#{API_BASE_URLS[Pagbank.config.environment]}instant-payments/webhook/#{key}", request_headers)
    end

    # Update a webhook
    # @param Boolean
    def put_webhook(key, url)
      content = {
        'webhookUrl': url
      }
      endpoint = "#{API_BASE_URLS[Pagbank.config.environment]}instant-payments/webhook/#{key}"
      begin
        put_json(endpoint, content, {})
      rescue Pagbank::RequestError => e
        raise Pagbank::RequestError.new(e.message, e.error_body)
      end
    end

    def destroy_webhook(key)
      endpoint = "#{API_BASE_URLS[Pagbank.config.environment]}instant-payments/webhook/#{key}"
      destroy_json(endpoint, request_headers)
    end

    # pix/oauth2
    # {
    #   "access_token": "{{token}}",
    #   "token_type": "Bearer",
    #   "expires_in": 31536000,
    #   "refresh_token": "{{token}}",
    #   "scope": "pix.read pix.write cob.read cob.write"
    # }
    # {"access_token":"82985f87","token_type":"Bearer","expires_in":31536000,"refresh_token":"54780ce565c6","scope":"cob.read cob.write payloadlocation.read payloadlocation.write pix.read pix.write webhook.read webhook.write"}
    def access_token
      start_url = "#{API_BASE_URLS[Pagbank.config.environment]}pix/oauth2"
      response = JSON.parse(post_form(start_url, { grant_type: 'client_credentials', scope: 'pix.write pix.read cob.write cob.read webhook.write webhook.read payloadlocation.write payloadlocation.read' },
                                      { Authorization: "Basic #{@auth} ", 'X-Api-Version': '1' }))
      # https://dev.gerencianet.com.br/docs
      # {"access_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJDbGllbnRfSWRfMT.7lJmEXzz73x4e5nDomGJGf65UywftVzwZRMYJ5rcPjQ","token_type":"Bearer","expires_in":3600,"scope":"cob.read cob.write gn.balance.read gn.pix.evp.read gn.pix.evp.write gn.settings.read gn.settings.write payloadlocation.read payloadlocation.write pix.read pix.send pix.write webhook.read webhook.write"}
      response['access_token']
    end

    def post_form(url, content, headers = {})
      @http.headers(headers).post(url, form: content, ssl_context: ssl_context)
    end

    def post_form_auth(url, content, headers = {})
      JSON.parse(@http.headers(@http.headers(request_headers(headers)).post(url, form: content,
                                                                                ssl_context: ssl_context)))
    end

    def post_json(url, content, headers = {})
      request = @http.headers(request_headers(headers)).post(url, body: content.to_json, ssl_context: ssl_context)

      if ![200, 201].include?(request.code)
        raise Pagbank::RequestError.new('Erro na requisição', JSON.parse(request.body))
      else
        JSON.parse(request.body)
      end
    end

    def post_json_noparse(url, content, headers = {})
      request = @http.headers(request_headers(headers)).post(url, body: content.to_json, ssl_context: ssl_context)

      if ![200, 201].include?(request.code)
        raise Pagbank::RequestError.new('Erro na requisição', request.body)
      else
        request.body
      end
    end

    def put_json(url, content, headers = {})
      request = @http.headers(request_headers(headers)).put(url, body: content.to_json, ssl_context: ssl_context)

      if ![200, 201].include?(request.code)
        raise Pagbank::RequestError.new('Erro na requisição', JSON.parse(request.body))
      else
        JSON.parse(request.body)
      end
    end

    def destroy_json(url, headers = {})
      request = @http.headers(request_headers(headers)).delete(url, ssl_context: ssl_context)

      if ![200, 201, 204].include?(request.code)
        raise Pagbank::RequestError.new('Erro na requisição', JSON.parse(request.body))
      else
        JSON.parse(request.body)
      end
    end

    def patch_json(url, content, headers = {})
      request = @http.headers(request_headers(headers)).patch(url, body: content.to_json, ssl_context: ssl_context)

      if ![200, 201].include?(request.code)
        raise Pagbank::RequestError.new('Erro na requisição', JSON.parse(request.body))
      else
        JSON.parse(request.body)
      end
    end

    def get_json(url, headers = {})
      JSON.parse(@http.headers(request_headers(headers)).get(url, ssl_context: ssl_context))
    end
    
    def get_content(url, headers = {})
      @http.headers(request_headers(headers)).get(url, ssl_context: ssl_context)
    end

    def request_headers(headers = {})
      # CURLOPT_SSLCERT => $config["certificado"], // Caminho do certificado ->  "certificado" => "./certificado.pem",
      # CURLOPT_SSLCERTPASSWD => "",
      DEFAULT_HEADERS.merge(Authorization: "Bearer #{access_token}").merge(headers)
    end
  end
end
