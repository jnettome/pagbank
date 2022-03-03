# frozen-string-literal: true

# rubocop:disable Metrics/ClassLength

require_relative "pagbank/version"
require_relative "pagbank/errors"
require_relative "pagbank/pagbank_configuration"
require_relative "pagbank/singleton"

require 'cgi'
require 'uri'
require 'net/http'
require 'openssl'
require 'json'
require 'forwardable'
require 'logger'
require 'http'

# Seguem as credenciais para utilizarem a API PIX em Sandbox:
# Client ID: cd57dad4-9359-11ec-b909-0242ac120002
# Client Secret: cd57df02-9359-11ec-b909-0242ac120002

# {"error"=>"invalid_token", "error_description"=>"Malformed authorization header"}
# Pagbank module
module Pagbank
  DEFAULT_CA_BUNDLE_PATH = __dir__ + "/data/ca-certificates.crt"

  # # map to the same values as the standard library's logger
  # LEVEL_DEBUG = Logger::DEBUG
  # LEVEL_ERROR = Logger::ERROR
  # LEVEL_INFO = Logger::INFO

  @config = Pagbank::PagbankConfiguration.setup

  class << self
    extend Forwardable

    attr_reader :config

    # user config
    def_delegators :@config, :api_client_id, :api_client_id=
    def_delegators :@config, :api_client_secret, :api_client_secret=
    def_delegators :@config, :api_test_token, :api_test_token=
    def_delegators :@config, :api_version, :api_version=
    def_delegators :@config, :environment, :environment=

    def_delegators :@config, :client_id=, :client_id
    def_delegators :@config, :open_timeout, :open_timeout=
    def_delegators :@config, :read_timeout, :read_timeout=
    def_delegators :@config, :write_timeout, :write_timeout=
    def_delegators :@config, :verify_ssl_certs, :verify_ssl_certs=
    def_delegators :@config, :ca_bundle_path, :ca_bundle_path=
    def_delegators :@config, :log_level, :log_level=
    def_delegators :@config, :logger, :logger=
    def_delegators :@config, :max_network_retries, :max_network_retries=

    # Internal configurations
    # def_delegators :@config, :max_network_retry_delay
    # def_delegators :@config, :initial_network_retry_delay
    # def_delegators :@config, :ca_store
  end

  # # Our Pix integration class
  # class Pix
  #   DEFAULT_HEADERS = {
  #     'Content-Type': 'application/json;encoding=utf-8',
  #     'X-Api-Version': '2',
  #     'Accept': 'application/json',
  #     'Api-SDK': 'jnettome-ruby-pagseguro-v1'
  #   }.freeze
  
  #   API_BASE_URLS = {
  #     'sandbox': 'https://secure.sandbox.api.pagseguro.com/',
  #     'live': 'https://secure.api.pagseguro.com/'
  #   }.freeze

  #   def initialize
  #     logger = Logger.new($stdout)
  #     @certfile = File.read(Pagbank.config.certfile)
  #     @keyfile = File.read(Pagbank.config.keyfile)
  #     @http = HTTP.use(logging: { logger: logger })
  #     @auth = Base64.strict_encode64("#{Pagbank.config.api_client_id}:#{Pagbank.config.api_client_secret}")
  #   end
  
  #   def ssl_context
  #     OpenSSL::SSL::SSLContext.new.tap do |ctx|
  #       ctx.set_params(
  #         verify_mode: OpenSSL::SSL::VERIFY_PEER,
  #         cert: OpenSSL::X509::Certificate.new(@certfile), key: OpenSSL::PKey::RSA.new(@keyfile)
  #       )
  #     end
  #   end
  # end
end

# rubocop:enable Metrics/ClassLength