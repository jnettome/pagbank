# frozen-string-literal: true

module Pagbank
  class RequestError < StandardError
    attr_reader :error_body
    def initialize(msg = '[pagbank-error]', error_body = {})
      @error_body = error_body
      super(msg)
    end
  end

  class TransferError < RequestError
    attr_reader :error_body
    def initialize(msg = '[pagbank-error]', error_body = {})
      @error_body = error_body
      super(msg)
    end
  end

  class LimitTransferError < RequestError
    attr_reader :error_body
    def initialize(msg = '[pagbank-error]', error_body = {})
      @error_body = error_body
      super(msg)
    end
  end
end