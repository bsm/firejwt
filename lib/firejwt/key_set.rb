require 'time'
require 'json'
require 'uri'
require 'openssl'

module FireJWT
  class KeySet < Hash
    URL = 'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com'.freeze

    attr_reader :expires_at

    def initialize(url: URL)
      super()

      @url = URI(url)
      expire!
      refresh!
    end

    def get(key)
      refresh! if expired?
      self[key]
    end

    def refresh!(limit = 5)
      resp = Net::HTTP.get_response(@url)
      unless resp.is_a?(Net::HTTPOK)
        raise "Server responded with #{resp.code}" if limit < 1

        refresh!(limit - 1)
      end

      raise ArgumentError, 'Expires header not included in the response' unless resp['expires']

      @expires_at = Time.httpdate(resp['expires'])
      JSON.parse(resp.body).each do |kid, cert|
        store kid, OpenSSL::X509::Certificate.new(cert).public_key
      end
    end

    def expire!
      @expires_at = Time.at(0)
    end

    def expired?
      @expires_at < Time.now
    end

    def expires_soon?
      @expires_at < (Time.now + 600)
    end
  end
end
