require 'time'
require 'json'
require 'uri'
require 'openssl'

module FireJWT
  class Certificates
    URL = 'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com'.freeze

    attr_reader :expires_at

    def initialize(url: URL)
      super()

      @url  = URI(url)
      @keys = {}

      expire!
      refresh!
    end

    def get(kid)
      refresh! if expired?

      @keys[kid]
    end

    def refresh!(limit = 5)
      resp = Net::HTTP.get_response(@url)
      unless resp.is_a?(Net::HTTPOK)
        raise "Server responded with #{resp.code}" if limit < 1

        refresh!(limit - 1)
      end

      raise ArgumentError, 'Expires header not included in the response' unless resp['expires']

      @expires_at = Time.httpdate(resp['expires'])
      @keys.clear

      JSON.parse(resp.body).each do |kid, pem|
        cert = OpenSSL::X509::Certificate.new(pem)
        @keys.store kid, cert.public_key
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
