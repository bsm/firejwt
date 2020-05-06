require 'json'
require 'jwt'
require 'net/http'

module FireJWT
  class Validator
    # @param [Hash] opts
    # @option opts [String] :algorithm the expected algorithm. Default: RS256.
    # @option opts [String] :aud verify the audience claim against the given value. Default: nil (= do not validate).
    # @option opts [String] :iss verify the issuer claim against the given value. Default: nil (= do not verify).
    # @option opts [String] :sub verify the subject claim against the given value. Default: nil (= do not verify).
    # @option opts [Boolean] :verify_iat verify the issued at claim. Default: false.
    # @option opts [Integer] :exp_leeway expiration leeway in seconds. Default: none.
    def initialize(**opts)
      @defaults = opts.dup
      @keys = KeySet.new
    end

    # @param [String] token the token string
    # @param [Hash] opts options
    # @option opts [Boolean] :allow_expired allow expired tokens. Default: false.
    # @option opts [String] :algorithm the expected algorithm. Default: RS256.
    # @option opts [String] :aud verify the audience claim against the given value. Default: nil (= do not validate).
    # @option opts [String] :iss verify the issuer claim against the given value. Default: nil (= do not verify).
    # @option opts [String] :sub verify the subject claim against the given value. Default: nil (= do not verify).
    # @option opts [Boolean] :verify_iat verify the issued at claim. Default: false.
    # @option opts [Integer] :exp_leeway expiration leeway in seconds. Default: none.
    # @return [FireJWT::Token] the token
    # @raises [JWT::DecodeError] validation errors
    def decode(token, allow_expired: false, **opts)
      opts = norm_opts(@defaults.merge(opts))
      payload, header = JWT.decode token, nil, !allow_expired, opts do |header|
        @keys.get(header['kid'])
      end
      Token.new(payload, header)
    end

    private

    def norm_opts(opts)
      opts[:verify_aud] = opts.key?(:aud) unless opts.key?(:verify_aud)
      opts[:verify_iss] = opts.key?(:iss) unless opts.key?(:verify_iss)
      opts[:verify_sub] = opts.key?(:sub) unless opts.key?(:verify_sub)
      opts[:algorithm] ||= 'RS256'
      opts
    end
  end
end
