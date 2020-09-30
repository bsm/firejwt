require 'json'
require 'jwt'
require 'net/http'

module FireJWT
  class InvalidAuthTimeError < JWT::DecodeError; end

  # Validator validates tokens applying guidelines outlined in
  # https://firebase.google.com/docs/auth/admin/verify-id-tokens#verify_id_tokens_using_a_third-party_jwt_library.
  class Validator
    # @param [String] project_id the unique identifier for your Firebase project, which can be found in the URL of that project's console.
    def initialize(project_id)
      project_id = project_id.to_s

      @certs = Certificates.new
      @opts  = {
        algorithms: %w[RS256].freeze,

        # exp must be in the future, iat must be in the past
        verify_expiration: true,
        verify_iat: true,

        # aud must be your Firebase project ID
        verify_aud: true, aud: project_id,

        # iss must be "https://securetoken.google.com/<projectId>"
        verify_iss:  true, iss: "https://securetoken.google.com/#{project_id}",
      }
    end

    # @param [String] token the token string
    # @return [FireJWT::Token] the token
    # @raises [JWT::DecodeError] validation errors
    def decode(token)
      payload, header = JWT.decode token, nil, true, **@opts do |header|
        @certs.get(header['kid'])
      end

      # sub must be a non-empty string
      sub = payload['sub']
      raise(JWT::InvalidSubError, 'Invalid subject. Expected non-empty string') unless sub.is_a?(String) && !sub.empty?

      # auth_time must be in the past
      aut = payload['auth_time']
      raise(InvalidAuthTimeError, 'Invalid auth_time') if !aut.is_a?(Numeric) || aut.to_f > Time.now.to_f

      Token.new(payload, header)
    end
  end
end
