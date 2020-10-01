module FireJWT
  autoload :Certificates, 'firejwt/certificates'
  autoload :Validator, 'firejwt/validator'

  class Token < Hash
    attr_reader :header

    def initialize(payload, header)
      super()
      update(payload)
      @header = header
    end
  end
end
