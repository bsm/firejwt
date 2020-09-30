require 'rspec'
require 'firejwt'
require 'webmock/rspec'

WebMock.disable_net_connect!

class MockCert
  attr_reader :cert, :pkey

  def initialize
    @pkey = OpenSSL::PKey::RSA.new 2048
    @cert = OpenSSL::X509::Certificate.new
    @cert.version = 2
    @cert.serial = 2605014480174073526
    @cert.subject = OpenSSL::X509::Name.parse('/CN=securetoken.system.gserviceaccount.com')
    @cert.issuer = @cert.subject
    @cert.public_key = @pkey.public_key
    @cert.not_before = Time.now
    @cert.not_after = @cert.not_before + 3600

    exts = OpenSSL::X509::ExtensionFactory.new
    exts.subject_certificate = cert
    exts.issuer_certificate = cert
    @cert.add_extension(exts.create_extension('basicConstraints', 'CA:FALSE', true))
    @cert.add_extension(exts.create_extension('keyUsage', 'Digital Signature', true))
    @cert.add_extension(exts.create_extension('extendedKeyUsage', 'TLS Web Client Authentication', true))
    @cert.sign(@pkey, OpenSSL::Digest.new('SHA256'))
  end

  def kid
    @kid ||= Digest::SHA1.hexdigest(@cert.to_der)
  end

  def to_json(*)
    { kid => @cert }.to_json
  end
end
