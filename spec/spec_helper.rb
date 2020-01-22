require 'rspec'
require 'firejwt'
require 'webmock/rspec'

WebMock.disable_net_connect!

MOCK_KID = 'e5a91d9f39fa4de254a1e89df00f05b7e248b985'.freeze
MOCK_RSA = OpenSSL::PKey::RSA.new File.read(File.expand_path('../testdata/priv.pem', __dir__))
MOCK_RESPONSE = {
  MOCK_KID => File.read(File.expand_path('../testdata/cert.pem', __dir__)),
}.freeze
