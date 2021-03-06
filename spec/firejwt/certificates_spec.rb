require 'spec_helper'

RSpec.describe FireJWT::Certificates do
  let(:cert) { MockCert.new }

  let! :http_request do
    stub_request(:get, described_class::URL.to_s).to_return(
      status: 200,
      headers: { expires: (Time.now + 3600).httpdate },
      body: cert.to_json,
    )
  end

  it 'inits' do
    expect(subject.expires_at).to be_within(10).of(Time.now + 3600)
    expect(subject).not_to be_expired
    expect(http_request).to have_been_made
  end

  it 'retrieves keys' do
    expect(subject.get('BAD')).to be_nil
    expect(subject.get(cert.kid)).to be_instance_of(OpenSSL::PKey::RSA)
  end

  it 'check/updates expiration status' do
    expect(subject).not_to be_expired
    subject.expire!
    expect(subject).to be_expired
  end
end
