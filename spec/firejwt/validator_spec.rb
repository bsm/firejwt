require 'spec_helper'

RSpec.describe FireJWT::Validator do
  subject { described_class.new(project_id) }

  let! :http_request do
    stub_request(:get, FireJWT::Certificates::URL.to_s).to_return(
      status: 200,
      headers: { expires: (Time.now + 3600).httpdate },
      body: cert.to_json,
    )
  end

  let :payload do
    now = Time.now.to_i
    {
      'name'           => 'Me',
      'picture'        => 'https://test.host/me.jpg',
      'sub'            => 'MDYwNDQwNjUtYWQ0ZC00ZDkwLThl',
      'user_id'        => 'MDYwNDQwNjUtYWQ0ZC00ZDkwLThl',
      'aud'            => project_id,
      'iss'            => 'https://securetoken.google.com/' << project_id,
      'iat'            => now - 1800,
      'exp'            => now + 3600,
      'auth_time'      => now,
      'email'          => 'me@example.com',
      'email_verified' => true,
      'firebase'       => {
        'sign_in_provider' => 'google.com',
        'identities'       => {
          'google.com' => ['123123123123123123123'],
          'email'      => ['me@example.com'],
        },
      },
    }
  end

  let(:cert)       { MockCert.new }
  let(:project_id) { 'mock-project' }
  let(:token)      { JWT.encode payload, cert.pkey, 'RS256', kid: cert.kid }

  it 'decodes' do
    decoded = subject.decode(token)
    expect(decoded).to be_instance_of(FireJWT::Token)
    expect(decoded).to eq(payload)
    expect(decoded.header).to eq(
      'alg' => 'RS256',
      'kid' => cert.kid,
    )
    expect(http_request).to have_been_made
  end

  it 'rejects bad tokens' do
    expect { subject.decode('BAD') }.to raise_error(JWT::DecodeError)
  end

  it 'verifies exp' do
    payload['exp'] = Time.now.to_i - 1
    expect { subject.decode(token) }.to raise_error(JWT::ExpiredSignature)
  end

  it 'verifies iat' do
    payload['iat'] = Time.now.to_i + 10
    expect { subject.decode(token) }.to raise_error(JWT::InvalidIatError)
  end

  it 'verifies aud' do
    payload['aud'] = 'other'
    expect { subject.decode(token) }.to raise_error(JWT::InvalidAudError)
  end

  it 'verifies iss' do
    payload['iss'] = 'other'
    expect { subject.decode(token) }.to raise_error(JWT::InvalidIssuerError)
  end

  it 'verifies sub' do
    payload['sub'] = ''
    expect { subject.decode(token) }.to raise_error(JWT::InvalidSubError)
  end

  it 'verifies auth_time' do
    payload['auth_time'] = Time.now.to_i + 10
    expect { subject.decode(token) }.to raise_error(FireJWT::InvalidAuthTimeError)
  end
end
