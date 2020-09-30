require 'spec_helper'

RSpec.describe FireJWT::Validator do
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

  subject          { described_class.new(project_id) }

  it 'should decode' do
    decoded = subject.decode(token)
    expect(decoded).to be_instance_of(FireJWT::Token)
    expect(decoded).to eq(payload)
    expect(decoded.header).to eq(
      'alg' => 'RS256',
      'kid' => cert.kid,
    )
  end

  it 'should reject bad tokens' do
    expect { subject.decode('BAD') }.to raise_error(JWT::DecodeError)
  end

  it 'should verify exp' do
    payload['exp'] = Time.now.to_i - 1
    expect { subject.decode(token) }.to raise_error(JWT::ExpiredSignature)
  end

  it 'should verify iat' do
    payload['iat'] = Time.now.to_i + 10
    expect { subject.decode(token) }.to raise_error(JWT::InvalidIatError)
  end

  it 'should verify aud' do
    payload['aud'] = 'other'
    expect { subject.decode(token) }.to raise_error(JWT::InvalidAudError)
  end

  it 'should verify iss' do
    payload['iss'] = 'other'
    expect { subject.decode(token) }.to raise_error(JWT::InvalidIssuerError)
  end

  it 'should verify sub' do
    payload['sub'] = ''
    expect { subject.decode(token) }.to raise_error(JWT::InvalidSubError)
  end

  it 'should verify auth_time' do
    payload['auth_time'] = Time.now.to_i + 10
    expect { subject.decode(token) }.to raise_error(FireJWT::InvalidAuthTimeError)
  end
end
