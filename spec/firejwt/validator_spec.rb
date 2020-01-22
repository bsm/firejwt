require 'spec_helper'

RSpec.describe FireJWT::Validator do
  let! :keys_request do
    stub_request(:get, FireJWT::KeySet::URL.to_s).to_return(
      status: 200,
      headers: { expires: (Time.now + 3600).httpdate },
      body: MOCK_RESPONSE.to_json,
    )
  end

  let :exp_time do
    Time.now.to_i + 3600
  end

  let :token do
    payload = {
      sub: 'me@example.com',
      aud: 'you',
      iss: 'me',
      exp: exp_time,
    }
    JWT.encode payload, MOCK_RSA, 'RS256', kid: MOCK_KID
  end

  it 'should decode' do
    decoded = subject.decode(token)
    expect(decoded).to be_instance_of(FireJWT::Token)
    expect(decoded).to eq(
      'sub' => 'me@example.com',
      'aud' => 'you',
      'iss' => 'me',
      'exp' => exp_time,
    )
    expect(decoded.header).to eq(
      'alg' => 'RS256',
      'kid' => 'e5a91d9f39fa4de254a1e89df00f05b7e248b985',
    )
  end

  it 'should reject bad tokens' do
    expect { subject.decode('BAD') }.to raise_error(JWT::DecodeError)
  end

  it 'should verify audiences' do
    expect(subject.decode(token, aud: 'you')).to be_instance_of(FireJWT::Token)
    expect { subject.decode(token, aud: 'other') }.to raise_error(JWT::InvalidAudError)
  end

  it 'should verify issuers' do
    expect(subject.decode(token, iss: 'me')).to be_instance_of(FireJWT::Token)
    expect { subject.decode(token, iss: 'other') }.to raise_error(JWT::InvalidIssuerError)
  end

  it 'should verify subjects' do
    expect(subject.decode(token, sub: 'me@example.com')).to be_instance_of(FireJWT::Token)
    expect { subject.decode(token, sub: 'other') }.to raise_error(JWT::InvalidSubError)
  end
end
