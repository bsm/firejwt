Gem::Specification.new do |s|
  s.name          = 'firejwt'
  s.version       = '0.3.1'
  s.authors       = ['Black Square Media Ltd']
  s.email         = ['info@blacksquaremedia.com']
  s.summary       = %(Firebase JWT validation)
  s.description   = %()
  s.homepage      = 'https://github.com/bsm/firejwt'
  s.license       = 'Apache-2.0'

  s.files         = `git ls-files -z`.split("\x0").reject {|f| f.match(%r{^spec/}) }
  s.test_files    = `git ls-files -z -- spec/*`.split("\x0")
  s.require_paths = ['lib']
  s.required_ruby_version = '>= 2.5'

  s.add_dependency 'jwt'
  s.add_development_dependency 'rake'
  s.add_development_dependency 'rspec'
  s.add_development_dependency 'rubocop-bsm'
  s.add_development_dependency 'webmock'
end
