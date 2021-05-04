# FireJWT

[![Test](https://github.com/bsm/firejwt/actions/workflows/test.yml/badge.svg)](https://github.com/bsm/firejwt/actions/workflows/test.yml)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Decode and validate [Google Firebase](https://firebase.google.com/) JWT tokens with [Ruby](https://www.ruby-lang.org/) and [Go](https://golang.org/).

## Usage

**Ruby**:

```ruby
require 'firejwt'

# Init a validator
validator = FireJWT::Validator.new 'my-project'

# Decode a token
token = begin
  validator.decode('eyJh...YbQ') # => {'sub' => 'me@example.com', 'aud' => 'my-project'}
rescue JWT::DecodeError
  nil
end
```

**Go**:

```go
package main

import (
  "log"

  "github.com/bsm/firejwt"
)

func main() {
  vr, err := firejwt.New("my-project")
  if err != nil {
    log.Fatalln(err)
  }
  defer vr.Stop()

  tk, err := vr.Decode("eyJh...YbQ")
  if err != nil {
    log.Fatalln(err)
  }

  log.Println(tk.Claims) // => {"sub": "me@example.com", "aud": "my-project"}
}
```
