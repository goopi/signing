# signing

Sign and unsign your data.

## Usage

```ruby
require "signing"
include Signing

signer = Signer.new("secret", "salt")

# sign
signed_value = signer.sign("value")

# unsign
signer.unsign(signed_value) # returns "value"
```

## Installation

Install it using rubygems.

```
$ gem install signing
```

## License

MIT
