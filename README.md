# sslshake

Tiny Ruby library to simulate SSL and TLS handshakes. Independent of OpenSSL. Supports SSLv2, SSLv3, TLS 1.0 - 1.2.

## Requirements

* Ruby v1.9.3+

## Usage

```ruby
require 'sslshake'
SSLShake.hello('my.host', port: 4443, protocol: 'tls1.2')
```

## License

MPLv2, see [https://www.mozilla.org/en-US/MPL/2.0/](https://www.mozilla.org/en-US/MPL/2.0/)
