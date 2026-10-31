# Local TLS fixtures

`localhost-cert.der` and `localhost-key.der` are a self-signed certificate and
test-only RSA key for the loopback servers in `tests/services.rs`. Do not use them
outside tests or add the certificate to a trust store.

Regenerate from this directory:

```sh
openssl req -x509 -newkey rsa:2048 -nodes -keyout test-key.pem -out test-cert.pem \
  -days 3650 -subj /CN=localhost \
  -addext subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1
openssl x509 -in test-cert.pem -outform DER -out localhost-cert.der
openssl pkcs8 -topk8 -nocrypt -in test-key.pem -outform DER -out localhost-key.der
```
