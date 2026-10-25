# Lab TLS fixture

This self-signed certificate is used only by the isolated HTTP/2 sandbox suite.
It is not a secret, is not trusted outside the lab, and must not be reused for a
real listener. The client disables certificate verification and the certificate
covers `app.test`, `localhost`, and `127.0.0.1`.

Regenerate the fixture when it expires:

```sh
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout lab/fixtures/tls/key.pem -out lab/fixtures/tls/cert.pem \
  -days 3650 -subj "/CN=app.test" \
  -addext "subjectAltName=DNS:app.test,DNS:localhost,IP:127.0.0.1"
chmod 644 lab/fixtures/tls/cert.pem lab/fixtures/tls/key.pem
```
