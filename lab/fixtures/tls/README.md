# Lab TLS fixture

This lab-only CA and leaf certificate are used by the isolated HTTP/2 and HTTP/3
sandbox suites. They are not secrets, are not trusted outside the lab, and must
not be reused for a real listener. `cert.pem` is the leaf for `app.test`,
`localhost`, and `127.0.0.1`; `ca.pem` is the trust anchor used by the HTTP/3
probe. The HTTP/2 Python client disables certificate verification.

Regenerate the fixture when it expires:

```sh
openssl req -x509 -newkey rsa:2048 -nodes -keyout /tmp/ca-key.pem \
  -out lab/fixtures/tls/ca.pem -days 3650 -subj "/CN=kunato-lab-ca" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"
openssl req -newkey rsa:2048 -nodes -keyout lab/fixtures/tls/key.pem \
  -out /tmp/leaf.csr -subj "/CN=app.test" \
  -addext "subjectAltName=DNS:app.test,DNS:localhost,IP:127.0.0.1"
printf 'subjectAltName=DNS:app.test,DNS:localhost,IP:127.0.0.1\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n' > /tmp/leaf.ext
openssl x509 -req -in /tmp/leaf.csr -CA lab/fixtures/tls/ca.pem \
  -CAkey /tmp/ca-key.pem -CAcreateserial -out lab/fixtures/tls/cert.pem \
  -days 3650 -extfile /tmp/leaf.ext
chmod 644 lab/fixtures/tls/ca.pem lab/fixtures/tls/cert.pem lab/fixtures/tls/key.pem
```
