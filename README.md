# Zphinx Zerver!

This is an experimental sphinx server. for more info see:
https://github.com/stef/libsphinx and for a reference implementation see:
https://github.com/stef/pwdsphinx/blob/v2-bcrypto/pwdsphinx/oracle.py
for testing use the cli client `sphinx.py` from
https://github.com/stef/pwdsphinx/blob/v2-bcrypto/pwdsphinx/sphinx.py

to create x509 cert/server key run this - **ONLY** for testing/demo, in production use real certs/keys!!!!
```
openssl req -new -x509 -key server.der -keyform DER -out cert.pem -days 360
```

Licensed under AGPLv3+

also shouts to https://github.com/MasterQ32/zig-bearssl for the original bearssl bindings
