# Zphinx Zerver!

This is an experimental sphinx server. for more info see:
https://github.com/stef/libsphinx and for a reference implementation see:
https://github.com/stef/pwdsphinx/blob/v2-bcrypto/pwdsphinx/oracle.py
for testing use the cli client `sphinx.py` from
https://github.com/stef/pwdsphinx/blob/v2-bcrypto/pwdsphinx/sphinx.py

Licensed under AGPLv3+

also shouts to https://github.com/MasterQ32/zig-bearssl for the original bearssl bindings

## Building

The git repo's submodules need to be checked out recursively.

You need at least zig 0.7.1 do build this.

You will also need libequihash from: https://github.com/stef/equihash/

Make sure that `libequihash.pc` and `sodium.pc` are available in
`/usr/share/pkgconfig/` since zig seems to not be able to find other
distro-specific directories like `/usr/lib/x86_64-linux-gnu/pkgconfig/`

On a musl-based system just run `zig build -Drelease-safe=true` and be happy.

On a production debian system this should work: `zig build install --prefix . -Drelease-safe=true -Dtarget=x86_64-linux-gnu.2.25`

You might want to give permission to bind to ports below 1024:
```
sudo setcap 'cap_net_bind_service=+ep' ./bin/oracle
```

## Running

You could use a docker image provided by
https://github.com/D3vl0per/zphinx-zerver-docker

to create x509 cert/server key run this - **ONLY** for testing/demo, in production use real certs/keys!!!!
```
openssl ecparam -genkey -out ssl_key.pem -name secp384r1
openssl req -new -nodes -x509 -sha256 -key ssl_key.pem -out ssl_cert.pem -days 365 -subj '/CN=localhost'
```
Note currently zphinx only supports ECDSA key material. If other types of keys
are required, uncomment the line containing `c.br_ssl_server_init_full_ec` in
`oracle.zig` - and comment out the following line containing
`...br_ssl_server_init_minf2c(...`.

set your config in one of these files (later files over-ride earlier locations
in this list):

 - `/etc/sphinx/config`
 - `~/.config/sphinx/config`
 - `~/.sphinxrc`
 - `./sphinx.cfg`

In case you want some logging to stdout to feed your favorite daemontools-like
logger run oracle like this:

```
./bin/oracle 2>&1 | /usr/bin/ts
```

