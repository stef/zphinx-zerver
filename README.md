# Zphinx Zerver!

This is an implementation of a sphinx server that you should run in production.

for more info see:
https://github.com/stef/libsphinx and for a reference implementation see:
https://github.com/stef/pwdsphinx/blob/main/pwdsphinx/oracle.py
for testing use the cli client `sphinx.py` from
https://github.com/stef/pwdsphinx/blob/main/pwdsphinx/sphinx.py

Licensed under AGPLv3+

also shouts to https://github.com/MasterQ32/zig-bearssl for the original bearssl bindings

## Building

The git repo's submodules need to be checked out recursively.

You need at least zig 0.7.1 do build this.

You will also need libequihash from: https://github.com/stef/equihash/

Make sure that `libequihash.pc` and `sodium.pc` are available in
`/usr/share/pkgconfig/` since zig seems to not be able to find other
distro-specific directories like `/usr/lib/x86_64-linux-gnu/pkgconfig/`


Clone the repo:

`git clone --recursive https://github.com/stef/zphinx-zerver`

Just run `zig build install --prefix . --release=safe` and be happy.

You might want to give permission to bind to ports below 1024 (if you run this
as recommended on port 433):
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

You must publish the file `ssl_cert.pem` if you use a self-signed certificate, so
that your clients can include it in their configuration.

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

If this is the first time running your oracle, you might want to initialize it
by running:

```
./bin/oracle init
```

This will generate your long-term signing key for the threshold setup. You
**SHOULD** publish either the file containing the public key, or the base64
encoded string representing the public key so that other clients can use your
server in a threshold setup.

In case you want some logging to stdout to feed your favorite daemontools-like
logger run oracle like this:

```
./bin/oracle 2>&1 | /usr/bin/ts
```

## Funding

This project is funded through [NGI0 PET](https://nlnet.nl/PET), a fund
established by [NLnet](https://nlnet.nl) with financial support from the
European Commission's [Next Generation Internet](https://ngi.eu) program. Learn
more at the [NLnet project page](https://nlnet.nl/project/OpaqueSphinxServer).

[<img src="https://nlnet.nl/logo/banner.png" alt="NLnet foundation logo" width="20%" />](https://nlnet.nl)
[<img src="https://nlnet.nl/image/logos/NGI0_tag.svg" alt="NGI Zero Logo" width="20%" />](https://nlnet.nl/PET)

