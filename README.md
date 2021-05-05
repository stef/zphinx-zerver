# Zphinx Zerver!

This is an experimental sphinx server. for more info see:
https://github.com/stef/libsphinx and for a reference implementation see:
https://github.com/stef/pwdsphinx/blob/v2-bcrypto/pwdsphinx/oracle.py
for testing use the cli client `sphinx.py` from
https://github.com/stef/pwdsphinx/blob/v2-bcrypto/pwdsphinx/sphinx.py

Licensed under AGPLv3+

also shouts to https://github.com/MasterQ32/zig-bearssl for the original bearssl bindings

## Building

You need at least zig 0.7.1 do build this.

if you get errors complaining about missing `sodium.h` apply the `sphinx.patch`
in the sphinx submodule.

on a musl-based system just run `zig build -Drelease-safe=true` and be happy.

on debian or other glibc-based systems due to
https://github.com/ziglang/zig/issues/6469, you might have to edit `build.zig` and in this part

```
    // on normal systems this is ok:
    exe.linkSystemLibrary("sodium");
    // on debian, you have to do this:
    // exe.addObjectFile("/usr/lib/x86_64-linux-gnu/libsodium.a");
```

Set the correct path to your static libsodium lib and uncomment this line.
While you have to comment out the line containing:

```
    exe.linkSystemLibrary("sodium");
```

so that the result looks like this:

```
    // on normal systems this is ok:
    // exe.linkSystemLibrary("sodium");
    // on debian, you have to do this:
    exe.addObjectFile("/usr/lib/x86_64-linux-gnu/libsodium.a");
```

finally you need to run `zig build -Drelease-safe=true -Dtarget=x86_64-linux-gnu.2.25`

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
