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

on debian, you have to edit `build.zig` and in this part

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

to create x509 cert/server key run this - **ONLY** for testing/demo, in production use real certs/keys!!!!
```
openssl req -new -x509 -key server.der -keyform DER -out cert.pem -days 360
```

set your config in one of these files (later files over-ride earlier locations
in this list):

 - `/etc/sphinx/config`
 - `~/.config/sphinx/config`
 - `~/.sphinxrc`
 - `./sphinx.cfg`
