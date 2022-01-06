#!/usr/bin/env bash

# invoke with sbox.sh path/oracle path/sphinx.cfg path/seccomp.bpf
# notice: wordexp will not work in the jail, since at least musl actually exec /bin/sh to eval a printf
# also important the cfg file must not use spaces around the = signs, otherwise sourcing it will fail
# during sourcing the cfg file there is one error/warning regarding [server] which can be ignored
# seccomp.bpf can be generated by following the steps in seccomp/README.md

libs=$(ldd "$1" | fgrep -v linux-vdso.so | sed 's;.*\s\(/[^ ]*\) (0x[0-9a-f]*)$;\1;' | sort -u)
libdirs=$(echo "$libs" | sed 's;\(/.*/\).*;\1;' | sort -u)
mkdirs=$(echo "$libdirs" | sed 's;\(.*\);--dir \1;')
libinds=$(echo "$libs" | sed 's;\(.*\);--ro-bind \1 \1;')

source "$2" 2>/dev/null

# clear environment
env -i \
bwrap --unshare-all \
      --share-net \
      --hostname zphinx \
      --ro-bind "$1" /oracle \
      --file 0 /sphinx.cfg \
      --bind "$datadir" /data \
      --ro-bind "$ssl_cert" /cert.pem \
      --ro-bind "$ssl_key" /key.pem \
      $mkdirs $libinds \
      --seccomp 11 11<$3 \
      --chdir / \
      /oracle <<EOCFG
[server]
ssl_key="key.pem"
ssl_cert="cert.pem"
port=${port:-2355}
address="${address:-::}"
timeout=${timeout:-3}
datadir="${datadir:-data}"
max_kids=${max_kids:-5}
verbose=${verbose:-false}
rl_decay=${rl_decay:-1800}
rl_threshold=${rl_threshold:-1}
rl_gracetime=${rl_gracetime:-10}
EOCFG
