# generating seccomp rules

```
git clone https://android.googlesource.com/platform/external/minijail/ /tmp/minijail
cd /tmp/minijail
make constants.json
cd -
cp /tmp/minijail/constants.json .
strace -fo target.strace bin/oracle # and run full pwdsphinx testuite against it
tools/generate_seccomp_policy.py target.strace >target.seccomp
tools/compile_seccomp_policy.py target.seccomp target.bpf
```

it helps if you name your target something like "arch-libcvariant" to make it
recognizable.
