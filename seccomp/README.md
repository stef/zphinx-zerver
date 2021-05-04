# generating seccomp rules

```
strace -fo target.strace bin/oracle # and run full pwdsphinx testuite against it
tools/generate_seccomp_policy.py target.strace >target.seccomp
tools/compile_seccomp_policy.py target.seccomp target.bpf
```

it helps if you name your target something like "arch-libcvariant" to make it
recognizable.
