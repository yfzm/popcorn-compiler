/usr/local/popcorn/aarch64/bin/musl-clang -o sd self-dump.c -static -v
scp sd arm:~
