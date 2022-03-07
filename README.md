# README

## Requirements

fuse >= 3
libssh2

server must be a **known host**
server must have `/tmp/fusenfs/` dir with rw perms

```bash
gcc -Wall nfs.c `pkg-config fuse3 --cflags --libs` -lssh2 -o hello
```

## Experiments

1. opening a LARGE file, writing on a small block
2. opening a new file, writing A LOT

## Details
1. flushed back only on release -- when no more fds
2. cannot intercept close -- can't open a file
3. truncate can be called on an unopen file????
    - no.