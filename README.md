# README

## Build and Run

```bash
mkdir build && cd build
cmake ..
make
```

To run:

```bash
./fusenfs <mountpoint>
```

For usage options: `./fusenfs -h`
The host's directory being used (may be specified using the `--host-mp=<path-on-host>` option) must already exist.

To stop:

```bash
fusermount -u <mountpoint>
```

## Requirements

pkg-config
fuse >= 3
libssh2

server must be a **known host**
server must have `/tmp/fusenfs/` dir with appropriate permissions

## Experiments

### Case I: Large File / Small Write

#### Setup

1. On server:

Add a large file in the mounted directory using the following command
```bash
rm newfile
dd if=/dev/urandom of=newfile bs=1M count=1024 # 1GiB file
```

#### Run

On client:

```bash
cd <mountpoint>
time <path-to-build>/nfs_better
```

#### Results
1. Time by fusenfs: **11.442s**
2. Time by NFS: **0.008s**

### Case II: New File / Large Write

#### Run

On client:

```bash
cd <mountpoint>
time <path-to-build>/fusenfs_better
```

#### Results
1. Time by fusenfs: **1.754s**
2. Time by NFS: **3.167s**

## Gotchas
1. Must give full path in options
2. The local cache directory should be empty before opening