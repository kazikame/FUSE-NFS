# Lab 3

```
Author - Saksham Goel
```

## System Tools

### script / strace

```bash
script session_record
```
The `script` tool saves everything displayed on a terminal, including the commands typed in.

```bash
strace cat - > new_file
```

`strace` lists down all syscalls (w/ arguments) invoked by the process in the arguments.
The trace generated can be summarized as follows:

1. `execve()` is called by the shell to execute `cat`
2. The linker:
    - tries to load (user-provided) `ld.so.preload`, but fails as there isn't one
    - loads `libc.so` and `mmap`s it randomized locations with the right r/w permissions
    - loads `locale-archive`, presumably to memory-map system locales (used by cat? unsure.)
3. cat:
    - calls `fstat(1, S_IFREG)` to check if the (output) file with `fd=1` is a regular file (and not a dir, device, pipe, etc.). This returns with a `0` since `new_file` is indeed a regular file
    - calls `fstat(0, S_IFCHR)` to check if the (input) file with `fd=0`, here `stdin`, is a character device, returning a `0`.
    - calls `fadvise64(0, 0, 0, POSIX_FADV_SEQUENTIAL)`, announcing to the kernel that the program intends to read `stdin` sequentially. 
    - reads "hi mom" from stdin
    - writes "hi mom" to file with `fd=1`

Worth noting that there is no mention of `new_file` here -- the shell automagically maps this file to `fd=1`. The program here doesn't need to know any better.


### lsof

The `lsof` utilities returns the list of all open files belonging to all active processes. Some interesting `/dev/*` files that can be seen:

1. `/dev/null`: Used to write garbage data. The data written cannot be restored.
2. `/dev/ptmx`: The master side of the pseudoterminal, used by the shell process.
3. `/dev/pts/0`: The pseudoterminal slave, which provides an interface of a real terminal and is piped to the master fd as input.

### ifconfig / tcpdump / dhclient

The machine's external interface is named `eno1`.

To capture packets on this interface, we used:

```bash
tcpdump -i eno1 -w packet_file
```
This packet dump can be interpreted using a tool like wireshark.

> Are DHCP messages sent over UDP or TCP?

DHCP uses UDP, since:
1. Messages like DISCOVER are broadcasted to the subnet, which cannot be done via TCP
2. UDP usually has lesser overhead
3. since DHCP messages are usually exchanged between nodes within a few hops, fancy features like reliability and flow control are not required. 

> What is the link-layer (e.g., Ethernet) address of your host?
`14:58:d0:58:xx:xx`

> What is the IP address of your DHCP server?
`128.110.156.4`: taken from wireshark dump

> What is the purpose of the DHCP release message? Does the DHCP server issue an acknowledgment of receipt of the client's DHCP request? What would happen if the client's DHCP release message is lost?

DHCP release, sent by the client, is an optional courtesy message that informs the server to free up the client's IP address as the lease is no longer required. No ACK is sent in response, since this is optional. If this message is lost, the server will not realize that the client is no longer using the assigned IP until the lease expires.

## NFS

### Server Setup

```bash
sudo apt install nfs-kernel-server
sudo mkdir -p /mnt/nfs_share
sudo chown -R nobody:nogroup /mnt/nfs_share/
sudo chmod 777 /mnt/nfs_share/
```

To export `/mnt/nfs_share/` directory, we edit the `/etc/exports` file:

```
/mnt/nfs_share 10.10.1.2/24(rw,sync,no_subtree_check)
```

This gives the entire 10.x.x.x local subnet access to this folder. The config options:
1. `rw` - read/write access
2. `sync` - changes are written to disk before they are applied
3. `no_subtree_check` - subtree_check ensures that clients can't write outside the exported folder. To level playing field with FUSE, we disable it.

Now, restart the nfs server:

```bash
sudo exportfs -a
sudo systemctl restart nfs-kernel-server
```

### Client Setup

```bash
sudo apt install nfs-common
sudo mkdir -p /mnt/nfs_dir # NFS mount point
```

To mount the dir:
```bash
sudo mount 10.10.1.2:/mnt/nfs_share /mnt/nfs_dir
```


To test if everything is working correctly:
```bash
echo "hi mom" > /mnt/nfs_dir/file.txt
```

The new file should be reflected on server.

## FUSE NFS

For setup and install, see [README.md](./README.md).

### Code
All source files are located in the `src/` directory.

| File | Description |
|------|-------------|
| fusenfs.c | Filesystem implementation using FUSE |
| test.c    | Test function as given in Lab 3 |
| nfs_win.c | Experiment where NFS performs better than fusenfs |
| fusenfs_win.c | Experiement where fusenfs performs better than NFS |

### Architecture

We use the `SFTP` protocol -- a file transfer protocol over SSH -- to copy files to and from the server.

We initiate an SFTP connection (over an SSH connection voer a TCP connection) in our implementation of FUSE's init function.
```c++
static void *fusenfs_init(struct fuse_conn_info *conn,
			struct fuse_config *cfg) {
    // ...
    connect(sock, ...);
    // ...

    //! SSH handshake
    libssh2_session_handshake(session, sock);
    // ...
    //! SFTP connection
    libssh2_sftp_init(session);
    // ...
}
```

The keypair must be setup manually before the filesystem is run. The path to key files can be mentioned explicity -- see `./fusenfs -h`.
The server's fingerprint should also be stored at the client.

This connection is teared down when the filesystem exits in `fusenfs_destroy()`.

By default, the `/tmp/` directory on client is used as a local cache to which every file is copied before being operated on.
By default, the `/tmp/fusenfs/` directory on the host is mounted. 

#### Filesystem Operations

| POSIX Operation | fusenfs function | Description |
|-----------------|------------------|-------------|
| `open()`        | `fusenfs_open()` | Checks whether the file exists in the local cache, and otherwise copies it from the server via `sftp_read`. This function does not create a new file. |
| `stat()`        | `fusenfs_getattr()` | Gets all file attributes except the size from the server via sftp. The file size is picked from the cache if available |
| `readdir()`     | `fusenfs_readdir()` | Reads a directory from the server using `sftp_readdir` |
| `creat()`       | `fusenfs_create()`  | Creates a new empty file on the server (using `sftp_creat`) and the local cache |
| `read()`        | `fusenfs_read()`    | Expects the file in local cache. Locally opens the file, reads into the buffer, and closes it |
| `write()`       | `fusenfs_write()`   | Expects the file in local cache. Locally opens the file, writes from the buffer, and closes it. No changes are reflected at the server |
| `truncate()`    | `fusenfs_truncate()`| Truncates the file in local cache. Changes are not flushed to the server |
| `close()`       | `fusenfs_release()` | This function is called after the final `fd` to a file is closed. It flushes the entire file to the server using `sft_write`. |

We do not handle file permissions properly -- writing to a file only opened with read permissions may work.

Since there is no one-to-one mapping of POSIX `close()` with any FUSE operation, every `read()` and `write()` requires opening and closing the file in the local cache.

Other filesystem functions such as `remove()` are not implemented.


## Experiments

We perform the following two experiments (repeated 5 times) to distinguish the performance of two filesystems:


### Case I: Writing to a large file

We setup a large file (~1GB) on the host, open it on the client, and append 100bytes of garbage data to it.

| Filesystem | Time (variance) |
| -----------| --------------- |
| NFS        | 0.008s (0.001) |
| fusenfs    | 11.441s (0.023) |

NFS clearly performs much better than fusenfs. This is expected since fusenfs copies the entire `1GB` file before the append operation, and then copies the entire file back over the network. One the other hand, NFS writes in blocks and only needs to write the last new block (few KBs) instead of the entire file.

Setup instructions can be found in README.md
Code can be found in `nfs_win.c`

### Case II: Creating a large file from scratch

We create a large new file from scratch on the client of size 1GB, writing in chunks of 1MB.

| Filesystem | Time (variance) |
| -----------| --------------- |
| NFS        | 3.167s (0.120) |
| fusenfs    | 1.754s (0.083) |

fusenfs performs almost 2x better than NFS. This makes sense since fusenfs writes all the data to the local cache before flushing it over the network to the host in one go when the `fd` is closed. NFS on the other hand flushes data after every `write()` of 1MB, and hence is unable to use the entire network bandwidth. 
