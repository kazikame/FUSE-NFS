/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>
  This program can be distributed under the terms of the GNU GPLv2.
  See the file COPYING.
*/

/** @file
 *
 * minimal example filesystem using high-level API
 *
 * Compile with:
 *
 *     gcc -Wall hello.c `pkg-config fuse3 --cflags --libs` -o hello
 *
 * ## Source code ##
 * \include hello.c
 */


#define FUSE_USE_VERSION 31
#define MAX_FILEPATH_LENGTH 4096
#define CHUNK_SIZE 4 * 1024 * 1024

#define OPEN_FLAG 1

#include <fuse3/fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <assert.h>

//! Libssh2 headers
#include <libssh2.h>
#include <libssh2_sftp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/time.h>

#include <sys/types.h>
#include <ctype.h>

/*
 * Command line options
 *
 * We can't set default values for the char* fields here because
 * fuse_opt_parse would attempt to free() them when the user specifies
 * different values on the command line.
 */
static struct options {
    const char *username;
    const char *host;
    const char *pubkeyfile;
    const char *privkeyfile;
    const char *host_mp;
    const char *tmp_dir;
	int show_help;
} options;

/**
 * @brief sftp state
 * 
 */
static struct sftp_state {
    int sock;
    LIBSSH2_SESSION *session;
    LIBSSH2_SFTP *sftp_session;
    const char *fingerprint;
} sftp_state = {0, NULL, NULL, NULL};

#define OPTION(t, p)                           \
    { t, offsetof(struct options, p), 1 }
static const struct fuse_opt option_spec[] = {
    OPTION("--user=%s", username),
    OPTION("--host-ip=%s", host),
    OPTION("--pubkey=%s", pubkeyfile),
    OPTION("--privkey=%s", privkeyfile),
    OPTION("--host-mountpoint=%s", host_mp),
    OPTION("--tmp-dir=%s", tmp_dir),
	OPTION("-h", show_help),
	OPTION("--help", show_help),
	FUSE_OPT_END
};

static void *fusenfs_init(struct fuse_conn_info *conn,
			struct fuse_config *cfg)
{
	(void) conn;
	// cfg->kernel_cache = 0;

    //! Connect!
    fprintf(stderr, "hi mom\n");
    int rc = libssh2_init(0);
    if (rc != 0) {
        fprintf(stderr, "libssh init failed %d\n", rc);
        _exit(1);
    }

    sftp_state.sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(22);
    sin.sin_addr.s_addr = inet_addr(options.host);
    if(connect(sftp_state.sock, (struct sockaddr*)(&sin),
               sizeof(struct sockaddr_in)) != 0) {
        fprintf(stderr, "failed to connect!\n");
        _exit(2);
    }

    sftp_state.session = libssh2_session_init();
    if(!sftp_state.session) {
        fprintf(stderr, "libssh2 session init failed!\n");
        _exit(3);
    }

    //! TODO: This doesn't seem right for performance
    libssh2_session_set_blocking(sftp_state.session, 1);

    rc = libssh2_session_handshake(sftp_state.session, sftp_state.sock);
    if(rc) {
        fprintf(stderr, "Failure establishing SSH session: %d\n", rc);
        _exit(4);
    }

    sftp_state.fingerprint = libssh2_hostkey_hash(sftp_state.session, LIBSSH2_HOSTKEY_HASH_SHA1);
    fprintf(stderr, "Fingerprint: ");
    for(int i = 0; i < 20; i++) {
        fprintf(stderr, "%02X ", (unsigned char)sftp_state.fingerprint[i]);
    }
    fprintf(stderr, "\n");

    if(libssh2_userauth_publickey_fromfile(sftp_state.session, options.username, options.pubkeyfile,
                                               options.privkeyfile, "")) {
        fprintf(stderr, "\tAuthentication by public key failed!\n");
        goto shutdown;
    } else {
        fprintf(stderr, "\tAuthentication by public key succeeded.\n");
    }

    sftp_state.sftp_session = libssh2_sftp_init(sftp_state.session);
    if(!sftp_state.sftp_session) {
        fprintf(stderr, "Unable to init SFTP session\n");
        goto shutdown;
    }
	return NULL;

shutdown:
    libssh2_session_disconnect(sftp_state.session, "Normal Shutdown");
    libssh2_session_free(sftp_state.session);
    close(sftp_state.sock);
    libssh2_exit();
    return NULL;
}

static int fusenfs_getattr(const char *path, struct stat *stbuf,
			 struct fuse_file_info *fi)
{
	(void) fi;
    //! Check if file has already been cached locally
    char cache_fp[MAX_FILEPATH_LENGTH] = "";
    strcat(cache_fp, options.tmp_dir);
    strcat(cache_fp, path);
    if(access(cache_fp, F_OK) == 0) {
        // not cached
        return stat(cache_fp, stbuf);
    }
    char filepath[MAX_FILEPATH_LENGTH] = "";
    strcat(filepath, options.host_mp);
    strcat(filepath, path);

    //! TODO: Handle the case when file is already in cache
    LIBSSH2_SFTP_ATTRIBUTES attrs;
    int rc = libssh2_sftp_stat(sftp_state.sftp_session, filepath, &attrs);
    if (rc != 0) {
        fprintf(stderr, "sftp_stat failed (%s %d)\n", filepath, rc);
        return -ENOENT;
    }

    //! Parse stats
	memset(stbuf, 0, sizeof(struct stat));
    if (attrs.flags & LIBSSH2_SFTP_ATTR_SIZE) {
        stbuf->st_size = attrs.filesize;
    }
    if (attrs.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS) {
        stbuf->st_mode = attrs.permissions;
    }

	return 0;
}

static int fusenfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			 off_t offset, struct fuse_file_info *fi,
			 enum fuse_readdir_flags flags)
{
	(void) offset;
	(void) fi;
	(void) flags;

    char filepath[MAX_FILEPATH_LENGTH] = "";
    strcat(filepath, options.host_mp);
    strcat(filepath, path);
    // fprintf(stderr, "dir %s\n", filepath);

    LIBSSH2_SFTP_HANDLE* fh = libssh2_sftp_opendir(sftp_state.sftp_session, filepath);
    if (!fh) {
        fprintf(stderr, "could not find dir %s\n", filepath);
        return -ENOENT;
    }

    char filedata[512] = "";
    LIBSSH2_SFTP_ATTRIBUTES attrs;
    while (libssh2_sftp_readdir(fh, filedata, 512, &attrs) > 0) 
    {
        //! TODO: fill attributes maybe?
        filler(buf, filedata, NULL, 0, 0);
    }

    libssh2_sftp_closedir(fh);

	return 0;
}

static int cache_file(const char *path, const char *cache_path, int create) 
{
    fprintf(stderr, "Caching File %s %s\n", path, cache_path);
    int flags = LIBSSH2_FXF_READ;
    if (create) {
        flags |= LIBSSH2_FXF_CREAT;
    }

    LIBSSH2_SFTP_HANDLE* fh = libssh2_sftp_open(sftp_state.sftp_session, path, flags, LIBSSH2_SFTP_S_IRWXU | LIBSSH2_SFTP_S_IRWXG | LIBSSH2_SFTP_S_IRWXO);
    if (!fh) {
        return -ENOENT;
    }

    //! Open file
    int fd = creat(cache_path, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

    char* buf = (char*)malloc(CHUNK_SIZE);
    if (!buf) return -ENOMEM;
    int num_bytes = 0;
    while ((num_bytes = libssh2_sftp_read(fh, buf, CHUNK_SIZE)) > 0) 
    {
        int bytes_written = 0;
        while (bytes_written != num_bytes) {
            bytes_written += write(fd, buf + bytes_written, num_bytes - bytes_written);
        }
    }
    free(buf);
    libssh2_sftp_close(fh);
    close(fd);

    if (num_bytes < 0) {
        fprintf(stderr, "Error while reading %d\n", num_bytes);
    }
    
    return num_bytes;
}

static int fusenfs_create(const char * path, mode_t mode, struct fuse_file_info *fi)
{
    //! Check if file has already been cached locally
    char cache_fp[MAX_FILEPATH_LENGTH] = "";
    strcat(cache_fp, options.tmp_dir);
    strcat(cache_fp, path);

    char filepath[MAX_FILEPATH_LENGTH] = "";
    strcat(filepath, options.host_mp);
    strcat(filepath, path);

    if(!access(cache_fp, F_OK) == 0) {
        // not cached
        int rc = cache_file(filepath, cache_fp, 1);
        if (rc < 0) return rc;
    }

    // int fd = open(cache_fp, fi->flags);

    // if (fd < 0) return fd;

    fi->fh = OPEN_FLAG;

	return 0;
}

static int fusenfs_open(const char *path, struct fuse_file_info *fi)
{
    //! Check if file has already been cached locally
    char cache_fp[MAX_FILEPATH_LENGTH] = "";
    strcat(cache_fp, options.tmp_dir);
    strcat(cache_fp, path);

    char filepath[MAX_FILEPATH_LENGTH] = "";
    strcat(filepath, options.host_mp);
    strcat(filepath, path);

    if(access(cache_fp, F_OK) != 0) {
        // not cached
        int rc = cache_file(filepath, cache_fp, 0);
        if (rc < 0) return rc;   
    }
    // int fd = open(cache_fp, fi->flags);

    // if (fd < 0) return fd;

    fi->fh = OPEN_FLAG;

	return 0;
}

static int fusenfs_read(const char *path, char *buf, size_t size, off_t offset,
		      struct fuse_file_info *fi)
{
	(void) fi;

    char cache_fp[MAX_FILEPATH_LENGTH] = "";
    strcat(cache_fp, options.tmp_dir);
    strcat(cache_fp, path);

    //! TODO: this is just sad. Each read requires opening (and closing) a file. :(
    int fd = open(cache_fp, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "read: open cache_fp failed %s %d\n", cache_fp, fd);
        return fd;
    }
    lseek(fd, offset, SEEK_SET);

    int rc = read(fd, buf, size);
    fprintf(stderr, "read: bytes %d (%ld)\n", rc, size);
    close(fd);

    return rc;
}

static int fusenfs_write(const char *path, const char *buf, size_t size, off_t offset,
		      struct fuse_file_info *fi)
{
	(void) fi;

    char cache_fp[MAX_FILEPATH_LENGTH] = "";
    strcat(cache_fp, options.tmp_dir);
    strcat(cache_fp, path);

    //! TODO: this is just sad. Each read requires opening (and closing) a file. :(
    int fd = open(cache_fp, O_WRONLY);
    if (fd < 0) {
        fprintf(stderr, "write: open cache_fp failed %s %d\n", cache_fp, fd);
        return fd;
    }
    lseek(fd, offset, SEEK_SET);

    int rc = write(fd, buf, size);
    close(fd);

    return rc;
}

static int fusenfs_truncate(const char *path, off_t offset,
		      struct fuse_file_info *fi)
{
    //! NOTE: Assumes that the file is **already open**.
    char cache_fp[MAX_FILEPATH_LENGTH] = "";
    strcat(cache_fp, options.tmp_dir);
    strcat(cache_fp, path);

    int rc = truncate(path, offset);
    return rc;
}

static void fusenfs_destroy(void *private_data)
{
    libssh2_sftp_shutdown(sftp_state.sftp_session);
    libssh2_session_disconnect(sftp_state.session, "Normal Shutdown");
    libssh2_session_free(sftp_state.session);
    close(sftp_state.sock);
    fprintf(stderr, "all done\n");
    libssh2_exit();
}

//! TODO: Flush file back to NFS
static int fusenfs_release(const char *path, struct fuse_file_info * fi)
{
    fprintf(stderr, "releasing %s\n", path);
    if (((fi->flags & O_RDWR) == 0) && ((fi->flags & O_WRONLY) == 0)) {
        fprintf(stderr, "readonly %s\n", path);
        return 0;
    }

    char filepath[MAX_FILEPATH_LENGTH] = "";
    strcat(filepath, options.host_mp);
    strcat(filepath, path);

    LIBSSH2_SFTP_HANDLE* fh = libssh2_sftp_open(sftp_state.sftp_session, filepath, LIBSSH2_FXF_WRITE, 0);
    if (!fh) {
        return -ENOENT;
    }

    char cache_fp[MAX_FILEPATH_LENGTH] = "";
    strcat(cache_fp, options.tmp_dir);
    strcat(cache_fp, path);

    int fd = open(cache_fp, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "release: open cache_fp failed %s %d\n", cache_fp, fd);
        return fd;
    }

    char* buf = (char*)malloc(CHUNK_SIZE);
    int num_bytes = 0;
    while ((num_bytes = read(fd, buf, CHUNK_SIZE)) > 0) {
        int bytes_written = 0;
        while (bytes_written != num_bytes) {
            bytes_written += libssh2_sftp_write(fh, buf + bytes_written, num_bytes - bytes_written);
            fprintf(stderr, "Bytes written: %d\n", bytes_written);
        }
    }
    if (num_bytes < 0) {
        fprintf(stderr, "release: num_bytes read is negative %d\n", num_bytes);
    }

    free(buf);
    libssh2_sftp_close(fh);
    close(fd);

    if (num_bytes < 0) {
        fprintf(stderr, "Error while releasing %d\n", num_bytes);
    }
    
    return num_bytes;
}

static const struct fuse_operations fusenfs_oper = {
	.init       = fusenfs_init,
	.getattr	= fusenfs_getattr,
	.readdir	= fusenfs_readdir,
    .create     = fusenfs_create,
	.open		= fusenfs_open,
	.read		= fusenfs_read,
    .write      = fusenfs_write,
    .truncate   = fusenfs_truncate,
    .release    = fusenfs_release,
    .destroy    = fusenfs_destroy
};

static void show_help(const char *progname)
{
    //! TODO: Complete this
	printf("usage: %s [options] <mountpoint>\n\n", progname);
	printf("File-system specific options:\n"
	       "    --name=<s>          Name of the \"hello\" file\n"
	       "                        (default: \"hello\")\n"
	       "    --contents=<s>      Contents \"hello\" file\n"
	       "                        (default \"Hello, World!\\n\")\n"
	       "\n");
}

//! TODO: Store in a sep tmp dir
int main(int argc, char *argv[])
{
	int ret;
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

	/* Set defaults -- we have to use strdup so that
	   fuse_opt_parse can free the defaults if other
	   values are specified */
    options.host = strdup("10.10.1.2");
    options.username = strdup("sg99");
    options.pubkeyfile = strdup("/users/sg99/.ssh/id_rsa.pub");
    options.privkeyfile = strdup("/users/sg99/.ssh/id_rsa");
    options.host_mp = strdup("/tmp/fusenfs/");
    options.tmp_dir = strdup("/tmp/");

	/* Parse options */
	if (fuse_opt_parse(&args, &options, option_spec, NULL) == -1)
		return 1;

	/* When --help is specified, first print our own file-system
	   specific help text, then signal fuse_main to show
	   additional help (by adding `--help` to the options again)
	   without usage: line (by setting argv[0] to the empty
	   string) */
	if (options.show_help) {
		show_help(argv[0]);
		assert(fuse_opt_add_arg(&args, "--help") == 0);
		args.argv[0][0] = '\0';
	}

	ret = fuse_main(args.argc, args.argv, &fusenfs_oper, NULL);
	fuse_opt_free_args(&args);
	return ret;
}