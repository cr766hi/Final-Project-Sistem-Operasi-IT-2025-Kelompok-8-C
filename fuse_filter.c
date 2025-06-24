#define FUSE_USE_VERSION 31
#include <fuse3/fuse.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>

static const char *source_dir = "/home/aldo/fpsisop"; //ganti sesuai path yang mau dijadikan fuse

int is_malicious(const char *name) {
    return strstr(name, "virus") || strstr(name, "trojan");
}

void delete_malicious_files(const char *dirpath) {
    DIR *dp;
    struct dirent *entry;

    dp = opendir(dirpath);
    if (dp == NULL) {
        perror("opendir");
        return;
    }

    while ((entry = readdir(dp)) != NULL) {
        if (entry->d_type == DT_REG) {
            if (is_malicious(entry->d_name)) {
                char filepath[1024];
                snprintf(filepath, sizeof(filepath), "%s/%s", dirpath, entry->d_name);
                if (unlink(filepath) == 0) {
                    printf("Deleted: %s\n", filepath);
                } else {
                    perror("unlink");
                }
            }
        }
    }
    closedir(dp);
}

static void fullpath(char fpath[PATH_MAX], const char *path) {
    snprintf(fpath, PATH_MAX, "%s%s", source_dir, path);
}

static int xmp_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi) {
    (void) fi;
    int res;
    char fpath[PATH_MAX];
    fullpath(fpath, path);
    res = lstat(fpath, stbuf);
    if (res == -1)
        return -errno;
    return 0;
}

static int xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                       off_t offset, struct fuse_file_info *fi,
                       enum fuse_readdir_flags flags) {
    (void) offset;
    (void) fi;
    (void) flags;

    char fpath[PATH_MAX];
    fullpath(fpath, path);
    DIR *dp;
    struct dirent *de;

    dp = opendir(fpath);
    if (dp == NULL)
        return -errno;

    while ((de = readdir(dp)) != NULL) {
        if (is_malicious(de->d_name)) continue; 

        struct stat st = {0};
        st.st_ino = de->d_ino;
        st.st_mode = de->d_type << 12;
        if (filler(buf, de->d_name, &st, 0, 0))
            break;
    }

    closedir(dp);
    return 0;
}

static int xmp_open(const char *path, struct fuse_file_info *fi) {
    int res;
    char fpath[PATH_MAX];
    fullpath(fpath, path);

    res = open(fpath, fi->flags);
    if (res == -1)
        return -errno;

    close(res);
    return 0;
}

static int xmp_read(const char *path, char *buf, size_t size, off_t offset,
                    struct fuse_file_info *fi) {
    int fd;
    int res;
    char fpath[PATH_MAX];
    fullpath(fpath, path);

    fd = open(fpath, O_RDONLY);
    if (fd == -1)
        return -errno;

    res = pread(fd, buf, size, offset);
    if (res == -1)
        res = -errno;

    close(fd);
    return res;
}

static const struct fuse_operations xmp_oper = {
    .getattr = xmp_getattr,
    .readdir = xmp_readdir,
    .open = xmp_open,
    .read = xmp_read,
};

int main(int argc, char *argv[]) {
    delete_malicious_files(source_dir);

    return fuse_main(argc, argv, &xmp_oper, NULL);
}
