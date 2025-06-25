# Final-Project-Sistem-Operasi-IT-2025-Kelompok-8-C

## Peraturan
1. Waktu pengerjaan dimulai hari Kamis (19 Juni 2025) setelah soal dibagikan hingga hari Rabu (25 Juni 2025) pukul 23.59 WIB.
2. Praktikan diharapkan membuat laporan penjelasan dan penyelesaian soal dalam bentuk Readme(github).
3. Format nama repository github “Sisop-FP-2025-IT-[Kelas][Kelompok]” (contoh:Sisop-FP-2025-IT-A01).
4. Setelah pengerjaan selesai, seluruh source code dan semua script bash, awk, dan file yang berisi cron job ditaruh di github masing - masing kelompok, dan link github dikumpulkan pada form yang disediakan. Pastikan github di setting ke publik.
5. Commit terakhir maksimal 10 menit setelah waktu pengerjaan berakhir. Jika melewati maka akan dinilai berdasarkan commit terakhir.
6. Jika tidak ada pengumuman perubahan soal oleh asisten, maka soal dianggap dapat diselesaikan.
7. Jika ditemukan soal yang tidak dapat diselesaikan, harap menuliskannya pada Readme beserta permasalahan yang ditemukan.
8. Praktikan tidak diperbolehkan menanyakan jawaban dari soal yang diberikan kepada asisten maupun praktikan dari kelompok lainnya.
9. Jika ditemukan indikasi kecurangan dalam bentuk apapun di pengerjaan soal final project, maka nilai dianggap 0.
10. Pengerjaan soal final project sesuai dengan modul yang telah diajarkan.

## Kelompok C08


Nama | NRP
--- | ---
Christiano Ronaldo Silalahi | 5027241025
Bayu Kurniawan | 5027241055
Ahmad Syauqi Reza | 5027241085
Adinda Cahya Pramesti | 5027241117

## Deskripsi Soal

FUSE - File filtering
Buatlah sebuah program FUSE yang dapat mount sebuah directory dan melakukan filtering terhadap isi directory tersebut. Setelah mount directory, sistem filtering ini akan mengecek seluruh nama file yang ada menghapus seluruh file di dalam mounted directory dengan nama file yang mengandung kata virus dan trojan.


### Catatan


Struktur repository:
```
.
|_ fuse_filter.c
```

## Pengerjaan

>Poin 1: Membuat kode operasi FUSE

**Teori**

...

**Solusi**
```c
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
        if (is_malicious(de->d_name)) continue; // ← bagian filter digunakan di dalam FUSE op

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
```


> Poin 2: Membuat Kode Filter dile berbahaya

**Teori**

...

**Solusi**
```c
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

int main(int argc, char *argv[]) {
    delete_malicious_files(source_dir); // ← Pemanggilan fungsi filter
    return fuse_main(argc, argv, &xmp_oper, NULL);

```


**Video Menjalankan Program**


https://github.com/user-attachments/assets/f372bd60-c120-48d6-a73d-a9d8d0de0c2a


...

## Daftar Pustaka

Sitasi 1
Sitasi 2
Sitasi 3
