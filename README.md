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
-

Struktur repository:
```
.
|_ fuse_filter.c
```

## Pengerjaan

### 1. Men-mount direktori sumber ke mount point.

**Teori**

FUSE (Filesystem in Userspace) memungkinkan proses non-privilege membuat filesystem baru dengan menjalankan kode di userspace—kernel hanya bertindak sebagai jembatan

**Solusi**

Pada kode:

```
static const char *source_dir = "/home/aldo/fpsisop";
...
int main(int argc, char *argv[]) {
    delete_malicious_files(source_dir);
    return fuse_main(argc, argv, &xmp_oper, NULL);
}
```
- `fuse_main` mem-mount direktori sesuai argumen `CLI` `(mis. mount_dir)` dan mendaftarkan callback `(xmp_oper)`.

- Empat operasi minimum di-implementasi `(getattr, readdir, open, read)` agar filesystem dapat di-browse dan membaca berkas.

### 2. Menyaring nama berkas berbahaya ketika listing.

**Teori**

`readdir` pada FUSE dipanggil setiap kali program `(mis. ls)` membaca isi direktori. Dengan melewatkan entri tertentu, kita dapat “menyembunyikan” berkas tanpa mengubah disk.

**Solusi**

Fungsi `is_malicious` menggunakan strstr untuk mendeteksi substring “virus” atau “trojan”. Pada `xmp_readdir`, sebelum setiap entri dimasukkan dengan filler, dilakukan pengecekan:

```
int is_malicious(const char *name) {
    return strstr(name, "virus") || strstr(name, "trojan");
}if (is_malicious(de->d_name)) continue;
 ```

Hasilnya, pengguna tidak akan melihat file yang diblokir pada direktori mount point.

### 3. Menghapus berkas berbahaya sebelum filesystem aktif.

**Teori**

Praktik keamanan proaktif kerap menghapus artefak yang terdeteksi malware sebelum bisa diakses. Menghapus saat pre-mount menghindari konsumsi ruang disk dan risiko eksekusi 
documentation.suse.com
.

**Solusi**


`delete_malicious_files` dijalankan di awal main. Ia:

Membuka direktori sumber dengan opendir.

Menelusuri entri reguler `(d_type == DT_REG)`.

Apabila nama berkas mengandung pola berbahaya → unlink, lalu menuliskan log Deleted: `<path>`.

Dengan begitu, berkas sudah terhapus sebelum FUSE mulai menerima permintaan I/O.

```
void delete_malicious_files(const char *dirpath) {
    ...
    if (is_malicious(entry->d_name)) {
        snprintf(filepath, sizeof(filepath), "%s/%s", dirpath, entry->d_name);
        if (unlink(filepath) == 0) {
            printf("Deleted: %s\n", filepath);
        }
    }
}
```

https://github.com/user-attachments/assets/f372bd60-c120-48d6-a73d-a9d8d0de0c2a


...

## Daftar Pustaka

- von der Assen, J., Feng, C., Huertas Celdrán, A., Oleš, R., Bovet, G., & Stiller, B. (2024). GuardFS: a File System for Integrated Detection and Mitigation of Linux‑based Ransomware [Preprint]. arXiv.

- Bloem, M., Alpcan, T., & Basar, T. (2009). A robust control framework for malware filtering.

- Saxe, J., & Berlin, K. (2017). eXpose: A character‑level convolutional neural network with embeddings for detecting malicious URLs, file paths and registry keys. arXiv.

- Šrndić, N., & Laskov, P. (2016). Hidost: a static machine‑learning‑based detector of malicious files. EURASIP Journal on Information Security, 2016, Article 22. 


