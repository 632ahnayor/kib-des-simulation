# Simulasi Transmisi Ciphertext Dua Arah (DES-CBC Manual)

Dua VM Ubuntu Server (`peer-a` dan `peer-b`) saling bertukar pesan terenkripsi melalui TCP, dua arah. Algoritma DES dan mode CBC ditulis manual dengan Python, tanpa library kriptografi. Kunci diasumsikan sudah diketahui kedua pihak (hardcoded), sehingga tidak ada distribusi kunci.

## 1. Struktur Berkas

| Berkas | Fungsi |
|---|---|
| `des.py` | Algoritma enkripsi/dekripsi (DES + CBC + padding PKCS#7) |
| `secure_node.py` | Node jaringan dua arah yang mengirim/menerima ciphertext, plus log |
| `test_connection.py` | Uji koneksi TCP tanpa enkripsi (hanya framing) |
| `test_des.py` | Unit test untuk `des.py` |

## 2. Lingkungan VM

| Item | Nilai |
|---|---|
| VM | 2 Ubuntu Server (`peer-a`, `peer-b`), hasil clone |
| Adapter 1 | NAT (untuk `apt`/internet) |
| Adapter 2 | Host-only (jalur komunikasi antar-peer) |
| IP statis (`enp0s8`) | `peer-a` = `192.168.56.10`, `peer-b` = `192.168.56.20` |
| Port | `65432` |

Host-only dipilih karena privat, stabil, dan antar-VM dapat saling terhubung. Satu koneksi TCP bersifat full-duplex: peran `server` (listen/accept) dan `client` (connect) hanya berbeda saat koneksi dibuat. Setelah itu kedua sisi menjalankan thread kirim dan terima yang sama.

---

## 3. Crypto (`des.py`)

### Cara kerja singkat

1. **Key schedule:** kunci 64 bit lewat PC-1 menjadi 56 bit, dibagi dua bagian (C dan D, masing-masing 28 bit), diputar kiri sesuai `SHIFT_SCHEDULE`, lalu PC-2 menghasilkan 16 subkey 48 bit.
2. **Blok 64 bit:** Initial Permutation (IP), 16 ronde Feistel (`L, R = R, L XOR F(R, K)`), tukar L dan R, lalu IP_INV.
3. **Fungsi F:** ekspansi E (32 ke 48 bit), XOR dengan subkey, 8 S-box (6 ke 4 bit), permutasi P.
4. **Dekripsi:** algoritma yang sama dengan urutan subkey dibalik.
5. **Padding PKCS#7:** panjang data dibulatkan ke kelipatan 8 byte. Data yang sudah pas tetap ditambah satu blok penuh.
6. **Mode CBC:** `C_i = E(P_i XOR C_(i-1))`, dengan `C_0 = IV` acak 8 byte per pesan. Keluaran: `IV || ciphertext`.

### Konstanta

| Nama | Keterangan |
|---|---|
| `IP` | Permutasi awal, diterapkan sebelum ronde 1 |
| `IP_INV` | Kebalikan IP, diterapkan setelah ronde 16 |
| `E` | Tabel ekspansi 32 ke 48 bit |
| `P` | Permutasi 32 bit setelah S-box |
| `PC1` | Pilih 56 dari 64 bit kunci (membuang bit paritas) |
| `PC2` | Pilih 48 dari 56 bit untuk tiap subkey |
| `SHIFT_SCHEDULE` | Jumlah geseran kiri per ronde pada key schedule |
| `S_BOXES` | 8 S-box (4 baris x 16 kolom), substitusi non-linear 6 ke 4 bit |
| `BLOCK_SIZE` | Ukuran blok = 8 byte (64 bit) |

### Fungsi

| Fungsi | Keterangan |
|---|---|
| `bytes_to_bits(data)` | Bytes menjadi list bit (MSB dulu) |
| `bits_to_bytes(bits)` | List bit menjadi bytes (panjang harus kelipatan 8) |
| `permute(bits, table)` | Permutasi/seleksi umum berdasarkan tabel (indeks mulai 1) |
| `xor(a, b)` | XOR dua list bit sama panjang |
| `left_rotate(bits, n)` | Rotasi kiri melingkar sebanyak `n` |
| `generate_subkeys(key)` | Membuat 16 subkey 48 bit dari kunci 8 byte |
| `_substitute(bits_48)` | Menerapkan 8 S-box: baris dari bit terluar, kolom dari 4 bit tengah |
| `feistel_function(r, k)` | Fungsi F: E, XOR subkey, S-box, P |
| `_des_block(bits, subkeys)` | 16 ronde Feistel pada satu blok (maju = enkripsi, subkey terbalik = dekripsi) |
| `encrypt_block(block, subkeys)` | Enkripsi satu blok 8 byte |
| `decrypt_block(block, subkeys)` | Dekripsi satu blok 8 byte |
| `pad(data)` / `unpad(data)` | Tambah/validasi dan hapus padding PKCS#7 (`ValueError` jika rusak) |
| `generate_iv()` | IV acak 8 byte dari `os.urandom` |
| `cbc_encrypt(pt, key, iv=None)` | Enkripsi CBC, mengembalikan `IV \|\| ciphertext` (IV bisa ditentukan untuk tes) |
| `cbc_decrypt(data, key)` | Memisahkan IV, dekripsi CBC, lalu `unpad` |
| `des_encrypt(pt, key)` / `des_decrypt(ct, key)` | API publik, pembungkus `cbc_encrypt`/`cbc_decrypt` |

### Main

Blok `if __name__ == "__main__"` menjalankan smoke test: mengenkripsi lalu mendekripsi satu pesan, mencetak hasilnya, dan memastikan round-trip berhasil dengan `assert`.

---

## 4. Koneksi

### Format pesan di jaringan

```
[4 byte panjang, big-endian][8 byte IV][blok ciphertext ...]
```

TCP adalah aliran byte tanpa batas pesan, sehingga panjang diberikan di depan agar penerima tahu berapa byte yang harus dibaca.

### `secure_node.py`

**Variabel/konstanta**

| Nama | Keterangan |
|---|---|
| `KEY` | Kunci DES 8 byte yang dibagi kedua peer (`133457799BBCDFF1`) |
| `LOG_FILE` | Nama file log, diisi saat program mulai (`log_<role>_<waktu>.txt`) |

**Fungsi**

| Fungsi | Keterangan |
|---|---|
| `log(message)` | Cetak ke layar dan tulis ke `LOG_FILE` dengan timestamp milidetik |
| `send_encrypted(sock, text)` | Enkripsi teks, catat plaintext dan ciphertext, kirim dengan header panjang |
| `recv_exactly(sock, n)` | Mengulang `recv()` sampai tepat `n` byte diterima (`ConnectionError` jika koneksi putus) |
| `receive_encrypted(sock)` | Baca satu frame, catat ciphertext, dekripsi, catat plaintext. Mengembalikan `None` jika gagal |
| `listen_loop(sock)` | Thread latar belakang: terus menerima dan menampilkan pesan peer |
| `send_loop(sock)` | Thread utama: baca keyboard dan kirim, berhenti saat mengetik `quit` |
| `run_as_server(port)` | Bind `0.0.0.0`, `listen`, `accept`, lalu jalankan kedua loop |
| `run_as_client(host, port)` | `connect` ke peer, lalu jalankan kedua loop |

**Main:** membaca argumen (`server <port>` atau `client <host> <port>`), membuat nama file log, lalu memanggil `run_as_server` atau `run_as_client`.

### `test_connection.py`

Sama seperti `secure_node.py` tetapi **tanpa enkripsi**, untuk memastikan jaringan dan framing benar sebelum DES dipasang. Fungsinya: `send_message`, `recv_exactly`, `receive_message`, `listen_loop`, `send_loop`, `run_as_server`, `run_as_client`, dengan main yang sama (membaca peran dari argumen).

---

## 5. Pengujian

### 5.1 Unit test cipher (`test_des.py`, 16 tes)

| Kelas | Yang diuji |
|---|---|
| `TestBitUtilities` | Konversi bytes/bit, IP dan IP_INV saling kebalikan, XOR, rotasi |
| `TestKeySchedule` | 16 subkey masing-masing 48 bit, kunci salah panjang ditolak |
| `TestSingleBlock` | Vektor uji DES terpublikasi (kunci `133457799BBCDFF1`, plaintext `0123456789ABCDEF`, ciphertext `85E813540F0AB405`) dan round-trip |
| `TestPadding` | Round-trip berbagai panjang, blok penuh tambahan, padding rusak ditolak |
| `TestCBCEndToEnd` | Round-trip berbagai panjang pesan, IV acak menghasilkan ciphertext berbeda, IV tetap bisa direproduksi, kunci salah dan ciphertext yang diubah tidak memulihkan pesan |

Jalankan: `python3 test_des.py`

### 5.2 Uji koneksi tanpa enkripsi

```bash
# peer-a
python3 test_connection.py server 65432
# peer-b
python3 test_connection.py client 192.168.56.10 65432
```

Jika gagal, cek firewall: `sudo ufw allow 65432/tcp`.

### 5.3 Uji end-to-end terenkripsi

```bash
# peer-a (jalankan lebih dulu)
python3 secure_node.py server 65432
# peer-b
python3 secure_node.py client 192.168.56.10 65432
```

Pesan uji dan hasil yang diharapkan:

| Pesan | Ukuran ciphertext (termasuk IV) | Menunjukkan |
|---|---|---|
| `hello` | 16 byte | Padding mengisi satu blok |
| `12345678` | 24 byte | Padding PKCS#7 menambah satu blok penuh |
| Kalimat 50+ karakter | 64 byte | Chaining CBC multi-blok |
| `hello` lagi | 16 byte, hex berbeda | IV acak per pesan |

Verifikasi: hex `[SEND] ciphertext` di pengirim harus sama dengan `[RECV] ciphertext` di penerima, dan plaintext hasil dekripsi harus sama dengan yang diketik.

### 5.4 Sniffing tidak live (NIC trace VirtualBox)

Wireshark di host **tidak dapat melihat** trafik antar-VM, karena host-only adalah switch virtual yang meneruskan frame langsung antara port VM tujuan dan host tidak berada di jalurnya. Solusinya merekam di NIC virtual VM (sebelum switch):

```
cd "C:\Program Files\Oracle\VirtualBox"
VBoxManage list vms
VBoxManage controlvm "<nama VM peer-a>" nictracefile2 "C:\path\peer-a.pcap"
VBoxManage controlvm "<nama VM peer-a>" nictrace2 on
:: jalankan sesi secure_node.py, lalu:
VBoxManage controlvm "<nama VM peer-a>" nictrace2 off
```

`nictrace2` merujuk ke Adapter 2 (host-only). Aktifkan sebelum node terhubung agar handshake terekam. Buka `.pcap` di Wireshark dengan filter `tcp.port == 65432 && tcp.len > 0`, lalu **Follow > TCP Stream**. Hasil: payload berupa 4 byte panjang diikuti ciphertext yang sama dengan log, tanpa teks terbaca.

Alternatif tidak live: `sudo tcpdump -i enp0s8 -n -s0 -Z $USER -w ~/capture.pcap port 65432` di `peer-a`, lalu salin dengan `scp`.

### 5.5 Sniffing live (stream tcpdump ke Wireshark)

Di `peer-a`, izinkan `tcpdump` lewat `sudo` tanpa password:

```bash
echo "$USER ALL=(root) NOPASSWD: /usr/bin/tcpdump" | sudo tee /etc/sudoers.d/tcpdump
sudo chmod 440 /etc/sudoers.d/tcpdump
```

Di host (sebelum menjalankan node):

```
ssh user@192.168.56.10 "sudo tcpdump -i enp0s8 -U -s0 -w - not port 22" | "C:\Program Files\Wireshark\Wireshark.exe" -k -i -
```

`-w -` menulis pcap ke stdout, `-U` mem-flush tiap paket, `not port 22` mencegah SSH yang membawa capture ikut tertangkap (feedback loop), dan `-k -i -` membuat Wireshark membaca dari stdin.

---

## 6. Keterbatasan

- **DES sudah usang:** kunci efektif 56 bit dapat di-brute-force. Dipilih untuk tujuan pembelajaran.
- **Tanpa integritas:** CBC hanya menjamin kerahasiaan. Pengecekan padding hanya mendeteksi sebagian modifikasi, dan MAC diperlukan untuk integritas sebenarnya.
- **Kunci hardcoded:** sesuai asumsi tugas bahwa kunci sudah dimiliki kedua pihak.
