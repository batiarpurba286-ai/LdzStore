# Ldz Mods — Neon Key Store

Toko digital responsif dengan React/Vite, Express, dan SQLite.

## Fitur
- Katalog 3 paket dengan harga yang bisa diedit di `src/main.jsx` dan `server.js`.
- Form checkout dan pesanan tersimpan di SQLite.
- Panel admin dengan password hash scrypt, token sesi, rate limit, dan inventaris key.
- Key disimpan di server dan baru dapat dikirim ketika order berstatus `paid`.
- Endpoint webhook sengaja fail-closed; belum ada integrasi pembayaran sungguhan.

## Menjalankan di komputer / hosting Node.js
1. Install Node.js 20+.
2. Salin `.env.example` menjadi `.env`.
3. Buat password admin hash dengan perintah di bawah, lalu isi `ADMIN_PASSWORD_HASH`.
4. Jalankan `npm install`, `npm run build`, lalu `npm start`.
5. Buka `http://localhost:3000`.

### Membuat hash password admin
Jalankan perintah ini di terminal:
```bash
node -e "const c=require('crypto');const s=c.randomBytes(16);console.log('scrypt$'+s.toString('hex')+'$'+c.scryptSync(process.argv[1],s,32).toString('hex'))" "GANTI_DENGAN_PASSWORD_KUAT"
```
Masukkan output lengkap ke `ADMIN_PASSWORD_HASH` dalam `.env`. Jangan gunakan password contoh di produksi.

## Penting: QRIS & pengiriman otomatis
Versi ini adalah starter yang aman untuk dikembangkan, bukan toko live siap menerima pembayaran. QRIS nyata membutuhkan akun merchant dan payment gateway (misalnya provider berizin yang mendukung QRIS dinamis), serta konfigurasi API dan webhook.
- Buat order di server; jangan percaya status pembayaran dari browser atau screenshot.
- Terapkan validasi signature webhook berdasarkan dokumentasi provider menggunakan raw request body.
- Cocokkan reference order, merchant, nominal, mata uang, status final, dan cegah replay/idempotency.
- Setelah webhook valid, ubah status order menjadi `paid` dalam transaksi database lalu panggil fungsi alokasi key secara atomik.
- Kirim key melalui halaman order terautentikasi atau email provider, jangan menaruh key di URL atau log.
- Aktifkan HTTPS, backup database, secret manager, logging tanpa data sensitif, kebijakan privasi, dan syarat refund sebelum peluncuran.

Endpoint webhook sekarang selalu menolak konfirmasi paid karena provider belum dipilih. Ini disengaja: pembayaran tidak boleh dianggap lunas tanpa verifikasi server-to-server.
