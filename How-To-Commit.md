# Semantic Commit Messages

Gunakan format commit yang konsisten untuk membuat riwayat perubahan lebih mudah dibaca dan dipahami.

## Format

```
<type>(<scope>): <subject>
```

* **type**: jenis perubahan (wajib)
* **scope**: area yang terpengaruh (opsional)
* **subject**: ringkasan singkat dalam present tense (wajib)

---

## Contoh

```
feat: add hat wobble
^--^  ^------------^
|     |
|     +-> Ringkasan perubahan (present tense)
|
+-------> Tipe perubahan
```

---

## Daftar Tipe Commit

* **feat**
  Menambahkan fitur baru

* **fix**
  Memperbaiki bug

* **refactor**
  Perubahan kode tanpa menambah fitur atau memperbaiki bug (restrukturisasi)

* **perf**
  Peningkatan performa (refactor khusus untuk optimasi)

* **docs**
  Perubahan dokumentasi (misalnya README)

* **style**
  Perubahan yang tidak memengaruhi logic (formatting, spasi, dll)

* **test**
  Menambahkan atau memperbaiki testing

* **chore**
  Perubahan minor yang tidak terkait langsung dengan src/test (misalnya update dependency)

* **build**
  Perubahan pada build system, dependency, atau versi project

* **ci**
  Perubahan terkait CI/CD pipeline

* **ops**
  Perubahan terkait infrastruktur, deployment, backup, dll

* **revert**
  Membatalkan commit sebelumnya

---

## Catatan Tambahan

* Gunakan **present tense** (contoh: `add`, bukan `added`)
* Buat subject singkat dan jelas
* Gunakan **scope** jika perubahan spesifik pada bagian tertentu
  Contoh:

  ```
  feat(auth): add JWT login
  fix(api): handle null response
  ```
