# ST6 — AI Agent summarizer dan evaluasi ringkasan

Status: **lulus pada mode template/deterministik**.
Mode LLM disediakan untuk uji pada VM dengan endpoint model yang tersedia.

## Tujuan

Membuktikan bahwa AI Agent:

1. Menghasilkan ringkasan terstruktur dari alert MCP.
2. Tidak mengarang `alert_ids`, CVE, IP, atau fakta lain.
3. Tidak menyarankan pemblokiran otomatis.
4. Menyatakan ketidakpastian bila data terbatas.
5. Dapat dinilai dengan rubric yang konsisten.

## Isi paket

| File | Fungsi |
|---|---|
| `summarizer.py` | Normalisasi alert, ringkasan template, mode LLM, validasi skema |
| `prompt.md` | System prompt dan guardrail AI Agent |
| `evaluate_st6.py` | Pemeriksaan faithfulness, completeness, actionability, clarity, conciseness |
| `test_st6.py` | Uji mode template, skema, redaksi IP, CVE, dan determinisme |
| `rubric.json` | Rubric 1–5 untuk penilaian manusia |
| `fixtures/alerts_input.json` | Tiga alert contoh: brute-force, traversal, XXE |
| `hasil-st6.json` | Output contoh yang dihasilkan uji |
| `run-st6.sh` | Menjalankan uji dan evaluator |

## Uji cepat (tanpa LLM)

```bash
cd docs/smoke-test/smoke-test6
python3 test_st6.py
python3 evaluate_st6.py
```

Hasil yang diharapkan:

```text
ST6 PASS
scores={'faithfulness': 5, 'completeness': 5, 'actionability': 5, 'clarity': 5, 'conciseness': 5}
```

## Mode LLM

Set endpoint yang kompatibel dengan OpenAI Chat Completions:

```bash
export LLM_BASE_URL="https://endpoint-model/v1"
export LLM_API_KEY="ganti-api-key"
export LLM_MODEL="nama-model"
```

Jalankan:

```bash
python3 summarizer.py --input fixtures/alerts_input.json --mode llm --output hasil-llm.json
```

Jika panggilan LLM gagal atau output tidak sesuai skema, program otomatis
memakai ringkasan template dan menambahkan alasan di `ketidakpastian`.
Kunci API tidak boleh disimpan di repository.

## Skema output

```json
{
  "ringkasan": "string",
  "severity": "low|medium|high|critical",
  "indikator": ["string"],
  "dampak": "string",
  "mitigasi": ["string"],
  "alert_ids": ["string"],
  "ketidakpastian": "string"
}
```

## Evaluasi

`evaluate_st6.py` memeriksa:

- Skema lengkap dan severity valid.
- `alert_ids` hanya berasal dari input.
- CVE yang disebut harus ada di input.
- Tidak ada IP mentah; prefiks `/24` diizinkan.
- Tidak ada frasa pemblokiran otomatis.
- Skor heuristic 1–5 untuk lima kriteria.

Skor heuristic ini bukan pengganti penilaian manusia. Untuk laporan TA,
gunakan `rubric.json` dengan minimal dua penilai dan laporkan kecocokan
antar-penilai.

## Batasan

- Mode template adalah baseline deterministik, bukan bukti kualitas LLM.
- Uji LLM nyata bergantung pada model, prompt, dan kuota endpoint.
- Fixture hanya tiga alert; evaluasi utama memakai dataset uji 80%.
- Ringkasan belum memakai metadata Wazuh Server API atau log mentah.
