# AMCache-Triage

🚀 Fast, scriptable triage tool for Windows `Amcache.hve` registry hives — with SHA-1 extraction, hash whitelisting, and optional VirusTotal enrichment.

---

## 🔍 What It Does

This tool parses the Windows `Amcache.hve` registry file to extract metadata about executed binaries (paths, hashes, timestamps). It improves traditional triage workflows by:

- 🧼 Whitelisting known-good hashes via [hashlookup.circl.lu](https://hashlookup.circl.lu)
- 🔒 Querying [VirusTotal](https://www.virustotal.com/) only for unknown or suspicious hashes
- 🧾 Exporting clean CSV and JSON reports
- 📊 Displaying results in a terminal UI with optional highlighting of malicious files

---

## 📦 Features

- ✅ Parses both modern and legacy Amcache formats
- ✅ Bulk SHA-1 lookup against CIRCL Hashlookup
- ✅ Optional VirusTotal enrichment (`--vt`)
- ✅ Filters out known OS/system binaries
- ✅ Outputs to CSV or JSON
- ✅ Interactive console view with [rich](https://github.com/Textualize/rich)
- 🐧 100% offline-capable (except for VT)

---

## 📸 Example Usage

```bash
export VT_API_KEY=your_virustotal_key

python amcache_triage.py \
  --input /path/to/Amcache.hve \
  --csv report.csv \
  --vt \
  --only-detections
````

Or run without VT:

```bash
python amcache_triage.py --input Amcache.hve --csv report.csv
```

---

## 🔐 Why Whitelist First?

Free VirusTotal API keys are limited to **500 requests/day**.
This tool first checks known hashes using [hashlookup.circl.lu](https://hashlookup.circl.lu), skipping known system binaries and saving precious VT quota for the real unknowns.

---

## 💡 Possible Extensions

* Add support for local NSRL hash whitelists
* Create an OpenCTI/OpenRELiK worker
* Add support for MalwareBazaar or Hybrid Analysis API
* Web UI or MISP enrichment module

---

## 🛠 Requirements

* Python 3.8+
* `python-registry`, `requests`, `rich`

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## 📖 Credits

* Original code: [Cristian Souza](https://github.com/cristianmsbr) — *Amcache-EvilHunter*
* Forked and extended by: Thomas Lowagie
  License: MIT

---

## 🪪 License

This project is licensed under the MIT License. See [`LICENSE`](LICENSE) for details.
