# L3 Extractor

A small cross-platform desktop app (Windows & macOS) that derives the **L3 RSA
key** (`n`, `d`, `e`) for a given **BTLD ID** from a BMW *PSdZData* security set.

It is a GUI wrapper around the original extraction script, with the same logic
and byte-for-byte identical output, plus a command-line interface.

> **No input data is included in this repository.** You must supply your own
> PSdZData files. See [Required input files](#required-input-files).

![screenshot placeholder](assets/screenshot.png)

## Features

- Clean modern GUI (built with [customtkinter](https://github.com/TomSchimansky/CustomTkinter)).
- Works on **Windows** and **macOS** (and Linux).
- PKCS#12 loading via the `cryptography` library, so **no external OpenSSL
  binary is required**. Falls back to the system `openssl -legacy` if needed.
- Shows every step of the derivation in a live log.
- Save the result as `l3_<BTLD>.py` or copy it to the clipboard.
- Scriptable CLI for automation.

## Required input files

Put these five files from your PSdZData set in one folder and point the app at
that folder:

| File | From |
| --- | --- |
| `sec_auth_l3.xml` | `psdzdata/security/` |
| `sec_security.lic` | `psdzdata/security/` |
| `sec_keyreference.xml` | `psdzdata/security/` |
| `bmw_logo.png` | extracted from `resource.jar` |
| `bmw_mini_logo.png` | extracted from `resource.jar` |

These files are **intentionally not part of this repo** and are ignored by
`.gitignore`. Keep them private.

## Run from source

Requires Python 3.9+.

```bash
python -m venv venv
# Windows:  venv\Scripts\activate
# macOS:    source venv/bin/activate
pip install -r requirements.txt

python main.py          # GUI
```

### Command line

```bash
python cli.py --input ./input --btld btld-000014E0
# writes l3_000014E0.py and prints L3_N / L3_D / L3_E / L3_MODLEN
```

## Output

```python
L3_N = 0x...
L3_D = 0x...
L3_E = 3
L3_MODLEN = 64
```

Paste these straight into your flashing script.

## Build standalone apps

Prebuilt Windows and macOS bundles are produced automatically by GitHub Actions
(see `.github/workflows/build.yml`). Push a tag like `v1.0.0` to attach them to a
release, or download the artifacts from any run.

To build locally:

```bash
pip install -r requirements-build.txt
pyinstaller l3extractor.spec
```

- **Windows:** `dist/L3Extractor/L3Extractor.exe`
- **macOS:** `dist/L3Extractor.app`

> macOS builds are unsigned. On first launch, right-click the app and choose
> **Open**, or clear the quarantine flag:
> `xattr -dr com.apple.quarantine dist/L3Extractor.app`.

## Project layout

```
l3extract/
  core.py     # extraction logic (GUI-agnostic)
  gui.py      # customtkinter GUI
main.py       # GUI entry point
cli.py        # command-line interface
l3extractor.spec   # PyInstaller build spec
```

## Disclaimer

For use with your own vehicle data and licensed material only.
