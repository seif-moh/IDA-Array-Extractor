# Array Extractor for IDA Pro

> Turn any selected data range in IDA into a ready-made list/array — in one click.

![IDA Pro](https://img.shields.io/badge/IDA%20Pro-7.x%20%7C%208.x%20%7C%209.x-6d4aff)
![Python](https://img.shields.io/badge/Python-3-blue)
![License](https://img.shields.io/badge/license-MIT-green)

---

## 🇬🇧 Overview

Select a data range in IDA (like a `dd` array), run the plugin, pick the data type / language / list name, click **Copy** — done. The list is on your clipboard.

---

## ✨ Features

- **Start / End address** — auto-filled from your current selection in IDA.
- **Data type**: `int8/uint8`, `int16/uint16`, `int32/uint32`, `int64/uint64`, `float`, `double`
- **List / array name**, **number format** (hex or decimal).
- One **Copy** button on the result window.
- Copying is fully guarded: if clipboard access isn't available for any reason, you get a clear message to select-and-copy manually instead of a crash.

---

## 📦 Installation

1. Copy [`array_extractor.py`](array_extractor.py) into your IDA plugins directory:

   | OS | Path |
   |---|---|
   | Windows | `%APPDATA%\Hex-Rays\IDA Pro\plugins\` |
   | Linux / macOS | `~/.idapro/plugins/` |

2. Restart IDA.
3. Open a binary and check **Array Extractor** appears under `Edit → Plugins`.

---

## 🚀 Usage

1. In the disassembly (or hex) view, select the data range, e.g.:

   ```
   check dd 244B28EH, 0AF77805h, 110DFC17h, 7AFC3A1h, 6AFEC533h
        dd 4ED659A2h, 33C5D4B0h, 28658288h, ...
        ...
   ```

2. Trigger the plugin:
   - `Ctrl-Alt-A`, or
   - `Edit → Plugins → Array Extractor...`
3. The **Start**/**End** fields are already filled in from your selection. Just set:
   - **Data type** (e.g. `UInt32`)
   - **Output language** (Python / C / C# / Rust / Go)
   - **List / array name**
   - **Number format** (Hexadecimal / Decimal)
4. Click **Extract**, then **Copy**. Paste anywhere.

---

## 📄 License

MIT — see [LICENSE](LICENSE).

---

<p align="center">Made with ❤️ for the reverse-engineering community, by <b>Seif Mohammed</b>.</p>
