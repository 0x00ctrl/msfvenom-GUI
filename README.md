<div align="center">
  <h1>
    MSFVenom Payload Studio
  </h1>
  <p>
    A clean, modern GUI for <code>msfvenom</code>. Pick a platform, narrow down the catalog with a few clicks, and generate your payload—no command-line flag hunting required.
  </p>
</div>

<br />

<div align="center">
  <img width="1275" height="872" alt="MSFVenom Payload Studio Main Interface" src="https://github.com/user-attachments/assets/b3462307-eaed-4439-8693-a88d280716bd" />
  <br /><br />
  <img width="1271" height="873" alt="MSFVenom Payload Studio Payload Generation" src="https://github.com/user-attachments/assets/38976f4a-1e15-4cd7-8ce9-f6153a1cd467" />
</div>

## Features

- **Dark, modern UI** built with PySide6
- **Dynamic catalog** loaded directly from your local `msfvenom` installation
- **Guided filtering workflow:** Platform → Architecture → Family → Transport → Payload
- **Live search** with instant payload list filtering
- **Payload option inspector** to view required and optional module parameters
- **Command preview** with one-click clipboard copy
- **Asynchronous background workers** to keep the interface responsive during catalog loading and generation

## Installation & Setup

Ensure you have **Python 3**, **PySide6**, and **Metasploit Framework** installed on your system.

**Arch Linux:**
```bash
sudo pacman -S python pyside6 metasploit
```
*(Package names and installation commands will vary depending on your distribution.)*

**Run the application:**
```bash
python3 msfvenom-gui.py
```

## Quick Start

1. **Select a Platform:** Choose your target operating system or environment from the top card.
2. **Filter the Catalog:** Narrow down results using architecture, family, or transport filters (click **All** to skip any step).
3. **Choose a Payload:** Select a module from the list, use the search bar to filter, or type a module name directly.
4. **Configure & Generate:** Set your `LHOST`/`LPORT`, select an output format and destination path, and click **Generate payload**.
5. **Inspect Options:** If you are unsure about specific module flags, click **Inspect payload options** and review the output log.

## Notes & Disclaimer

> **Catalog Inference:** Architecture and family filters are inferred from payload naming conventions to simplify navigation. Unconventional modules may appear under `unspecified` or `other / none`. Select **All** at any stage to view the unfiltered catalog.

> **Legal Disclaimer:** This tool is intended strictly for authorized security testing and educational purposes. Do not use it against systems you do not own or lack explicit permission to test.

> *Made this using GPT-6 terra cuz I didnt want to waste time manually writing the command each time for building the payloads 😛*
