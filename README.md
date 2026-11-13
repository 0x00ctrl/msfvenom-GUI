# MSFVenom Payload Studio

A clean, modern GUI for `msfvenom`. Pick a platform, narrow down the
catalog with a few clicks, and generate your payload, no command-line
flag hunting required.

<img width="1275" height="872" alt="image" src="https://github.com/user-attachments/assets/b3462307-eaed-4439-8693-a88d280716bd" />

<img width="1271" height="873" alt="image" src="https://github.com/user-attachments/assets/38976f4a-1e15-4cd7-8ce9-f6153a1cd467" />


## Features

- Dark, modern UI built with PySide6
- Dynamic catalog loaded straight from your installed `msfvenom`
- Guided flow: platform → architecture → family → transport → payload
- Searchable payload list with live filtering
- Payload option inspector
- Command preview + one-click copy
- Background workers so the UI never freezes

## Setup

You'll need Python 3, PySide6, and Metasploit installed.

```bash
sudo pacman -S pyside6 python3 metasploit
```
*Installation command for your distro may be different*

```bash
python3 msfvenom-gui.py
```
### Quick start

    Pick a platform from the top card.
    Optionally narrow it down with architecture, family, or transport. Click All to skip a step.
    Find your payload in the list. Search works, and you can type a module name directly.
    Fill in LHOST/LPORT, choose an output format and file, then hit Generate payload.
    Stuck on a payload's options? Hit Inspect payload options and check the log.

### Heads up
*==The architecture and family buttons are inferred from payload names and are just there to help you navigate. Some unusual modules may show up under unspecified or other / none. Choose All to see everything.
This tool is for authorized testing only. Don't use it against systems you don't own or have explicit permission to test.==*
