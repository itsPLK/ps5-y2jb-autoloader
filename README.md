<p align="center">
  <img src="./download0/cache/splash_screen/aHR0cHM6Ly93d3cueW91dHViZS5jb20vdHY=/icon0.png" width="128" />
</p>

<h1 align="center">PS5 Y2JB Autoloader V0.5 UI</h1>

<p align="center">
  <em>Modern monochrome UI with stable long-run behavior, optimized for PS5 WebKit rendering.</em>
</p>

<p align="center">
  <a href="https://github.com/RDX-Sci01/ps5-y2jb-autoloader_SK/stargazers">
    <img src="https://img.shields.io/github/stars/RDX-Sci01/ps5-y2jb-autoloader_SK?style=social" alt="GitHub Stars"/>
  </a>
  <a href="https://github.com/RDX-Sci01/ps5-y2jb-autoloader_SK/issues">
    <img src="https://img.shields.io/github/issues/RDX-Sci01/ps5-y2jb-autoloader_SK" alt="GitHub Issues"/>
  </a>
  <a href="https://github.com/RDX-Sci01/ps5-y2jb-autoloader_SK/blob/main/LICENSE">
    <img src="https://img.shields.io/badge/license-GPL--3.0-blue" alt="License"/>
  </a>
</p>

<p align="center">
  <img src="https://github.com/user-attachments/assets/4f04395f-ebbd-4cf0-9c51-997226385c6d" alt="PS5 Y2JB UI Screenshot" width="600" />
</p>

---

## Table of Contents

- [Features](#features)
- [How to Use](#how-to-use)
- [How to Compile](#how-to-compile)
- [Credits](#credits)
- [License](#license)
- [Disclaimer](#disclaimer)
- [Star History](#star-history)

---

## Features

- Original **Y2JB structure preserved**  
- Modern **monochrome UI**  
- **PS5 WebKit-safe rendering path**  
- Minimal compositing layers for **smooth performance**  
- Stable long-run behavior during payload execution  
- Exact preservation of **layout, IDs, and styles**  
- Only `uiLog` and `updateProgress` were merged/fixed  
- Scrollbars, footer, progress bar, and scaling behavior remain unchanged  

---

## How to Use

1. Access the PS5 via FTP: /user/download/PPSA01650
2. Download `download0.dat` from the [releases page](#)  
3. Send the file to your PS5 using FTP  

---

## How to Compile

Use **🗄️ UFS2Tool**:  
[https://github.com/SvenGDK/UFS2Tool](https://github.com/SvenGDK/UFS2Tool)

---

## Credits

- **[Gezine](https://github.com/Gezine)** – Creator of the original [Y2JB](https://github.com/Gezine/Y2JB)  
- **[shahrilnet](https://github.com/shahrilnet), [null_ptr](https://github.com/n0llptr)** – Referenced code from [Remote Lua Loader](https://github.com/shahrilnet/remote_lua_loader)  
- **[BenNoxXD](https://github.com/BenNoxXD)** – [ClosePlayer](https://github.com/BenNoxXD/PS5-BDJ-HEN-loader) reference  
- **[ntfargo](https://github.com/ntfargo)** – Provided V8 CVEs and CTF writeups  
- **abc and psfree team** – Lapse implementation  
- **[flat_z](https://github.com/flatz) and [LM](https://github.com/LightningMods)** – Implemented GPU read/write using direct ioctl  
- **[john-tornblom](https://github.com/john-tornblom) and [EchoStretch](https://github.com/EchoStretch)** – Provided `elfldr.elf` payload  
- **[hammer-83](https://github.com/hammer-83)** – Various BD-J PS5 exploit references  
- **[zecoxao](https://github.com/zecoxao), [idlesauce](https://github.com/idlesauce), [TheFlow](https://github.com/theofficialflow)** – Helped troubleshoot `dlsym`  
- **[Dr.Yenyen](https://github.com/DrYenyen) and PS5 R&D community** – Tested Y2JB  
- **Rush** – Created Y2JB backup file  

---

## License

This project is licensed under the **GPL-3.0 License**.  

The original **Y2JB** base code remains under its **MIT License** ([LICENSE-MIT](LICENSE-MIT)).  
All unique modifications and additions in this fork are under **GPL-3.0**.  

---

## Disclaimer

This tool is provided **as-is** for research and development purposes only. Use at your own risk. The developers are **not responsible** for any damage, data loss, or consequences resulting from its use.  

---
