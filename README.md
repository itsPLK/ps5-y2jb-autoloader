<p align="center">
 <img src="./src/icon0.png" width="128" />
</p>
<h1 align="center">PS5 Y2JB Autoloader</h1>
<h3 align="center">Fork of <a href="https://github.com/Gezine/Y2JB">Y2JB</a></h3>
&nbsp;
<p align="center">Automatically loads the kernel exploit and your elf payloads.<br>Supports PS5 firmwares 4.03-12.70</p>

<p align="center">
    <b>Other Autoloaders:</b><br>
    <a href="https://github.com/itsPLK/ps5-bdjb-autoloader">BD-JB</a> | 
    <a href="https://github.com/itsPLK/ps5-lua-autoloader">Lua</a>
</p>

<p align="center">
 <img src="./y2jb_screenshot.png" width="600" />
</p>


## How to Use

There are two ways to use the autoloader:

### 🟢 Option 1: Payload Manager

If no `autoload.txt` config is found, the autoloader will automatically launch **[Payload Manager](https://github.com/itsPLK/ps5-payload-manager)** — a fully-featured PS5 payload manager with a web UI. This lets you configure and send payloads directly from your browser, without needing to manually set up config files or transfer ELF files ahead of time.

Just run the autoloader — if there's nothing configured, Payload Manager starts automatically.

> **Note:** Payload Manager also has its own built-in autoload feature, which lets you configure payloads to load automatically on startup — all managed through its web UI. This is separate from the `autoload.txt` mechanism described below.

---

### ⚙️ Option 2: Manual Config (`autoload.txt`)

For a fixed, automated payload chain, you can configure payloads manually:

- Create a directory named `ps5_autoloader`.
- Inside this directory, place your `.elf` / `.bin` files, and an `autoload.txt` file.
  - In `autoload.txt`, list the files you want to load, one filename per line.
  - Filenames are case-sensitive — ensure each name exactly matches the file.
  - You can add lines like `!1000` to make the loader wait 1000 ms before sending the next payload.
- Put the `ps5_autoloader` directory in one of these locations (priority order - highest first):
  - Root of a USB drive
  - Internal drive: `/data/ps5_autoloader`

> **Note:** When an `autoload.txt` config is found, Payload Manager is **not** launched automatically. If you also want Payload Manager available, place `pldmgr.elf` in your `ps5_autoloader` directory and add it to `autoload.txt`.

## How to Update

Since version **v0.2**, you can update the autoloader by simply placing **`y2jb_update.zip`** (from the [Releases page](https://github.com/itsPLK/ps5_y2jb_autoloader/releases)) on the **root** of a USB drive, and starting the app.

## Setup Instructions

Installation is the same as the original [Y2JB](https://github.com/Gezine/Y2JB/blob/main/README.md) (remote loader).


### Jailbroken PS5 (Webkit, Lua, BD-JB)
- Install the correct YouTube version for your firmware:
  - For firmware **4.03 to 12.40** get YouTube app (PPSA01650) version **01.000.003** PKG
  - For firmware **12.60 and up** get YouTube app (PPSA01650) version **01.000.030** PKG
  - *(Note: PPSA01651 and PPSA01652 from different regions also work)*
- Use FTP to place `download0.dat` from releases page in `/user/download/PPSA0165*`

### Non-Jailbroken PS5
You might find a system backup with pre-configured Autoloader (I don't distribute such backups).

You can also restore [Y2JB](https://github.com/Gezine/Y2JB) (remote loader) system backup, and then:
- install Autoloader over it by using [y2jb_updater](https://github.com/itsPLK/y2jb_updater)
- or use FTP to place `download0.dat` from releases page in `/user/download/PPSA01650`
- or install separate YT app from different region, and use FTP to place `download0.dat` from releases page in `/user/download/PPSA0165*`


## Additional Info

<Details>
<Summary><i>How to have different autoload configs for multiple YT apps?</i></Summary>

If you want to use multiple YT apps from different regions,
name your directory <code>ps5_autoloader_[TITLE_ID]</code>, e.g. <code>ps5_autoloader_PPSA01650</code>
this will allow you to have different autoload.txt files for each app
(these directories always take precedence over the generic ps5_autoloader directory)
</Details>

<Details>
<Summary><i>How to use custom ELF Loader version?</i></Summary>

By default, the autoloader uses a custom version of **elfldr** that only accepts connections from the PS5 itself (localhost). This improves security by preventing other devices on your network from sending payloads to your console.

If you want to use a "normal" ELF Loader that allows sending payloads from any device:
1. Place your custom ELF Loader (e.g. `elfldr.elf`) in the `ps5_autoloader` directory.
2. Add `elfldr.elf` to your `autoload.txt`.
3. **Note**: If you are loading other payloads right after `elfldr.elf` in your `autoload.txt`, add a sleep command immediately after it (like `!4000` to sleep for 4 seconds) to give the new ELF Loader time to start up and listen before subsequent payloads are sent.

Example `autoload.txt`:
```text
# Load custom ELF Loader
elfldr.elf
# Give it 4 seconds to start up (only needed if sending more payloads)
!4000
# Send other payloads
etaHEN.elf
```
</Details>

## Credits

* **[Gezine](https://github.com/Gezine)** - creator of the original [Y2JB](https://github.com/Gezine/Y2JB)
* **[shahrilnet](https://github.com/shahrilnet), [null_ptr](https://github.com/n0llptr)** - Referenced many codes from [Remote Lua Loader](https://github.com/shahrilnet/remote_lua_loader)
* **[BenNoxXD](https://github.com/BenNoxXD)** - [ClosePlayer](https://github.com/BenNoxXD/PS5-BDJ-HEN-loader) reference
* **[ntfargo](https://github.com/ntfargo)** - Thanks for providing V8 CVEs and CTF writeups
* **abc and psfree team** - Lapse implementation
* **[matem6](https://github.com/matem6)** - [P2JB](https://github.com/matem6/P2JB-Y2JB-Porting) implementation
* **[flat_z](https://github.com/flatz) and [LM](https://github.com/LightningMods)** - Helping implement GPU rw using direct ioctl
* **[john-tornblom](https://github.com/john-tornblom) and [EchoStretch](https://github.com/EchoStretch)** - Providing elfldr.elf payload
* **[hammer-83](https://github.com/hammer-83)** - Various BD-J PS5 exploit references
* **[zecoxao](https://github.com/zecoxao), [idlesauce](https://github.com/idlesauce), and [TheFlow](https://github.com/theofficialflow)** - Helping troubleshoot dlsym
* **[Dr.Yenyen](https://github.com/DrYenyen) and PS5 R&D community** - Testing Y2JB
* **Rush** - Creating Y2JB backup file
* **[ufm42](https://github.com/ufm42)** - [kexp](https://github.com/ufm42/kexp) used for PS5 post JB all-in-one shellcode

## License

This project is licensed under the **GPL-3.0 License**.

The original **Y2JB** base code remains under its original **MIT License** (see [LICENSE-MIT](LICENSE-MIT)).  
All unique modifications and additions in this fork are licensed under **GPL-3.0**.

## Disclaimer

This tool is provided as-is for research and development purposes only. Use at your own risk. The developers are not responsible for any damage, data loss, or consequences resulting from the use of this software.

## Donate
- [donate to Gezine](https://github.com/sponsors/Gezine)
- [donate to PLK](DONATE.md)

## Star History

<a href="https://www.star-history.com/?repos=itsplk%2Fps5-y2jb-autoloader&type=date&legend=top-left">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/chart?repos=itsplk/ps5-y2jb-autoloader&type=date&theme=dark&legend=bottom-right" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/chart?repos=itsplk/ps5-y2jb-autoloader&type=date&legend=bottom-right" />
   <img alt="Star History Chart" src="https://api.star-history.com/chart?repos=itsplk/ps5-y2jb-autoloader&type=date&legend=bottom-right" />
 </picture>
</a>
