# Changelog

## v0.9

- **Unified Autoloader**: Autoload config parsing logic has been moved into [ps5-unified-autoloader](https://github.com/itsPLK/ps5-unified-autoloader) — a shared ELF used across all autoloaders (Y2JB, BD-JB, Lua). This keeps the codebase consistent and makes improvements available to all of them at once.
- **Sync autoload config from USB to /data**: Added support for syncing (moving) the autoload configuration from a USB drive to internal `/data` storage using the `@sync` directive in `autoload.txt`.
- **Improved stability for `autoload.txt` users**: Since payloads are now loaded after the YouTube app has fully closed, issues with certain payloads causing a kernel panic on load should be resolved.
- **Dropped YT cache directory config support**: Because the unified autoloader runs after the YouTube app is fully closed, loading the `autoload.txt` configuration from the YouTube app's cache directory is no longer supported.

[Full Changelog](https://github.com/itsPLK/ps5_y2jb_autoloader/compare/v0.8-a0146a2...v0.9-2b2e5f6)


## v0.8

- Added P2JB support for firmwares above 10.01 up to 12.70 (lower firmwares still use Lapse)
- Added estimated progress overlay during the P2JB exploit loading phase (shifts position randomly to prevent OLED burn-in)
- Updated elfldr [(rebuilt with latest sdk)](https://github.com/itsPLK/ps5-elfldr/releases/tag/v0.23.2-148b71c)
- Updated Payload Manager to [v0.3.1](https://github.com/itsPLK/ps5-payload-manager/releases/tag/v0.3.1)

[Full Changelog](https://github.com/itsPLK/ps5_y2jb_autoloader/compare/v0.7-530a4ce...v0.8-a0146a2)


## v0.7

- Improved stability of PSN dialog disabling ([07c1742](https://github.com/itsPLK/ps5-y2jb-autoloader/commit/07c17420b376318f95e826436ad07787c3429615))
- Updated kexp ([5bed6cf](https://github.com/itsPLK/ps5-kexp/commit/5bed6cf36b26e4109049499e89e2bda9f95a7bdc))
- Updated Payload Manager to [v0.3.0](https://github.com/itsPLK/ps5-payload-manager/releases/tag/v0.3.0)

[Full Changelog](https://github.com/itsPLK/ps5_y2jb_autoloader/compare/v0.6.3-e655073...v0.7-530a4ce)


## v0.6.3

- Updated `kexp` - fixes kernel panics when launching PS5 games (thanks @c0w-ar, @ufm42)

[Full Changelog](https://github.com/itsPLK/ps5_y2jb_autoloader/compare/v0.6-a9821f8...v0.6.3-e655073)


## v0.6 (Aborted)

*Note: v0.6 was an aborted release due to kernel panics when launching PS5 games (subsequently fixed in v0.6.3).*

- Removed the static 4-second startup delay (now polls for when the ELF loader is ready, starting immediately)
- Updated Lapse to 2.0, merged ufm42's kexp post-JB shellcode, and deprecated GPU RW / firmware-specific kernel offsets
- Overhauled the build system to resolve external binary dependencies (`kexp`, `elfldr`, `pldmgr`) dynamically during build time rather than tracking them in Git
- Added fully automated release workflows and simplified repository directory structure

[Full Changelog](https://github.com/itsPLK/ps5-y2jb-autoloader/compare/v0.5...v0.6-a9821f8)

## v0.5

- **New Loader UI**: A clean graphical interface that replaces system notification spam with a dedicated log window for important status updates. In the event of an error, the UI automatically hides to reveal the full "old style" debug logs.
- **Payload Manager (New Default ELF)**: It handles payload loading after the YouTube app is closed, improving the stability of payloads like **etaHEN** and **kstuff**.
    - **Note on Compatibility**: Your existing autoload configurations will continue to work as they did before.
    - **Note on Usage**: If you choose to use Payload Manager, it should be the **only** item listed in your `autoload.txt`.
- **Custom ELF Loader**: The default `elfldr` now only accepts connections from the PS5 itself (localhost). This improves security by preventing other devices on your network from sending payloads to your console.
    - **Note**: You can still use a standard `elfldr` if you need to send payloads from other devices. See the **Additional Info** section in [README.md](README.md) for instructions.

[Full Changelog](https://github.com/itsPLK/ps5_y2jb_autoloader/compare/v0.4...v0.5)


## v0.4

Note: By default, Y2JB Autoloader does not utilize the new kill_youtube.elf from the upstream Y2JB project.
If you experience stability issues with the current auto-close method, you can manually add kill_youtube.elf as the final entry in your autoload configuration.

[Full Changelog](https://github.com/itsPLK/ps5_y2jb_autoloader/compare/v0.3...v0.4)


## v0.3

[Full Changelog](https://github.com/itsPLK/ps5_y2jb_autoloader/compare/v0.2.2...v0.3)


## v0.2.2

[Full Changelog](https://github.com/itsPLK/ps5_y2jb_autoloader/compare/v0.2.1...v0.2.2)


## v0.2.1

- splash.html included in download0.dat now has read-only permissions
- updater will now fix splash.html permissions too

[Full Changelog](https://github.com/itsPLK/ps5_y2jb_autoloader/compare/v0.2...v0.2.1)


## v0.2

This version adds y2jb_updater.
To install future releases, simply put the y2jb_update.zip file on your USB drive.

Updated elfldr.elf to v0.21

[Full Changelog](https://github.com/itsPLK/ps5_y2jb_autoloader/compare/v0.1...v0.2)


## v0.1

- Initial release