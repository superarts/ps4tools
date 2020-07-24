ps4tools
========

## Fork info

**This section is under construction.**

I forked this repo to figure out how to downport 6.72 games to 5.05.

- I'm on macOS and I don't quite understand the existing logic of output path, so I added a simple workaround to write files to `output-filename.pkg`. `mkdir` first to avoid some weird empty directories.
- Added `elf-downgrader.py` and `sfo-tool.py` (I found them from [here](https://www.psx-place.com/threads/latest-ps4-jailbreaks-developments-now-convert-games-up-to-6-72-to-be-playable-on-5-05-fw.30519/). 
  - You may need to `pip2 install hexdump` to run `python elf-downgrader.py`.
- I'm still looking for a command line to to repack / generate (fake) PKG file. Please let me know if there's any.

IMPORTANT: Do *NOT* pirate! Only play backup games you own, and support the game companies you love.

## Original README

My collection of tools for PS4 file handling.

Credits
-------

flat_z (original Python scripts for PUP and PKG unpacking)

zecoxao (updates and bug fixes)

CrazyVoid (for genidx sources)

zecoxao (for undat sources)

CHANGELOG
--------

* First Release

	- pupunpack: splits PS4UPDATE.PUP and exposes inner PUP files (encrypted).
	- unpkg: unpacks retail/debug PKG files while collecting data and dumping internal files (mostly a C port of flat_z's Python script, at the moment).
	- unpfs: unpacks pfs images
	- trophy: unpack trophy files (incl. bruteforce for npcommid)
	- genidx: generate PS4 IDX File
	- undat: index.dat decrypter for ps4
	- fpkg_rename: Renames fpkg into following format $TITLE - ($TITLE_ID) ($VERSION).pkg
