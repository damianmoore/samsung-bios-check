Samsung BIOS Check
==================

*BIOS update checker for Samsung laptops running Linux*

If you have a Samsung laptop and you run Linux, you may know that updating the BIOS/firmware is a hassle. The website doesn't show the firmware version updates available for download so you have to boot Windows and run their application just to check. There are also so many hardware version numbers for each product line, depending on keyboard layout and other hardware differences, that it can be hard to know what yours is.

Running this script will allow you to see easily from Linux (and possibly other UNIX OSs) whether there is an update of your BIOS. You'll still need to boot into Windows to perform an actual upgrade but this should make the process a bit less painful.

    sudo ./samsung_bios_check.py

The script gets your current BIOS version number via [dmidecode](http://www.nongnu.org/dmidecode/) so for this reason it requires root permissions. It then downloads the same XML from Samsung that their own Windows updater uses and compares version numbers. You can read my original [blog post](https://epixstudios.co.uk/blog/2012/12/01/samsung-laptop-firmware-update-check-from-linux/) for info about understanding their updater software.

To perform the upgrade once you boot Windows you'll need to go to the support section of the Samsung site, find your product, find 'Manuals & Downloads', then under 'Firmware' there'll be an item called 'Update Software (Firmware) (ver.1.0.0.X)'. Click the blue 'EXE' button/link to download 'BIOSUpdate.exe'.

This has been tested on a couple of NP900X3C (Series 9) machines but should work on others unless Samsung change their numbering system or update software. Contributions welcome.
