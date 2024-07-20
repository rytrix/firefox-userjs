# Firefox user.js
This a repository that is setup to combine arkenfox and betterfox configs using override files and a config file

The goal of this user.js configuration is to disable bloat/noisey features, tracking and generally enable security features by default. The goal of this configuration is not maximum privacy at the expense of usability, but instead focusing on security and usability as a priority, if you want privacy use TOR or Mulvad. With that said privacy features that don't effect usability much are enabled ootb.

Two things notably fixed by default are DNS and WebRTC leaks when using vpns.

# config.py
This file specifies what links arkenfox and betterfox are pulled from and what files are included in the final user.js

# setup.py
Grabs github releases of arkenfox and betterfox if they are not present, then combines each specified file from the config.jsonc file into a user.js file

# Install user.js
Download Mozilla Firefox
1. Open Firefox. In the URL bar, type about:profiles and press Enter.
2. For the profile you want to use (or use default), click Open Folder in the Root Directory section.
3. Move the user.js file into the folder.
