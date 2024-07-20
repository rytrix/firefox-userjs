# Firefox user.js
This a repository that is setup to combine arkenfox and betterfox configs using override files and a config file

# config.py
This file specifies what files are included in the final user.js and what links arkenfox and betterfox are pulled from

# setup.py
Grabs github releases of arkenfox and betterfox if they are not present, then combines each specified file from the config.jsonc file into a user.js file

# install user.js
1. Open Firefox. In the URL bar, type about:profiles and press Enter.
2. For the profile you want to use (or use default), click Open Folder in the Root Directory section.
3. Move the user.js file into the folder.
