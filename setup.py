from urllib.request import urlretrieve
import zipfile
import os
import shutil


def read_file(file: str):
    with open(file, "r") as handle:
        return handle.read()


def write_file(file: str, text: str):
    with open(file, "w") as handle:
        handle.write(text)


def download_release_and_unzip(url: str, filename: str, directory: str):
    # If the directory was already there nuke it
    if os.path.isdir(directory):
        shutil.rmtree(directory)

    urlretrieve(url, filename)
    with zipfile.ZipFile(filename, 'r') as zip_ref:
        # change internal folder name to directory
        # keeping directory in case something changes
        # to keep root directory clean
        files = zip_ref.namelist()
        zip_ref.extractall(directory)
        os.rename(f"{directory}/" + files[0], f"{directory}/" + directory)

    # remove zip
    if os.path.isfile(filename):
        os.remove(filename)


def get_arkenfox():
    # Updated July 19, 2024
    url = "https://github.com/arkenfox/user.js/archive/refs/tags/126.1.zip"
    filename = "arkenfox.zip"
    directory = "arkenfox"
    download_release_and_unzip(url, filename, directory)


def get_betterfox():
    # Updated July 19, 2024
    url = "https://github.com/yokoffing/Betterfox/archive/refs/tags/128.0.zip"
    filename = "betterfox.zip"
    directory = "betterfox"
    download_release_and_unzip(url, filename, directory)


def main():
    redownload = False
    if not os.path.isdir("arkenfox") or redownload:
        get_arkenfox()
    if not os.path.isdir("betterfox") or redownload:
        get_betterfox()

    userjs = ""

    userjs += read_file("arkenfox/arkenfox/user.js")
    userjs += read_file("arkenfox-overrides.js")

    userjs += read_file("betterfox/betterfox/Peskyfox.js")
    userjs += read_file("betterfox/betterfox/Fastfox.js")
    userjs += read_file("betterfox/betterfox/Smoothfox.js")
    userjs += read_file("betterfox/betterfox/Securefox.js")
    userjs += read_file("betterfox-overrides.js")

    write_file("user.js", userjs)


if __name__ == "__main__":
    main()
