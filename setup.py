from urllib.request import urlretrieve
import zipfile
import os
import shutil
import sys


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


def get_arkenfox(url: str):
    filename = "arkenfox.zip"
    directory = "arkenfox"
    download_release_and_unzip(url, filename, directory)


def get_betterfox(url: str):
    filename = "betterfox.zip"
    directory = "betterfox"
    download_release_and_unzip(url, filename, directory)


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "refresh":
        redownload = True
    else:
        redownload = False

    # import config.py
    from config import config

    if not os.path.isdir("arkenfox") or redownload:
        get_arkenfox(config["arkenfox"])
    if not os.path.isdir("betterfox") or redownload:
        get_betterfox(config["betterfox"])

    userjs = ""

    files = config["files"]

    for file in files:
        userjs += read_file(file)

    write_file("user.js", userjs)


if __name__ == "__main__":
    main()
