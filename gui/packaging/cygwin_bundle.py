"""Assemble a relocatable Cygwin tree from checksum-locked upstream packages."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import posixpath
from pathlib import Path
import shutil
import tarfile
import time
import urllib.request
import zipfile

HERE = Path(__file__).resolve().parent


def fetch(item, cache, base="", algorithm="sha256"):
    name = item.get("filename", Path(item.get("path", "")).name)
    target = cache / name
    expected = item[algorithm]
    if target.exists():
        with target.open("rb") as stream:
            if hashlib.file_digest(stream, algorithm).hexdigest() == expected:
                return target
    url = item.get("url", base + "/" + item.get("path", ""))
    for attempt in range(5):
        try:
            partial = target.with_suffix(target.suffix + ".part")
            with urllib.request.urlopen(url, timeout=90) as response, partial.open("wb") as stream:
                shutil.copyfileobj(response, stream)
            with partial.open("rb") as stream:
                if hashlib.file_digest(stream, algorithm).hexdigest() != expected:
                    raise ValueError("Checksum mismatch: " + name)
            partial.replace(target)
            return target
        except Exception as error:
            print("Download retry:", name, type(error).__name__, flush=True)
            if attempt == 4:
                raise RuntimeError("Download failed: " + name) from error
            time.sleep(1)


def mapped(name):
    name = posixpath.normpath(name.lstrip("/"))
    if name == ".." or name.startswith("../") or ":" in name:
        raise ValueError("Unsafe archive path: " + name)
    for prefix in ("usr/bin", "usr/lib"):
        if name == prefix or name.startswith(prefix + "/"):
            return name[4:]
    return name


def unpack_packages(archives, root):
    links = []
    for archive in archives:
        with tarfile.open(archive) as source:
            for member in source:
                # Unix manual names can contain characters forbidden by Win32.
                if member.name.lstrip("./").startswith(("usr/share/man/", "usr/share/info/")):
                    continue
                target = root / mapped(member.name)
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                elif member.isfile():
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with source.extractfile(member) as data, target.open("wb") as output:
                        shutil.copyfileobj(data, output)
                elif member.issym() or member.islnk():
                    name = member.linkname
                    if member.issym() and not name.startswith("/"):
                        name = posixpath.join(posixpath.dirname(member.name), name)
                    links.append((target, root / mapped(name)))
    # Materialize links so Windows Explorer can unpack without symlink privileges.
    while links:
        pending = []
        for target, source in links:
            if target == source or target.exists():
                continue
            if not source.exists():
                pending.append((target, source))
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            if source.is_dir():
                shutil.copytree(source, target, dirs_exist_ok=True)
            else:
                shutil.copy2(source, target)
        if len(pending) == len(links):
            print("Unresolved optional package links:", len(pending), flush=True)
            break
        links = pending
    for name in ("tmp", "etc", "var", "home"):
        (root / name).mkdir(parents=True, exist_ok=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("work", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    work, output = args.work.resolve(), args.output.resolve()
    cache = work / "downloads"
    cache.mkdir(parents=True, exist_ok=True)
    source_dir = output / "licenses" / "converter-sources"
    source_dir.mkdir(parents=True, exist_ok=True)
    lock = json.loads((HERE / "cygwin.lock.json").read_text())
    packages = lock["packages"]
    downloads = [(packages[name]["install"], lock["mirror"], "sha512") for name in lock["build"]]
    sources = {packages[name]["source"]["path"]: packages[name]["source"]
               for name in lock["runtime"] if "source" in packages[name]}
    downloads += [(item, lock["mirror"], "sha512") for item in sources.values()]
    upstream = json.loads((HERE / "sources.lock.json").read_text())
    python = json.loads((HERE / "python.lock.json").read_text())
    native = json.loads((HERE / "native-python.lock.json").read_text())
    downloads += [(item, "", "sha256") for item in upstream.values()]
    downloads += [(item, "", "sha256") for item in python.values()]
    downloads += [(item["source"], "", "sha256") for item in python.values() if item["source"]]
    downloads += [(item, "", "sha256") for item in native.values()]
    downloads += [(item["source"], "", "sha256") for item in native.values() if item["source"]]
    # Avoid two workers downloading the same source archive.
    unique = {item.get("filename", item.get("path")): (item, base, algorithm)
              for item, base, algorithm in downloads}
    with ThreadPoolExecutor(max_workers=6) as pool:
        list(pool.map(lambda entry: fetch(entry[0], cache, entry[1], entry[2]), unique.values()))
    print("Verified downloads:", len(unique), flush=True)
    for group, root in (("build", work / "cygwin"), ("runtime", output / "tools" / "cygwin")):
        unpack_packages([cache / Path(packages[name]["install"]["path"]).name for name in lock[group]], root)
        for executable in ("bash.exe", "perl.exe", "python3.12.exe"):
            if not (root / "bin" / executable).is_file():
                raise RuntimeError("Missing runtime executable: " + executable)
        cert = root / "etc" / "pki" / "tls" / "cert.pem"
        cert.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(cache / upstream["certificates"]["filename"], cert)
    for item in sources.values():
        shutil.copy2(cache / Path(item["path"]).name, source_dir)
    for name, item in upstream.items():
        if name == "certificates":
            continue
        archive = cache / item["filename"]
        shutil.copy2(archive, source_dir)
        destination = work / "sources" / name
        destination.mkdir(parents=True, exist_ok=True)
        with tarfile.open(archive) as source:
            prefix = source.getnames()[0].split("/")[0] + "/"
            for member in source:
                if member.name.startswith(prefix):
                    member.name = member.name[len(prefix):]
                    if member.name:
                        source.extract(member, destination, filter="data")
    wheelhouse = work / "python-packages"
    wheelhouse.mkdir(exist_ok=True)
    for item in python.values():
        shutil.copy2(cache / item["filename"], wheelhouse)
        if item["source"]:
            shutil.copy2(cache / item["source"]["filename"], source_dir)
    native_root = output / "tools" / "python"
    for name, item in native.items():
        destination = native_root if name == "python-runtime" else native_root / "Lib" / "site-packages"
        with zipfile.ZipFile(cache / item["filename"]) as archive:
            archive.extractall(destination)
        if item["source"]:
            shutil.copy2(cache / item["source"]["filename"], source_dir)
    (native_root / "python314._pth").write_text("python314.zip\n.\nLib/site-packages\nimport site\n")
    for name in ("cygwin.lock.json", "python.lock.json", "native-python.lock.json", "sources.lock.json"):
        shutil.copy2(HERE / name, output / "licenses")
    print("Build and portable runtime trees prepared.", flush=True)


if __name__ == "__main__":
    main()
