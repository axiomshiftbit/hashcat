"""Copy John notices as regular files for native Windows archive tools."""
import hashlib
import json
from pathlib import Path
import sys
import tarfile

root = Path(sys.argv[1])
lock = json.loads((Path(__file__).parent / "sources.lock.json").read_text())["john"]
archive = root / "licenses/converter-sources" / lock["filename"]
with archive.open("rb") as stream:
    if hashlib.file_digest(stream, "sha256").hexdigest() != lock["sha256"]:
        raise ValueError("John source checksum mismatch")
with tarfile.open(archive) as source:
    prefix = source.getnames()[0].split("/")[0]
    for destination, name in (("doc/LICENSE", "LICENSE"), ("doc/README", "README.md"), ("LICENSE", "LICENSE")):
        path = root / "tools/john" / destination
        path.unlink(missing_ok=True)
        path.write_bytes(source.extractfile(prefix + "/" + name).read())
