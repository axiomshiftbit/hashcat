"""Copy Qt's license texts in one streaming pass over its source archive."""
from pathlib import Path, PurePosixPath
import shutil
import sys
import tarfile

destination = Path(sys.argv[2]) / 'Qt-LICENSES'
destination.mkdir(parents=True, exist_ok=True)
with tarfile.open(sys.argv[1], mode='r|xz') as archive:
    for member in archive:
        parts = PurePosixPath(member.name).parts
        if member.isfile() and len(parts) == 3 and parts[1] == 'LICENSES':
            with archive.extractfile(member) as source, (destination / parts[2]).open('wb') as output:
                shutil.copyfileobj(source, output)
for required in ('LGPL-3.0-only.txt', 'GPL-3.0-only.txt'):
    if not (destination / required).is_file():
        raise SystemExit('Qt source archive is missing ' + required)
print('Qt license texts copied:', len(list(destination.iterdir())))
