"""Generate disposable documents with a public, fixed test password."""
import io
import sys
import subprocess
from pathlib import Path

import msoffcrypto
from docx import Document
from pypdf import PdfWriter

destination = Path(sys.argv[1])
destination.mkdir(parents=True, exist_ok=True)
password = "gui-fixture-only"
pdf = PdfWriter()
pdf.add_blank_page(width=100, height=100)
pdf.encrypt(password, algorithm="RC4-128")
pdf.write(destination / "synthetic.pdf")
document = Document()
document.add_paragraph("Synthetic GUI integration fixture, contains no user data.")
plain = io.BytesIO()
document.save(plain)
plain.seek(0)
with (destination / "synthetic.docx").open("wb") as output:
    msoffcrypto.OfficeFile(plain).encrypt(password, output)
(destination / "dictionary.txt").write_text(password + "\n", encoding="utf-8")
archive = destination / "synthetic.7z"
archive.unlink(missing_ok=True)
plain_file = destination / "fixture.txt"
plain_file.write_text("Synthetic archive fixture, contains no user data.\n", encoding="utf-8")
subprocess.run(["7z", "a", "-m0=lzma", "-mhe=on", "-p" + password,
                str(archive), str(plain_file)], check=True, stdout=subprocess.DEVNULL)
archive = destination / "synthetic.zip"
archive.unlink(missing_ok=True)
subprocess.run(["7z", "a", "-tzip", "-mem=AES256", "-p" + password,
                str(archive), str(plain_file)], check=True, stdout=subprocess.DEVNULL)
