"""Check portable runtime imports and the complete GUI extractor catalog."""
import argparse
import json
import os
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle", type=Path)
    args = parser.parse_args()
    root = args.bundle.resolve()
    runtime = root / "tools/cygwin/bin"
    john = root / "tools/john/run"
    env = os.environ.copy()
    for name in ("PYTHONHOME", "PYTHONPATH", "PERL5LIB", "OPENSSL_CONF", "OPENSSL_MODULES"):
        env.pop(name, None)
    env.update(PATH=os.pathsep.join([str(runtime), str(john), env["SystemRoot"] + "\\System32"]),
               LC_ALL="C.UTF-8", PYTHONUTF8="1", PYTHONNOUSERSITE="1", PYTHONDONTWRITEBYTECODE="1")

    def run(command, success=True):
        result = subprocess.run([str(arg) for arg in command], env=env, cwd=john,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=40)
        output = result.stdout.decode("utf-8", errors="replace")
        if success and result.returncode:
            raise RuntimeError(str(command[0]) + "\n" + output)
        for error in ("ModuleNotFoundError", "ImportError:", "Can't locate ", "error while loading shared libraries"):
            if error in output:
                raise RuntimeError(str(command[0]) + "\n" + output)
        return output

    python, perl = runtime / "python3.12.exe", runtime / "perl.exe"
    run([python, "-c", "import ssl, sqlite3, lxml.etree, olefile, Crypto.Cipher.AES, Crypto.Cipher.DES3, "
         "pyasn1.codec.ber.decoder, pyhanko.pdf_utils.reader, asn1crypto, scapy.all, "
         "berkeleydb.db, plyvel, google.protobuf, simplejson; print('Python dependencies OK')"])
    run([perl, "-MCompress::Raw::Lzma", "-MFile::Basename", "-e", "print qq(Perl dependencies OK\\n)"])
    run([root / "tools/hcxtools/hcxpcapngtool.exe", "--version"])
    run([root / "tools/hcxtools/hcxhash2cap.exe", "--version"])
    run([john / "john.exe", "--list=build-info"])
    catalog = json.loads((Path(__file__).parents[1] / "third_party/hashcat_reactor/tool_registry.json").read_text())
    resolved = {}
    for key, item in catalog.items():
        name = item["name"]
        preferred = {"python": ".py", "perl": ".pl", "native": ".exe"}[item["kind"]]
        candidates = [john / (name + extension) for extension in (preferred, ".exe", ".py", ".pl", "")]
        tool = next((path for path in candidates if path.is_file()), None)
        if tool is None:
            raise RuntimeError("Missing extractor: " + key)
        command = [tool]
        if tool.suffix in (".py", ".pl"):
            command.insert(0, python if tool.suffix == ".py" else perl)
        run(command, success=False)
        resolved[key] = tool.name
    (root / "tools/manifest.json").write_text(json.dumps({"catalog": resolved, "runtime": "Cygwin"}, indent=2) + "\n")
    print("All", len(resolved), "catalog tools found and launched with isolated PATH.")


if __name__ == "__main__":
    main()
