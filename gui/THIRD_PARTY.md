# Third-party components

The combined Hashcat Desktop application is distributed under GPL-3.0-or-later.
The Hashcat engine remains a separate, unmodified MIT-licensed program.
Original notices on individual MIT files remain applicable.

## hashcat-gui

Source: https://github.com/rgroesslinger/hashcat-gui

Revision: `12bbfc62a866a7ba9a384509e752ce36b5401d9f`

Copyright: Rainer Groesslinger (original spelling retained in source headers).
License: GPL-3.0-or-later; full text in `third_party/hashcat_gui/LICENSE`.

The command builder, option model, validation helpers, settings dependency,
machine-readable hash parser and their original tests are incorporated directly.
The ordered, checkable file-list operations in `src/pathlist.cpp` are adapted from
`MainWindow`. Folder validation follows the non-dot-file rule from upstream
`PathMonitor`. Workspace loading additionally validates the document version and
structure before allowing writes, following upstream `StateFile` behavior. The helper's optional system color-scheme API is guarded for Qt 6.4;
Hashcat Desktop supplies its own palette. Other imported source is unmodified.

## Hashcat-Reactor

Source: https://github.com/jjsvs/Hashcat-Reactor

Revision: `53261c1a2d3c7433d91ac05fb6d130dffd69eb0a`

Copyright (c) 2025 rabbit. License: MIT; full text in
`third_party/hashcat_reactor/LICENSE`.

The `JOHN_TOOLS` registry from `backend/server.js` is incorporated as JSON.
The dashboard layout/palette, rolling graph, device-card presentation and hash
marker cleanup are adapted for native Qt. The React/Electron runtime and bundled
third-party executables are not distributed by this application.

## External dependencies and corresponding source

Qt is dynamically linked. The Windows package includes the exact Qt Base source
archive, licenses, third-party notices, SBOM and build configuration in `licenses/`.
Qt libraries may be rebuilt and replaced. Linux packages use system Qt libraries.

Both binary packages include `HashcatDesktop-source.tar.gz`, containing the GUI,
vendored code, tests, build instructions and the packaging workflow for that build.
Build using the commands in README.md; no signing key is needed.

hcxtools and John Jumbo extractors run as separate programs with their own licenses.
The Windows archive contains project-built hcxtools 8.0.0 and John Jumbo at revision
`5184bc0b8c105f8c5978b112e723d65b2de3e63e`, plus a portable Cygwin/Python/Perl runtime.
Exact package versions, source URLs and checksums are recorded in the
`packaging/*.lock.json` files, also included under `licenses/`. Corresponding source
archives are in `licenses/converter-sources/`, including runtime libraries and Python
modules. Upstream license notices remain in those archives and installed packages.
The build scripts are included in `HashcatDesktop-source.tar.gz`.

John's bitcoin2john import is patched to use the maintained `berkeleydb.db` binding
with the same API in place of `bsddb3.db`. Protobuf 7.36.2 uses its Python implementation for compatibility with the
upstream wallet schema. PDF and Kerberos XML extraction use embedded CPython 3.14.9
with current pyHanko, cryptography and lxml Windows wheels. Other Python converters use the Cygwin
interpreter, including the Berkeley DB and LevelDB extensions. The older Cygwin
cryptography and ABI-incompatible lxml packages are not distributed. Unix manual pages are omitted and runtime symlinks are
materialized as regular files for Windows Explorer extraction. No system Cygwin,
WSL, Python or Perl installation is needed. Linux uses user-installed converters.
The PDF and RADIUS catalog entries select John's newer Python extractors instead
of their older Perl variants.

Berkeley DB 18 and the converter components linking it are redistributed under
AGPL-3.0 terms. Their complete corresponding sources and notices are included in
the converter source archives. They run separately from the GUI and Hashcat.

App-local MSVC runtime DLLs come from Visual Studio's redistributable directory
and retain Microsoft's terms. Qt and converter runtimes can be replaced within the
application directory.
The extractor catalog is a routing list, not a claim that Hashcat supports every
John format. Only recognized results can be saved/imported through the extractor.
