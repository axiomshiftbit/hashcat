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
`MainWindow`. The helper's optional system color-scheme API is guarded for Qt 6.4;
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

hcxtools and John Jumbo extractors are separate external dependencies with their
own licenses. Users select installed tools. No upstream John binaries are bundled.
The extractor catalog is a routing list, not a claim that Hashcat supports every
John format. Only recognized results can be saved/imported through the extractor.
