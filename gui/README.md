# Hashcat Desktop

Native C++17 / Qt 6 desktop interface for Windows 10/11 x64 and Linux x64.
Russian and English UI, managed queue, dictionary/combinator/mask/hybrid/association
forms, live status, pause/resume/checkpoint, per-task restore and results, profiles,
an unrestricted Hashcat argument editor, local capture conversion and built-in help.
This is an independent front end. The Hashcat engine is a separate process.

The integrated command builder and validators come from
[rgroesslinger/hashcat-gui](https://github.com/rgroesslinger/hashcat-gui).
The dashboard, rolling speed graph, device cards and extractor catalog are adapted
from [Hashcat-Reactor](https://github.com/jjsvs/Hashcat-Reactor).
See THIRD_PARTY.md for exact revisions, licenses and modifications.

Forms cover all ten Hashcat 8 attack modes: 0, 1, 3, 4, 5, 6, 7, 8, 9 and 12.
Modes 4/5/8/12 require Hashcat 8. Checked wordlists/rules execute in list order;
profiles preserve unchecked entries too. For PCFG, table and generic feeds, open
the matching extended-options tab. Mode 12 uses one `?w` and optionally one `?q`
after it for a second wordlist; it does not accept incrementing.

## Run

Windows: unpack the complete portable package and run `hashcat-desktop.exe`.
Keep the `hashcat/` and `tools/` directories intact. Hashcat, Qt, the MSVC runtime,
hcxtools, John Jumbo, Python, Perl and converter dependencies are included.
No WSL or system Python/Perl installation is required. Install the GPU manufacturer's
compute driver for GPU work.

Linux (Debian 13 / Ubuntu 24.04 or newer): install `qt6-base-dev`, `hashcat` and your
compute runtime, then run `./hashcat-desktop`. CPU testing can use `pocl-opencl-icd`.
The Linux archive uses system Qt libraries. Build from source on other distributions.

Choose the Hashcat executable at the top and click **Load modes**. The **Help** page
explains the workflow in the selected language and searches the installed engine's
full CLI reference. The **Commands** page accepts every Hashcat argument, one per
line or as a JSON array, including commands without a dedicated form. It does not
interpret shell pipes or redirection.

Each managed task keeps an independent restore file and result file, and a potfile
except in association mode (where Hashcat forbids it), under
the application's local data directory (`HashcatDesktop/Hashcat Desktop` under
LocalAppData on Windows or the platform Qt application data directory on Linux).
`--data-dir PATH` selects another workspace. Only one application instance can use
a workspace. Removing a queue entry preserves its files. Profiles and workspace
metadata contain file paths and settings. An unreadable, malformed or unsupported
workspace file is preserved and saving is disabled until another data directory
is selected or the file is repaired. Results stay local. The table shows the
first 2,000 records and at most 8 MiB; export copies the entire `hash:hex` file.

## Capture conversion

The same `hcxpcapngtool` engine as the official
[Hashcat converter](https://hashcat.net/cap2hashcat/) handles PCAPNG, PCAP and CAP,
including gzip input. `hcxhash2cap` additionally converts HCCAPX, HCCAP and legacy
PMKID/16800 input before extraction. Outputs: WPA/WPA2 mode 22000, EAP-MD5 mode 4800,
LEAP/MSCHAPv2 mode 5500 and TACACS+ mode 16100.

Install `hcxtools` on Linux. Windows uses the included hcxtools build through a
portable Cygwin runtime, selected automatically. This project builds and tests that
Windows port; upstream hcxtools does not support Windows. WSL is an optional
alternative using its default distribution and `wslpath`.
No capture is sent to an online service. An empty or incomplete
capture is reported as an unsuccessful extraction. Existing output files are not
overwritten.

The second converter tab integrates the 78-entry Reactor catalog, including ZIP,
RAR, 7z, PDF, Office, KeePass and other formats. Windows includes the appropriate
[John Jumbo](https://github.com/openwall/john) tools and dependencies. Leave the
interpreter field empty for automatic selection. On Linux install John Jumbo and
the dependencies for the formats you use, then select its run directory. Additional
arguments are passed literally, one per line; the input path is appended last.
The application removes John filename metadata from `$...$` records and asks the
selected Hashcat to identify compatible modes before saving. Unsupported output,
empty output, failures and cancellation do not create a result. Existing files
are never replaced. Select the appropriate mode when identification is ambiguous.
Each tool has its own supported versions and dependencies; catalog membership
does not mean all 78 formats are supported by Hashcat. Binary extractor outputs
and formats without `$...$` records require their own external preparation.

## Build and test

Requirements: CMake 3.21+, C++17 compiler and Qt 6.4+ Widgets/Concurrent/Test files.

```sh
cmake -S gui -B gui/build -DCMAKE_BUILD_TYPE=Release
cmake --build gui/build --config Release --parallel 2
ctest --test-dir gui/build -C Release --output-on-failure
```

For Windows, configure with the MSVC x64 toolchain and set `CMAKE_PREFIX_PATH` to
the matching Qt directory. Put Qt's `bin` directory on PATH when running tests.
Use `windeployqt --release path/to/hashcat-desktop.exe` to deploy runtime libraries.

Set `REAL_HASHCAT` to an absolute engine path to enable real CPU integration tests.
Tests create synthetic data in temporary directories. No user password files are
used. The GUI tests exercise actual widgets and a small deterministic subprocess
fixture. Fixture tests do not establish GPU-driver compatibility.

The manual GitHub Actions workflow `Desktop GUI` builds both platforms, tests them,
and produces downloadable packages. Its Windows integration installs the official
Intel CPU OpenCL runtime. A dedicated GPU remains necessary for vendor-specific validation.

## License

The combined GUI is GPL-3.0-or-later; see LICENSE and THIRD_PARTY.md. Hashcat's
separate engine remains MIT licensed. Both packages include corresponding GUI
source and build scripts in `HashcatDesktop-source.tar.gz`. Qt is dynamically linked and retains
its own LGPL/GPL/commercial licensing options. Distribution must preserve Qt license
notices and the user's ability to replace its shared libraries. hcxtools is a
separate program and retains its upstream license. Windows converter runtime
versions, checksums and corresponding sources are included under `licenses/`.
Build scripts and dependency locks are in `gui/packaging/`. The bundle includes
source archives for redistributed Cygwin and Python packages, John and hcxtools.
The Windows archive includes the unmodified Qt Base 6.12.0 sources, licenses,
third-party notices in those sources, build configuration and SBOM in `licenses/`.
You may rebuild and replace its Qt shared libraries, including for debugging changes.
