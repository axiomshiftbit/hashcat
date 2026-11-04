# Hashcat Desktop

Native C++17 / Qt 6 desktop interface for Windows 10/11 x64 and Linux x64.
Russian and English UI, managed queue, dictionary/combinator/mask/hybrid/association
forms, live status, pause/resume/checkpoint, per-task restore and results, profiles,
an unrestricted Hashcat argument editor, local capture conversion and built-in help.
This is an independent front end. The Hashcat engine is a separate process.

## Run

Windows: unpack the complete portable package and run `hashcat-desktop.exe`.
The packaged `hashcat/` directory must stay intact. Install the GPU manufacturer's
compute driver. If Windows reports a missing MSVC runtime, install Microsoft's
Visual C++ 2015-2022 x64 redistributable.

Linux (Debian 13 / Ubuntu 24.04 or newer): install `qt6-base-dev`, `hashcat` and your
compute runtime, then run `./hashcat-desktop`. CPU testing can use `pocl-opencl-icd`.
The Linux archive uses system Qt libraries. Build from source on other distributions.

Choose the Hashcat executable at the top and click **Load modes**. The **Help** page
explains the workflow in the selected language and searches the installed engine's
full CLI reference. The **Commands** page accepts every Hashcat argument, one per
line or as a JSON array, including commands without a dedicated form. It does not
interpret shell pipes or redirection.

Each managed task keeps an independent restore file, potfile and result file under
the application's local data directory (`HashcatDesktop/Hashcat Desktop` under
LocalAppData on Windows or the platform Qt application data directory on Linux).
`--data-dir PATH` selects another workspace. Only one application instance can use
a workspace. Removing a queue entry preserves its files. Profiles and workspace
metadata contain file paths and settings. Results stay local. The table shows the
first 2,000 records and at most 8 MiB; export copies the entire `hash:hex` file.

## Capture conversion

The same `hcxpcapngtool` engine as the official
[Hashcat converter](https://hashcat.net/cap2hashcat/) handles PCAPNG, PCAP and CAP,
including gzip input. `hcxhash2cap` additionally converts HCCAPX, HCCAP and legacy
PMKID/16800 input before extraction. Outputs: WPA/WPA2 mode 22000, EAP-MD5 mode 4800,
LEAP/MSCHAPv2 mode 5500 and TACACS+ mode 16100.

Install `hcxtools` on Linux. On Windows, install a WSL Linux distribution and install
`hcxtools` there; select the WSL option. The default WSL distribution is used and
paths are translated by `wslpath`. The upstream hcxtools project does not support
native Windows. No capture is sent to an online service. An empty or incomplete
capture is reported as an unsuccessful extraction. Existing output files are not
overwritten.

Archive, document and disk formats (ZIP, RAR, 7z, PDF, Office, KeePass, BitLocker,
VeraCrypt and others) need their own compatible extractors. They are not formats of
the website's capture converter. The built-in help explains importing extracted
hashes. This GUI does not claim to extract all of those formats itself.

## Build and test

Requirements: CMake 3.21+, C++17 compiler and Qt 6.4+ Widgets/Test development files.

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
PoCL CPU runtime. A dedicated GPU remains necessary for vendor-specific validation.

## License

The GUI source is MIT licensed, like Hashcat. Qt is dynamically linked and retains
its own LGPL/GPL/commercial licensing options. Distribution must preserve Qt license
notices and the user's ability to replace its shared libraries. hcxtools is a
separate external dependency and retains its upstream license.
