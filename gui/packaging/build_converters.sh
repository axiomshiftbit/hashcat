#!/usr/bin/env bash
set -euo pipefail
export PATH=/usr/local/bin:/usr/bin:/bin
export LC_ALL=C.UTF-8
export PYTHONNOUSERSITE=1
export SSL_CERT_FILE=/etc/pki/tls/cert.pem
work=$(cygpath -u "$1")
output=$(cygpath -u "$2")
packaging=$(cygpath -u "$3")

cd "$work/sources/hcxtools"
make -j4 PRODUCTION=1 hcxpcapngtool hcxhash2cap
mkdir -p "$output/tools/hcxtools"
cp hcxpcapngtool.exe hcxhash2cap.exe "$output/tools/hcxtools/"
cp license.txt "$output/tools/hcxtools/LICENSE.txt"

cd "$work/sources/john/src"
./configure --disable-native-tests --disable-simd --disable-openmp --disable-opencl --disable-pcap
make -j4
mkdir -p "$output/tools/john"
cp -r ../run ../doc ../README.md "$output/tools/john/"
# The maintained Berkeley DB binding preserves the API used by bitcoin2john.
sed -i 's/import bsddb3.db as bsddb_db/import berkeleydb.db as bsddb_db/' "$output/tools/john/run/bitcoin2john.py"

cmake -S "$work/sources/leveldb" -B "$work/leveldb-build" \
  -DCMAKE_POLICY_VERSION_MINIMUM=3.5 -DCMAKE_BUILD_TYPE=Release \
  -DLEVELDB_BUILD_TESTS=OFF -DLEVELDB_BUILD_BENCHMARKS=OFF \
  -DBUILD_SHARED_LIBS=OFF -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
  -DCMAKE_INSTALL_PREFIX=/usr/local
cmake --build "$work/leveldb-build" -j2
cmake --install "$work/leveldb-build"
export BERKELEYDB_DIR=/usr
export CFLAGS='-I/usr/local/include'
export CXXFLAGS='-I/usr/local/include'
export LDFLAGS='-L/usr/local/lib'
python3.12 -m pip install --no-index --no-deps --no-build-isolation --require-hashes \
  --find-links "$work/python-packages" \
  --target "$output/tools/cygwin/lib/python3.12/site-packages" \
  -r "$packaging/python-requirements.txt"
cp "$packaging/python-requirements.txt" "$output/licenses/"
printf '%s\n' 'Portable hcxtools, John Jumbo, Python and Perl assembled.'
