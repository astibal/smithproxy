#!/usr/bin/env bash
# Build the HTTP/3 curl client required by the privileged patch-runner labs.
set -euo pipefail

usage() {
    echo "usage: $0 DESTINATION NATIVE_H3_PREFIX" >&2
    exit 2
}

[[ $# == 2 ]] || usage
destination=$(realpath -m -- "$1")
native_h3=$(realpath -e -- "$2")
[[ $destination == /* && $native_h3 == /* ]] || usage

curl_version=8.18.0
curl_sha256=40df79166e74aa20149365e11ee4c798a46ad57c34e4f68fd13100e2c9a91946
work=${destination}-build
archive="$work/curl-$curl_version.tar.xz"
source_dir="$work/curl-$curl_version"

for package in libngtcp2 libngtcp2_crypto_ossl libnghttp3; do
    [[ -f $native_h3/lib/pkgconfig/$package.pc ]] || {
        echo "Native H3 runtime is missing $package.pc: $native_h3" >&2
        exit 2
    }
done

if [[ -x $destination/bin/curl-h3 ]]; then
    "$destination/bin/curl-h3" --version | grep -q 'Features:.*HTTP3'
    echo "Completed HTTP/3 curl runtime already exists: $destination"
    exit 0
fi

[[ ! -e $destination ]] || {
    echo "Incomplete HTTP/3 curl runtime blocks destination: $destination" >&2
    exit 2
}
mkdir -p "$work" "$destination"

[[ -f $archive ]] || curl -fLSs \
    "https://curl.se/download/curl-$curl_version.tar.xz" -o "$archive"
printf '%s  %s\n' "$curl_sha256" "$archive" | sha256sum -c -
[[ -d $source_dir ]] || tar -xJf "$archive" -C "$work"

PKG_CONFIG_PATH="$native_h3/lib/pkgconfig" cmake \
    -S "$source_dir" -B "$work/build" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$destination" \
    -DCMAKE_PREFIX_PATH="$native_h3" \
    -DBUILD_SHARED_LIBS=ON \
    -DBUILD_CURL_EXE=ON \
    -DBUILD_EXAMPLES=OFF \
    -DBUILD_LIBCURL_DOCS=OFF \
    -DBUILD_MISC_DOCS=OFF \
    -DBUILD_TESTING=OFF \
    -DCURL_USE_OPENSSL=ON \
    -DUSE_NGTCP2=ON
cmake --build "$work/build" -j "${CURL_HTTP3_BUILD_JOBS:-4}"
cmake --install "$work/build"

# The patch runner copies this runtime independently of native-h3. Keep all
# non-system HTTP/3 libraries beside curl so the bundle remains self-contained.
mkdir -p "$destination/lib"
cp -a "$native_h3"/lib/libnghttp3.so* \
    "$native_h3"/lib/libngtcp2.so* \
    "$native_h3"/lib/libngtcp2_crypto_ossl.so* \
    "$destination/lib/"
mv "$destination/bin/curl" "$destination/bin/curl.bin"
cat > "$destination/bin/curl-h3" <<'WRAPPER'
#!/usr/bin/env bash
set -euo pipefail
prefix=$(dirname -- "$(dirname -- "$(realpath -e -- "$0")")")
export LD_LIBRARY_PATH="$prefix/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
exec "$prefix/bin/curl.bin" "$@"
WRAPPER
chmod 0755 "$destination/bin/curl-h3"

"$destination/bin/curl-h3" --version | tee "$destination/curl-http3-version.txt"
grep -q 'Features:.*HTTP3' "$destination/curl-http3-version.txt"
ldd "$destination/bin/curl.bin" > "$destination/curl-http3-linkage.txt"
! grep -q 'not found' "$destination/curl-http3-linkage.txt"
(cd "$destination" && sha256sum bin/* lib/*.so* > SHA256SUMS)
echo "HTTP/3 curl runtime ready: $destination"
