#!/usr/bin/env bash
# Build independent C/C++ benchmark endpoints without changing Smithproxy's
# dependencies. Extra arguments are ordinary ngtcp2 CMake options.
set -euo pipefail
here=$(cd -- "$(dirname -- "$0")" && pwd)
destination=${1:-$here/../../../native-h3}
(( $# == 0 )) || shift
destination=$(realpath -m -- "$destination")
work=${destination}-build
[[ ! -e $destination/share/native-h3/SHA256SUMS ]] || {
    echo "Completed runtime already exists: $destination" >&2; exit 2;
}
mkdir -p "$work" "$destination"
jobs=${NATIVE_H3_BUILD_JOBS:-4}

# Check hashes on cached archives as well as new downloads. A version change
# must also review the small adapters against that version's example APIs.
fetch() {
    local project=$1 version=$2 checksum=$3
    local archive="$work/$project-$version.tar.xz"
    [[ -f $archive ]] || curl -fLSs \
        "https://github.com/ngtcp2/$project/releases/download/v$version/$project-$version.tar.xz" \
        -o "$archive"
    printf '%s  %s\n' "$checksum" "$archive" | sha256sum -c -
    [[ -d $work/$project-$version ]] || tar -xJf "$archive" -C "$work"
}
fetch ngtcp2 1.26.0 7804aa0fa1c39942ba322a90805824c37231f7675b08d0c3cc4332858a7b085e
fetch nghttp3 1.18.0 aad782c23d3f01bd4bb52c8bac7a553b631ef8115fd1612703df6183449fef19

source_dir="$work/ngtcp2-1.26.0"
adapter_hash=$(cat "$here/native-h3/"*.patch "$here/native-h3/benchmark.h" | sha256sum | cut -d ' ' -f1)
if [[ -e $source_dir/.smithproxy-benchmark && $(cat "$source_dir/.smithproxy-benchmark") != "$adapter_hash" ]]; then
    echo 'Cached source uses different adapters; choose a new runtime directory.' >&2
    exit 2
fi
if [[ ! -e $source_dir/.smithproxy-benchmark ]]; then
    for adapter in "$here/native-h3/"*.patch; do
        patch --batch --forward -d "$source_dir" -p1 < "$adapter"
    done
    cp "$here/native-h3/benchmark.h" "$source_dir/examples/"
    printf '%s\n' "$adapter_hash" > "$source_dir/.smithproxy-benchmark"
fi
cmake -S "$work/nghttp3-1.18.0" -B "$work/build-nghttp3" \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$destination" \
    -DENABLE_LIB_ONLY=ON -DENABLE_SHARED_LIB=ON -DENABLE_STATIC_LIB=OFF
cmake --build "$work/build-nghttp3" -j "$jobs"
cmake --install "$work/build-nghttp3"
cmake -S "$source_dir" -B "$work/build-ngtcp2" \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH="$destination" \
    -DENABLE_OPENSSL=ON -DENABLE_GNUTLS=OFF -DENABLE_LIB_ONLY=OFF \
    -DENABLE_SHARED_LIB=ON -DENABLE_STATIC_LIB=OFF "$@"
cmake --build "$work/build-ngtcp2" --target osslserver osslclient -j "$jobs"

mkdir -p "$destination/bin" "$destination/share/native-h3"
cp "$work/build-ngtcp2/examples/osslserver" "$destination/bin/h3-server.bin"
cp "$work/build-ngtcp2/examples/osslclient" "$destination/bin/h3-client.bin"
# Bundle the protocol libraries and libev for remote labs. TLS and ordinary
# system libraries remain distribution dependencies, like Smithproxy itself.
ldd "$destination/bin/h3-server.bin" > "$destination/share/native-h3/linkage.txt"
! grep -q 'not found' "$destination/share/native-h3/linkage.txt"
while read -r soname resolved; do
    if [[ $(realpath -m -- "$resolved") != $(realpath -m -- "$destination/lib/$soname") ]]; then
        cp -L -- "$resolved" "$destination/lib/$soname"
    fi
done < <(awk '/lib(ngtcp2|nghttp3|ev[.])/ {print $1, $3}' "$destination/share/native-h3/linkage.txt")
for endpoint in client server; do
    cat > "$destination/bin/h3-$endpoint" <<'WRAPPER'
#!/usr/bin/env bash
set -euo pipefail
prefix=$(dirname -- "$(dirname -- "$(realpath -e -- "$0")")")
export LD_LIBRARY_PATH="$prefix/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
exec "$prefix/bin/$(basename -- "$0").bin" "$@"
WRAPPER
    chmod 0755 "$destination/bin/h3-$endpoint"
done
cp "$source_dir/COPYING" "$destination/share/native-h3/ngtcp2-LICENSE"
cp "$work/nghttp3-1.18.0/COPYING" "$destination/share/native-h3/nghttp3-LICENSE"
printf 'ngtcp2=1.26.0\nnghttp3=1.18.0\ntransport=ngtcp2\ntls=OpenSSL\n' \
    > "$destination/share/native-h3/versions.txt"
printf 'adapters_sha256=%s\n' "$adapter_hash" >> "$destination/share/native-h3/versions.txt"
(cd "$destination" && sha256sum bin/* lib/*.so* > share/native-h3/SHA256SUMS)
printf 'Native H3 runtime ready: %s\n' "$destination"
