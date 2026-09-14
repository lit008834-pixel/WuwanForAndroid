#!/usr/bin/env bash
set -euo pipefail
ndk_path=${1:?NDK path required}
output_path=${2:?Output directory required}
case "$(uname -s)" in
  Linux) host_tag=linux-x86_64 ;;
  Darwin) host_tag=darwin-x86_64 ;;
  *) echo 'Build eBPF helper on Linux or macOS' >&2; exit 1 ;;
esac
compiler_root="$ndk_path/toolchains/llvm/prebuilt/$host_tag/bin"
for pair in 'arm64-v8a:aarch64-linux-android' 'armeabi-v7a:armv7a-linux-androideabi' 'x86:i686-linux-android' 'x86_64:x86_64-linux-android'; do
  abi=${pair%%:*}
  triple=${pair#*:}
  mkdir -p "$output_path/$abi"
  "$compiler_root/${triple}26-clang" -std=c11 -O2 -fPIE -pie \
    -Wall -Wextra -Werror -fstack-protector-strong \
    -Wl,-z,relro,-z,now,-z,max-page-size=16384 \
    app/src/main/cpp/ebpf/loader.c -o "$output_path/$abi/libwuwan_ebpf.so"
done
