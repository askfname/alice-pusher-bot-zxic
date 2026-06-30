#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
TOOLCHAIN_DIR="$ROOT_DIR/toolchain/host/usr/bin"
CROSS_PREFIX="$TOOLCHAIN_DIR/arm-buildroot-linux-uclibcgnueabi-"
CC="${CC:-${CROSS_PREFIX}gcc}"
STRIP="${STRIP:-${CROSS_PREFIX}strip}"
CFLAGS="${CFLAGS:--Os -ffunction-sections -fdata-sections}"
LDFLAGS="${LDFLAGS:--Wl,--gc-sections}"
MBEDTLS_DIR="$ROOT_DIR/lib-src/mbedtls-2.1.14"
SRC_FILE="$ROOT_DIR/src/alice-sms-pusher.c"
BUILD_DIR="$ROOT_DIR/.build"
OUTPUT_DIR="$ROOT_DIR/output"
TARGET="$OUTPUT_DIR/alice-pusher-bot"
TARGET_RUN="$OUTPUT_DIR/alice-pusher-bot.run"
EMBED_ASSET="$ROOT_DIR/tools/embed_asset.py"
SELF_EXTRACT="$ROOT_DIR/tools/make_self_extract.sh"
AVATAR_SRC="$ROOT_DIR/pic/miku_compressed.jpg"
SPONSOR_SRC="$ROOT_DIR/pic/sponsor_clean.jpg"

need_file() {
	if [ ! -f "$1" ]; then
		echo "错误：缺少文件: $1" >&2
		exit 1
	fi
}

need_exec() {
	if [ ! -x "$1" ]; then
		echo "错误：缺少可执行文件: $1" >&2
		exit 1
	fi
}

build_mbedtls_if_needed() {
	if [ -f "$MBEDTLS_DIR/library/libmbedtls.a" ] &&
	   [ -f "$MBEDTLS_DIR/library/libmbedx509.a" ] &&
	   [ -f "$MBEDTLS_DIR/library/libmbedcrypto.a" ]; then
		return
	fi

	if ! command -v cmake >/dev/null 2>&1; then
		echo "错误：mbedtls 静态库不存在，且当前环境没有 cmake，无法重建库。" >&2
		exit 1
	fi

	(
		cd "$MBEDTLS_DIR"
		rm -rf CMakeCache.txt CMakeFiles
		cmake -DCMAKE_C_COMPILER="$CC" \
			-DCMAKE_C_FLAGS="$CFLAGS" \
			-DCMAKE_EXE_LINKER_FLAGS="$LDFLAGS" \
			-DUSE_SHARED_MBEDTLS_LIBRARY=OFF \
			-DUSE_STATIC_MBEDTLS_LIBRARY=ON \
			-DMBEDTLS_BUILD_TESTS=OFF \
			-DMBEDTLS_BUILD_PROGRAMS=OFF \
			.
		make -j"$(nproc)"
	)
}

need_exec "$CC"
need_exec "$STRIP"
need_file "$SRC_FILE"
need_file "$EMBED_ASSET"
need_file "$SELF_EXTRACT"
need_file "$AVATAR_SRC"
need_file "$SPONSOR_SRC"
need_file "$MBEDTLS_DIR/include/mbedtls/ssl.h"

mkdir -p "$BUILD_DIR" "$OUTPUT_DIR"
python3 "$EMBED_ASSET" "$AVATAR_SRC" "$BUILD_DIR/avatar_asset.h" avatar_image image/jpeg
python3 "$EMBED_ASSET" "$SPONSOR_SRC" "$BUILD_DIR/sponsor_asset.h" sponsor_image image/jpeg

build_mbedtls_if_needed

"$CC" $CFLAGS -I"$MBEDTLS_DIR/include" "$SRC_FILE" -o "$TARGET" \
	$LDFLAGS -L"$MBEDTLS_DIR/library" \
	-lmbedtls -lmbedx509 -lmbedcrypto -pthread
"$STRIP" --strip-all "$TARGET"
"$SELF_EXTRACT" "$TARGET" "$TARGET_RUN"

echo "构建完成："
ls -lh "$TARGET" "$TARGET_RUN"
