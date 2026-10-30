#!/bin/sh
# Rebuild the .dex test fixtures from source (benign test code, never executed).
# Needs a JDK and an Android SDK. Usage: tests/fixtures/dex_src/build.sh
set -e
SDK="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
BT="${BUILD_TOOLS:-$SDK/build-tools/33.0.2}"
JAR="${ANDROID_JAR:-$SDK/platforms/android-33/android.jar}"
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$HERE/../dex"
TMP="$(mktemp -d)"
for name in suspicious benign; do
  mkdir -p "$TMP/$name/classes" "$TMP/$name/dex"
  javac -nowarn -source 8 -target 8 -cp "$JAR" -d "$TMP/$name/classes" $(find "$HERE/$name" -name '*.java')
  "$BT/d8" --min-api 24 --lib "$JAR" --output "$TMP/$name/dex" $(find "$TMP/$name/classes" -name '*.class')
  cp "$TMP/$name/dex/classes.dex" "$OUT/$name.dex"
done
rm -rf "$TMP"
echo "Wrote $OUT/suspicious.dex and $OUT/benign.dex"
