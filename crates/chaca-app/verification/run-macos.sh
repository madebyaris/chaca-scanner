#!/bin/sh
# Local development bundle: no signing, installation, or copies outside this crate.
set -eu
crate_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
repo_dir=$(CDPATH= cd -- "$crate_dir/../.." && pwd)
app_dir="$crate_dir/verification/Chaca Native.app"
mkdir -p "$app_dir/Contents/MacOS"
rm -f "$app_dir/Contents/MacOS/chaca-app"
cp "$repo_dir/target/debug/chaca-app" "$app_dir/Contents/MacOS/chaca-app"
cat > "$app_dir/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleName</key><string>Chaca Native</string>
<key>CFBundleDisplayName</key><string>Chaca Native</string>
<key>CFBundleIdentifier</key><string>com.chaca.native</string>
<key>CFBundleExecutable</key><string>chaca-app</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>0.7.0</string>
<key>NSHighResolutionCapable</key><true/>
</dict></plist>
PLIST
printf '%s\n' "$app_dir"
