#!/bin/sh
# PROTOTYPE: builds and ad-hoc signs build/AgentVMBlocks.app, then registers it
# with LaunchServices so a click can relaunch it when it isn't running.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
app=$root/build/AgentVMBlocks.app
rm -rf "$app"
mkdir -p "$app/Contents/MacOS"
cat > "$app/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleIdentifier</key><string>dev.agent-vm.prototype.blocks</string>
  <key>CFBundleName</key><string>agent-vm</string>
  <key>CFBundleDisplayName</key><string>agent-vm</string>
  <key>CFBundleExecutable</key><string>AgentVMBlocks</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleVersion</key><string>1</string>
  <key>CFBundleShortVersionString</key><string>0.0.1</string>
  <key>LSMinimumSystemVersion</key><string>12.0</string>
  <key>LSUIElement</key><true/>
  <key>ProtoRoot</key><string>$root</string>
</dict></plist>
EOF
swiftc -O -o "$app/Contents/MacOS/AgentVMBlocks" "$root/mac/Notifier.swift" \
  -framework AppKit -framework UserNotifications
codesign --force --sign - "$app"
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f "$app"
echo "built $app"
