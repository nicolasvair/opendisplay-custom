#!/bin/zsh
# Build the custom Release sender, signed with the Developer ID certificate,
# and install it as /Applications/OpenDisplay Custom.app.
set -e
cd "$(dirname "$0")"

APP_NAME="OpenDisplay Custom"
BUNDLE_ID="com.peetzweg.opensidecar.mac.custom"
TEAM="8ZMVCPUWKW"

xcodegen generate
xcodebuild -project OpenSidecar.xcodeproj -scheme OpenSidecarMac \
  -configuration Release -derivedDataPath build \
  DEVELOPMENT_TEAM="$TEAM" CODE_SIGN_STYLE=Manual \
  CODE_SIGN_IDENTITY="Developer ID Application" \
  OTHER_CODE_SIGN_FLAGS=--timestamp ENABLE_HARDENED_RUNTIME=YES \
  build | grep -E "error:|BUILD"

SRC="build/Build/Products/Release/$APP_NAME.app"
codesign --verify --deep --strict "$SRC"

osascript -e "quit app id \"$BUNDLE_ID\"" 2>/dev/null || true
while pgrep -f "$APP_NAME.app/Contents/MacOS" >/dev/null; do /bin/sleep 0.5; done

rm -rf "/Applications/$APP_NAME.app"
ditto "$SRC" "/Applications/$APP_NAME.app"
open "/Applications/$APP_NAME.app"
echo "$APP_NAME installed and running."
