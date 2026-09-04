#!/usr/bin/env bash
set -Eeuo pipefail
umask 022

usage() {
  echo "Usage: $0 <release-binary-dir> <new-output-dir> [version, default 0.3.0]" >&2
  echo "Optional: FIRSTCALL_ICON_ICNS=/absolute/path/icon.icns" >&2
  echo "Optional: FIRSTCALL_LICENSE_FILE=/absolute/path/LICENSE (defaults to repo LICENSE)" >&2
}

if [[ $# -lt 2 || $# -gt 3 ]]; then
  usage
  exit 2
fi
binary_dir="$1"
output_dir="$2"
version="${3:-0.3.0}"
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Version must be a numeric release version such as 0.3.0." >&2
  exit 2
fi
if [[ "$(uname -s)" != Darwin || "$(uname -m)" != arm64 ]]; then
  echo "This packager validates Apple Silicon macOS artifacts on an Apple Silicon Mac." >&2
  exit 2
fi
for command_name in codesign ditto lipo otool plutil python3 shasum tar; do
  command -v "$command_name" >/dev/null || {
    echo "Required tool is unavailable: $command_name" >&2
    exit 2
  }
done
binary_dir="$(cd "$binary_dir" && pwd -P)"
license_file="${FIRSTCALL_LICENSE_FILE:-$binary_dir/../../LICENSE}"
if [[ ! -f "$license_file" ]]; then
  echo "Missing distribution license; set FIRSTCALL_LICENSE_FILE: $license_file" >&2
  exit 2
fi
for binary in firstcall firstcall-cli; do
  if [[ ! -f "$binary_dir/$binary" || ! -x "$binary_dir/$binary" ]]; then
    echo "Missing executable release binary: $binary_dir/$binary" >&2
    exit 2
  fi
  if [[ "$(lipo -archs "$binary_dir/$binary")" != arm64 ]]; then
    echo "Expected an arm64 Mach-O binary: $binary" >&2
    exit 2
  fi
  while IFS= read -r dependency; do
    [[ -z "$dependency" ]] && continue
    case "$dependency" in
      /System/Library/* | /usr/lib/*) ;;
      *)
        echo "Unbundled dynamic dependency in $binary: $dependency" >&2
        exit 2
        ;;
    esac
  done < <(otool -L "$binary_dir/$binary" | tail -n +2 | sed -E 's/^[[:space:]]+//; s/ \(compatibility version.*$//')
done
[[ "$("$binary_dir/firstcall" --version)" == "firstcall $version" ]] || {
  echo "Desktop binary version does not match $version." >&2
  exit 2
}
[[ "$("$binary_dir/firstcall-cli" version)" == "firstcall-cli $version" ]] || {
  echo "CLI binary version does not match $version." >&2
  exit 2
}
"$binary_dir/firstcall-cli" --help >/dev/null

if [[ -e "$output_dir" || -L "$output_dir" ]]; then
  echo "Output path already exists; select a fresh directory: $output_dir" >&2
  exit 2
fi
mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd -P)"
stage_dir="$(mktemp -d "$output_dir/.package-stage.XXXXXX")"
cleanup() {
  if [[ -n "${stage_dir:-}" && "$stage_dir" == "$output_dir/.package-stage."* && -d "$stage_dir" ]]; then
    rm -rf -- "$stage_dir"
  fi
}
trap cleanup EXIT

package_name="firstcall-v${version}-aarch64-apple-darwin"
package_dir="$stage_dir/$package_name"
app_dir="$package_dir/FirstCall.app"
mkdir -p "$app_dir/Contents/MacOS" "$app_dir/Contents/Resources"
install -m 0755 "$binary_dir/firstcall" "$app_dir/Contents/MacOS/firstcall"
install -m 0755 "$binary_dir/firstcall-cli" "$app_dir/Contents/MacOS/firstcall-cli"
install -m 0755 "$binary_dir/firstcall-cli" "$package_dir/firstcall-cli"
install -m 0644 "$license_file" "$package_dir/LICENSE"
install -m 0644 "$license_file" "$app_dir/Contents/Resources/LICENSE"

icon_name=""
if [[ -n "${FIRSTCALL_ICON_ICNS:-}" ]]; then
  if [[ ! -f "$FIRSTCALL_ICON_ICNS" || "$FIRSTCALL_ICON_ICNS" != *.icns ]]; then
    echo "FIRSTCALL_ICON_ICNS must refer to an existing .icns file." >&2
    exit 2
  fi
  install -m 0644 "$FIRSTCALL_ICON_ICNS" "$app_dir/Contents/Resources/FirstCall.icns"
  icon_name="FirstCall.icns"
fi

python3 - "$app_dir" "$version" "$icon_name" <<'PY'
import pathlib
import plistlib
import sys

app, version, icon = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3]
info = {
    "CFBundleDevelopmentRegion": "en",
    "CFBundleDisplayName": "FirstCall",
    "CFBundleExecutable": "firstcall",
    "CFBundleIdentifier": "net.whago.firstcall",
    "CFBundleInfoDictionaryVersion": "6.0",
    "CFBundleName": "FirstCall",
    "CFBundlePackageType": "APPL",
    "CFBundleShortVersionString": version,
    "CFBundleVersion": version,
    "LSApplicationCategoryType": "public.app-category.developer-tools",
    "NSHighResolutionCapable": True,
    "NSSupportsAutomaticGraphicsSwitching": True,
}
if icon:
    info["CFBundleIconFile"] = icon
with (app / "Contents" / "Info.plist").open("wb") as file:
    plistlib.dump(info, file, sort_keys=True)
(app / "Contents" / "PkgInfo").write_bytes(b"APPL????")
PY

cat > "$package_dir/README-RELEASE.txt" <<EOF
FirstCall $version — Apple Silicon macOS

INSTALL
Move FirstCall.app to Applications, then open it.
The desktop app includes firstcall-cli in Contents/MacOS. Keep the entire
app bundle together so a copied MCP client configuration remains usable.

CLI
A separate firstcall-cli executable is included next to FirstCall.app.
From this extracted folder, run:
  ./firstcall-cli version
  ./firstcall-cli --help

To use the CLI embedded in Applications:
  /Applications/FirstCall.app/Contents/MacOS/firstcall-cli --help

RELEASE SCOPE
This archive contains the Apple Silicon macOS desktop and CLI binaries.
It does not contain Windows, Linux, or Intel Mac builds.
The app is ad-hoc signed for bundle integrity; it is not Apple notarized.
macOS may require you to approve opening this downloaded app.

SUPPORT
https://github.com/rad1092/firstcall-local-api-workbench/issues
EOF
cp "$package_dir/README-RELEASE.txt" "$app_dir/Contents/Resources/README-RELEASE.txt"

plutil -lint "$app_dir/Contents/Info.plist"
codesign --force --sign - "$app_dir/Contents/MacOS/firstcall-cli"
codesign --force --sign - "$package_dir/firstcall-cli"
codesign --force --sign - "$app_dir"
codesign --verify --deep --strict --verbose=2 "$app_dir"

tar_asset="$output_dir/$package_name.tar.gz"
zip_asset="$output_dir/$package_name.zip"
COPYFILE_DISABLE=1 tar -C "$stage_dir" -czf "$tar_asset" "$package_name"
ditto -c -k --norsrc --keepParent "$package_dir" "$zip_asset"

for format in tar.gz zip; do
  check_dir="$stage_dir/check-$format"
  mkdir "$check_dir"
  if [[ "$format" == tar.gz ]]; then
    tar -xzf "$tar_asset" -C "$check_dir"
  else
    ditto -x -k "$zip_asset" "$check_dir"
  fi
  extracted="$check_dir/$package_name"
  codesign --verify --deep --strict "$extracted/FirstCall.app"
  [[ "$("$extracted/FirstCall.app/Contents/MacOS/firstcall" --version)" == "firstcall $version" ]]
  [[ "$("$extracted/FirstCall.app/Contents/MacOS/firstcall-cli" version)" == "firstcall-cli $version" ]]
  [[ "$("$extracted/firstcall-cli" version)" == "firstcall-cli $version" ]]
  "$extracted/firstcall-cli" --help >/dev/null
done
(
  cd "$output_dir"
  shasum -a 256 "$package_name.tar.gz" "$package_name.zip" > SHA256SUMS.txt
  shasum -a 256 -c SHA256SUMS.txt
)
ditto "$app_dir" "$output_dir/FirstCall.app"
cp "$package_dir/README-RELEASE.txt" "$output_dir/README-RELEASE.txt"
echo "Validated macOS release artifacts: $output_dir"
echo "$tar_asset"
echo "$zip_asset"
echo "$output_dir/SHA256SUMS.txt"
