# MobileInsight Wireshark Dissector

This directory contains the MobileInsight Wireshark dissector implementation that supports cross-platform builds for both desktop and Android devices.

## Files

- `Makefile` - Cross-platform build system
- `ws_dissector.cpp` - Main dissector implementation
- `packet-aww.cpp` - AWW (Automator Wireshark Wrapper) packet dissector
- `packet-aww.h` - Header file for AWW dissector
- `config.h` - Platform-specific configuration header

## Building

### Desktop Build (macOS/Linux)

The default build target is desktop, which produces `ws_desktop_dissector`:

```bash
# Build for current platform (macOS/Linux) -> ws_desktop_dissector
make

# Or explicitly specify desktop target
make desktop

# Install to /usr/local/bin (macOS)
make install
```

### Android Build

To build for Android devices using the Android NDK, which produces `ws_dissector`:

```bash
# Build for Android (requires Android NDK) -> ws_dissector
make android

# Specify custom NDK path if needed
make ANDROID_NDK_ROOT=/path/to/android-ndk android

# Specify Android API level
make ANDROID_API_LEVEL=28 android
```

### Configuration Options

- `TARGET`: Build target (`desktop` or `android`)
- `ANDROID_NDK_ROOT`: Path to Android NDK (default: `/opt/android-ndk`)
- `ANDROID_API_LEVEL`: Android API level (default: `21`)
- `ANDROID_ARCH`: Android architecture (default: `arm64-v8a`)

### Clean Builds

```bash
# Clean current build
make clean

# Clean desktop build
make desktop-clean

# Clean Android build
make android-clean
```

## Platform Support

### Desktop

- **macOS**: Automatically detects ARM64 (Apple Silicon) vs Intel architectures
- **Linux**: Generic Linux build with standard paths

### Android

- **Architecture**: ARM64 (aarch64)
- **API Level**: Configurable (default: 21)
- **Toolchain**: Uses Android NDK clang++

## Requirements

### Desktop Build

- C++11 compatible compiler (g++ or clang++)
- Wireshark development headers
- GLib development headers

### Android Build

- Android NDK (with clang++ toolchain)
- Android sysroot with Wireshark and GLib headers
- Cross-compilation environment

## Usage Examples

```bash
# Quick desktop build (produces ws_desktop_dissector)
make

# Android build with custom NDK (produces ws_dissector)
make ANDROID_NDK_ROOT=$HOME/android-ndk-r25 android

# Build and show help
make help

# Clean everything and rebuild for Android
make clean && make android
```

## Troubleshooting

- Ensure Android NDK is properly installed and the path is correct
- For Android builds, make sure the sysroot contains required headers
- Use `make help` to see all available options and configuration variables

## Notes

- Android builds cannot be installed locally (they're for cross-compilation)
- The Makefile automatically detects the host platform for desktop builds
- All builds use C++11 standard and optimization flags
