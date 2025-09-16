# MobileInsight ws_dissector Makefile for Desktop and Android
#
# This Makefile supports cross-platform builds for both desktop and Android devices.
# It automatically detects the host platform and configures the appropriate toolchain.
#
# Usage:
#   Desktop build (default): make
#   Android build:           make BUILD_TARGET=android
#   Help:                    make help

# Build target detection
# Set BUILD_TARGET=android for Android builds, defaults to desktop
BUILD_TARGET ?= desktop
ARCH := $(shell uname -m)

# Android NDK configuration (customize these paths as needed)
ANDROID_NDK_ROOT ?= $(HOME)/Library/Android/sdk/ndk/27.3.13750724
ANDROID_API_LEVEL ?= 24
ANDROID_ARCH ?= x86_64

# Desktop build configuration (macOS/Linux)
ifeq ($(BUILD_TARGET),desktop)
    BINARY_NAME = ws_desktop_dissector
    ifeq ($(shell uname -s),Darwin)
        # macOS detection
        ifeq ($(ARCH),arm64)
            # ARM64 Mac (Apple Silicon)
            PREFIX = /opt/homebrew
            ARCH_FLAGS = -arch arm64
        else
            # Intel Mac
            PREFIX = /usr/local
            ARCH_FLAGS = -arch x86_64
        endif
        CXX = g++
        CXXFLAGS = -std=c++11 $(ARCH_FLAGS) -O2 -Wall -fPIC
        LDFLAGS = $(ARCH_FLAGS) -L$(PREFIX)/lib
        INCLUDES = -I$(PREFIX)/include \
                   -I$(PREFIX)/include/glib-2.0 \
                   -I$(PREFIX)/lib/glib-2.0/include \
                   -I$(PREFIX)/include/wireshark
        LIBS = -lglib-2.0 -lwireshark -lwsutil -lwiretap
    else
        # Linux desktop
        PREFIX = /usr
        CXX = g++
        CXXFLAGS = -std=c++11 -O2 -Wall -fPIC
        LDFLAGS = -L$(PREFIX)/lib
        INCLUDES = -I$(PREFIX)/include \
                   -I$(PREFIX)/include/glib-2.0 \
                   -I$(PREFIX)/lib/glib-2.0/include \
                   -I$(PREFIX)/include/wireshark
        LIBS = -lglib-2.0 -lwireshark -lwsutil -lwiretap
    endif
endif

# Android build configuration
ifeq ($(BUILD_TARGET),android)
    BINARY_NAME = ws_dissector
    # Check if Android NDK is available
    ifeq ($(wildcard $(ANDROID_NDK_ROOT)/toolchains/llvm/prebuilt/*),)
        $(error Android NDK not found at $(ANDROID_NDK_ROOT). Please set ANDROID_NDK_ROOT to a valid Android NDK path.)
    endif

    # Android NDK toolchain setup
    ANDROID_TOOLCHAIN := $(ANDROID_NDK_ROOT)/toolchains/llvm/prebuilt/darwin-x86_64
    ANDROID_CC := $(ANDROID_TOOLCHAIN)/bin/$(ANDROID_ARCH)-linux-android$(ANDROID_API_LEVEL)-clang++
    # /Users/roastedbeans/Library/Android/sdk/ndk/27.3.13750724/toolchains/llvm/prebuilt/darwin-x86_64/bin
    ANDROID_SYSROOT := $(ANDROID_TOOLCHAIN)/sysroot

    # Check if Android compiler exists
    ifeq ($(wildcard $(ANDROID_CC)),)
        $(error Android compiler not found: $(ANDROID_CC). Please check your Android NDK installation.)
    endif

    CXX = $(ANDROID_CC)
    CXXFLAGS = -std=c++11 -O2 -Wall -fPIC --sysroot=$(ANDROID_SYSROOT) \
               -I$(ANDROID_SYSROOT)/usr/include \
               -D__ANDROID__ -D__ANDROID_API__=$(ANDROID_API_LEVEL)
    LDFLAGS = --sysroot=$(ANDROID_SYSROOT) \
              -L$(ANDROID_SYSROOT)/usr/lib/$(ANDROID_ARCH)-linux-android/$(ANDROID_API_LEVEL) \
              -L$(ANDROID_SYSROOT)/usr/lib/$(ANDROID_ARCH)-linux-android

    # Android-specific include paths (adjust based on your Android build setup)
    INCLUDES = -I$(ANDROID_NDK_ROOT)/sources/android/support/include \
               -I$(ANDROID_NDK_ROOT)/sources/cxx-stl/llvm-libc++/include \
               -I$(ANDROID_SYSROOT)/usr/include \
               -I$(ANDROID_SYSROOT)/usr/include/glib-2.0 \
               -I$(ANDROID_SYSROOT)/usr/lib/glib-2.0/include \
               -I$(ANDROID_SYSROOT)/usr/include/wireshark

    # Android libraries (only use libraries available in Android NDK)
    LIBS = -lc++_static -lc -lm -ldl
endif

# Source files
SOURCES = ws_dissector.cpp packet-aww.cpp
OBJECTS = $(SOURCES:.cpp=.o)

# Build rules
all: $(BINARY_NAME)

$(BINARY_NAME): $(OBJECTS)
	$(CXX) $(LDFLAGS) -o $@ $^ $(LIBS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(BINARY_NAME)

# Desktop build targets
desktop:
	$(MAKE) BUILD_TARGET=desktop

desktop-clean:
	$(MAKE) BUILD_TARGET=desktop clean

# Android build targets
android:
	$(MAKE) BUILD_TARGET=android

android-clean:
	$(MAKE) BUILD_TARGET=android clean

# Installation (desktop only)
install: $(BINARY_NAME)
	@if [ "$(BUILD_TARGET)" = "android" ]; then \
		echo "Android builds cannot be installed locally. Use 'make android' to build."; \
		exit 1; \
	fi
	cp $(BINARY_NAME) /usr/local/bin/

# Cross-platform help
help:
	@echo "MobileInsight ws_dissector Makefile"
	@echo ""
	@echo "Build targets:"
	@echo "  desktop     - Build for desktop (macOS/Linux) -> ws_desktop_dissector [default]"
	@echo "  android     - Build for Android using NDK -> ws_dissector"
	@echo "  all         - Build using default target"
	@echo ""
	@echo "Clean targets:"
	@echo "  clean       - Clean current build"
	@echo "  desktop-clean - Clean desktop build"
	@echo "  android-clean - Clean Android build"
	@echo ""
	@echo "Installation:"
	@echo "  install     - Install desktop build to /usr/local/bin"
	@echo ""
	@echo "Configuration variables:"
	@echo "  BUILD_TARGET=desktop|android    - Build target"
	@echo "  ANDROID_NDK_ROOT=path     - Android NDK root directory"
	@echo "  ANDROID_API_LEVEL=level   - Android API level (default: 21)"
	@echo "  ANDROID_ARCH=arch         - Android architecture (default: arm64-v8a)"
	@echo ""
	@echo "Examples:"
	@echo "  make                       # Build ws_desktop_dissector for desktop"
	@echo "  make android               # Build ws_dissector for Android"
	@echo "  make BUILD_TARGET=android ANDROID_NDK_ROOT=/path/to/ndk"
	@echo "  make clean && make android # Clean and build Android"

.PHONY: all clean install desktop android desktop-clean android-clean help