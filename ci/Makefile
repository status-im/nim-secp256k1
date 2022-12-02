NIM_BUILD_SCRIPT_URL = https://raw.githubusercontent.com/status-im/nimbus-build-system/master/scripts/build_nim.sh
NIM_BUILD_SCRIPT = build_nim.sh

NPROC ?= $(shell nproc)
MAKEFLAGS ?= -j$(NPROC)

ifeq ($(detected_OS),Darwin)
 NCPU = $(shell sysctl -n hw.ncpu)
else ifeq ($(OS),Windows_NT)
 NCPU = $(NUMBER_OF_PROCESSORS)
 MAKE_CMD = mingw32-make
else ifneq ($(detected_OS),Linux)
 NCPU = $(shell nproc)
else
 NCPU = 1
 MAKE_CMD = make
endif

compiler: NIM_COMMIT ?= version-1-6
compiler: QUICK_AND_DIRTY_COMPILER ?= 1
compiler: QUICK_AND_DIRTY_NIMBLE ?= 1
compiler: CC ?= gcc
compiler: $(NIM_BUILD_SCRIPT)
	./build_nim.sh nim csources dist/nimble NimBinaries

$(NIM_BUILD_SCRIPT):
	curl -LSs $(NIM_BUILD_SCRIPT_URL) -o $(NIM_BUILD_SCRIPT)
	chmod +x $(NIM_BUILD_SCRIPT)
