VERSION    := 0.7

# Git info for versioning
GIT_HASH   := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
GIT_DIRTY  := $(shell git status --porcelain 2>/dev/null)
BUILD_TYPE ?= dev
ifeq ($(BUILD_TYPE),stable)
RELEASE_VERSION := v$(VERSION)-$(if $(GIT_DIRTY),$(shell date +"%Y%m%d%H%M%S"),$(GIT_HASH))
else
RELEASE_VERSION := v$(VERSION)-$(BUILD_TYPE)-$(if $(GIT_DIRTY),$(shell date +"%Y%m%d%H%M%S"),$(GIT_HASH))
endif

SRC_FILES := $(shell find src -type f)
ELFLDR_FILE := $(shell basename $(shell ls src/elfldr-ps5-*.elf 2>/dev/null | head -n 1) 2>/dev/null)
KEXP_FILE := $(shell basename $(shell ls src/kexp-*.bin 2>/dev/null | head -n 1) 2>/dev/null)

all: y2jb_update.zip

y2jb_update.zip: $(SRC_FILES)
	rm -rf build_dir
	cp -r src build_dir
	sed -i.bak "s/@@VERSION@@/$(RELEASE_VERSION)/g" build_dir/main.js && rm build_dir/main.js.bak
	sed -i.bak "s/@@ELFLDR_FILE@@/$(ELFLDR_FILE)/g" build_dir/aioshellcode.js && rm build_dir/aioshellcode.js.bak
	sed -i.bak "s/@@KEXP_FILE@@/$(KEXP_FILE)/g" build_dir/aioshellcode.js && rm build_dir/aioshellcode.js.bak
	python3 third_party/y2jb-updater/create_update_package.py build_dir
	rm -rf build_dir

clean:
	rm -rf build_dir y2jb_update.zip

.PHONY: all clean print-version
print-version:
	@echo $(RELEASE_VERSION)
