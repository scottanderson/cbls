# Top-level Makefile for CBLS

# Set the build directory
BUILD_DIR = build
TARGET_BIN = $(BUILD_DIR)/bin/cbls

.PHONY: all clean start

all: $(BUILD_DIR)/Makefile
	$(MAKE) -C $(BUILD_DIR)
	@echo Build succeded

$(BUILD_DIR)/Makefile: CMakeLists.txt
	mkdir -p $(BUILD_DIR)
	cmake -B $(BUILD_DIR)

clean:
	rm -rf $(BUILD_DIR)

start: all
	$(TARGET_BIN)

