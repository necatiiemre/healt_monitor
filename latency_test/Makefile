# HW Timestamp Latency Test - Makefile
#
# Kullanim:
#   make          - Normal derleme
#   make debug    - Debug sembolleri ile derleme
#   make clean    - Temizlik
#   make install  - /usr/local/bin'e kopyala
#

# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -Werror -std=gnu11 -I./include -I../shared
LDFLAGS = -lpthread -lrt

# Optimization
RELEASE_FLAGS = -O2 -march=native
DEBUG_FLAGS = -O0 -g3 -DDEBUG

# Directories
SRC_DIR = src
OBJ_DIR = obj
INC_DIR = include
SHARED_DIR = ../shared

# Target
TARGET = latency_test

# Source files (include shared sources)
SRCS = $(wildcard $(SRC_DIR)/*.c)
SHARED_SRCS = $(SHARED_DIR)/latency_results_shm.c
OBJS = $(SRCS:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
SHARED_OBJS = $(OBJ_DIR)/latency_results_shm.o
ALL_OBJS = $(OBJS) $(SHARED_OBJS)
DEPS = $(wildcard $(INC_DIR)/*.h) $(wildcard $(SHARED_DIR)/*.h)

# Default target
all: CFLAGS += $(RELEASE_FLAGS)
all: $(TARGET)

# Debug target
debug: CFLAGS += $(DEBUG_FLAGS)
debug: $(TARGET)

# Link
$(TARGET): $(ALL_OBJS)
	@echo "  LD    $@"
	@$(CC) $(ALL_OBJS) -o $@ $(LDFLAGS)
	@echo ""
	@echo "Build successful: $(TARGET)"
	@echo "Run with: sudo ./$(TARGET) -h"

# Compile src files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c $(DEPS) | $(OBJ_DIR)
	@echo "  CC    $<"
	@$(CC) $(CFLAGS) -c $< -o $@

# Compile shared files
$(OBJ_DIR)/latency_results_shm.o: $(SHARED_DIR)/latency_results_shm.c $(SHARED_DIR)/latency_results_shm.h | $(OBJ_DIR)
	@echo "  CC    $<"
	@$(CC) $(CFLAGS) -c $< -o $@

# Create obj directory
$(OBJ_DIR):
	@mkdir -p $(OBJ_DIR)

# Clean
clean:
	@echo "Cleaning..."
	@rm -rf $(OBJ_DIR) $(TARGET)
	@echo "Done."

# Install
install: $(TARGET)
	@echo "Installing to /usr/local/bin..."
	@sudo cp $(TARGET) /usr/local/bin/
	@sudo chmod +x /usr/local/bin/$(TARGET)
	@echo "Installed. Run with: sudo $(TARGET)"

# Uninstall
uninstall:
	@echo "Removing from /usr/local/bin..."
	@sudo rm -f /usr/local/bin/$(TARGET)
	@echo "Done."

# Help
help:
	@echo "HW Timestamp Latency Test - Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all       - Build with optimizations (default)"
	@echo "  debug     - Build with debug symbols"
	@echo "  clean     - Remove build files"
	@echo "  install   - Install to /usr/local/bin"
	@echo "  uninstall - Remove from /usr/local/bin"
	@echo "  help      - Show this help"
	@echo ""
	@echo "Usage after build:"
	@echo "  sudo ./$(TARGET) -h           # Show help"
	@echo "  sudo ./$(TARGET) -n 10        # Run test with 10 packets per VLAN"
	@echo "  sudo ./$(TARGET) -v           # Verbose output"
	@echo "  sudo ./$(TARGET) -I           # Show interface info"

# Phony targets
.PHONY: all debug clean install uninstall help

# Dependencies
$(OBJ_DIR)/main.o: $(SRC_DIR)/main.c $(INC_DIR)/common.h $(INC_DIR)/config.h $(INC_DIR)/hw_timestamp.h $(INC_DIR)/latency_test.h $(SHARED_DIR)/latency_results_shm.h
$(OBJ_DIR)/hw_timestamp.o: $(SRC_DIR)/hw_timestamp.c $(INC_DIR)/hw_timestamp.h $(INC_DIR)/common.h
$(OBJ_DIR)/packet.o: $(SRC_DIR)/packet.c $(INC_DIR)/packet.h $(INC_DIR)/config.h $(INC_DIR)/common.h
$(OBJ_DIR)/latency_test.o: $(SRC_DIR)/latency_test.c $(INC_DIR)/latency_test.h $(INC_DIR)/hw_timestamp.h $(INC_DIR)/packet.h $(INC_DIR)/common.h $(INC_DIR)/config.h
$(OBJ_DIR)/results.o: $(SRC_DIR)/results.c $(INC_DIR)/common.h $(INC_DIR)/config.h $(INC_DIR)/latency_test.h
