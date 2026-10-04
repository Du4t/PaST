PROJECT_ROOT := $(shell cd .. && pwd)
AFL_DIR := $(PROJECT_ROOT)/third_party/AFLplusplus
MUTATOR_DIR := $(shell pwd)

CC ?= gcc
CFLAGS := -O2 -g -Wall -Wextra -Wno-unused-parameter -fPIC \
          -I$(MUTATOR_DIR)/include \
          -I$(AFL_DIR)/include

LDFLAGS := -shared

SOURCES := $(wildcard src/*.c)
OBJECTS := $(SOURCES:.c=.o)
TARGET := libftfuzz_mutator.so

.PHONY: all clean test

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

test: $(TARGET)
	$(CC) -O2 -g -I$(MUTATOR_DIR)/include -o tests/test_policy_loader tests/test_policy_loader.c src/policy_loader.o
	$(CC) -O2 -g -I$(MUTATOR_DIR)/include -o tests/test_numeric_mutation tests/test_numeric_mutation.c src/numeric_mutation.o src/policy_loader.o
	tests/test_policy_loader
	tests/test_numeric_mutation

clean:
	rm -f src/*.o $(TARGET) tests/test_policy_loader tests/test_numeric_mutation
