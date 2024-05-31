## TFHE LIBRARY
TFHE_FOLDER_PATH = /usr/src/app/tfhe
TFHE_LDIR = $(TFHE_FOLDER_PATH)/lib
TFHE_IDIR = $(TFHE_FOLDER_PATH)/include

# Our code paths
DIR := $(shell pwd)
IDIR := $(DIR)/include
SDIR := $(DIR)/src
ODIR := $(DIR)/obj
BDIR := $(DIR)/bin

#compiler
CC := g++ -std=c++17
LD := $(CC)
INCS:= -I$(TFHE_IDIR) -I$(IDIR)
CFLAGS := $(INCS) -W -Wall -pedantic -O3 -g
LIBS:= -L$(TFHE_LDIR) -ltfhe-spqlios-fma
LDFLAGS := $(LIBS)

EXE := $(BDIR)/exe

SRC := $(wildcard $(SDIR)/*.cpp)
OBJ := $(patsubst $(SDIR)/%.cpp, $(ODIR)/%.o, $(SRC))

all: $(EXE)

$(EXE): $(OBJ)
	$(LD) -o $@ $^ $(LDFLAGS)

$(ODIR)/%.o: $(SDIR)/%.cpp
	$(CC) -c $^ $(CFLAGS) -o $@

.PHONY: clean

clean:
	rm $(ODIR)/*
