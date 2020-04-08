PROJECT=router
SOURCES=list.c skel.c
SOURCES_CPP=router.cpp sun_lib.cpp
LIBRARY=nope
INCPATHS=include
LIBPATHS=.
LDFLAGS=
CFLAGS=-c -g -static -Wall
CC=g++

# Automatic generation of some important lists
OBJECTS=$(SOURCES:.c=.o)
OBJECTS_CPP=$(SOURCES_CPP:.cpp=.o)
INCFLAGS=$(foreach TMP,$(INCPATHS),-I$(TMP))
LIBFLAGS=$(foreach TMP,$(LIBPATHS),-L$(TMP))

# Set up the output file names for the different output types
BINARY=$(PROJECT)

all: $(SOURCES) $(SOURCES_CPP) $(BINARY)

$(BINARY): $(OBJECTS) $(OBJECTS_CPP)
	$(CC) $(LIBFLAGS) $(OBJECTS) $(OBJECTS_CPP) $(LDFLAGS) -o $@

.c.o:
	$(CC) $(INCFLAGS) $(CFLAGS) -fPIC $< -o $@

distclean: clean
	rm -f $(BINARY)

clean:
	rm -f *.o router

