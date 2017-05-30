CC := clang
CFLAGS := -Wall -g -ferror-limit=0
LD := clang
LDFLAGS := -lpthread

SOURCES := $(shell find -maxdepth 1 -name "*.c")
OBJECTS := $(patsubst %.c, %.o, $(SOURCES))
HEADERS := $(shell find -maxdepth 1 -name "*.h")
LIB := libboar.a

TESTDIR := tests
TESTSOURCES := $(wildcard $(TESTDIR)/*.c)
TESTOBJECTS := $(patsubst %.c, %.o, $(TESTSOURCES))
TESTBINS := $(patsubst %.c, %, $(TESTSOURCES))

all: $(LIB)

$(LIB): $(OBJECTS)
	ar crs $@ $(OBJECTS)

all: $(OBJECTS)

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $<

test: $(TESTBINS)
	$(info compiling $(TESTBINS))

$(TESTDIR)/%: $(TESTDIR)/%.o $(LIB)
	$(LD) $(LDFLAGS) -o $@ $^

$(TESTDIR)/%.o: $(TESTDIR)/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(LIB)
	rm -f $(OBJECTS)
	rm -f $(TESTOBJECTS)
	rm -f $(TESTBINS)

.PHONY: clean
