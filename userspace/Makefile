.PHONY: all clean

CFLAGS += -I../common -Iinclude -Wunused-variable -g

src := $(patsubst %.c,%.o,$(wildcard src/*.c))
hdr := $(wildcard include/*.h)
hdr_comm := $(wildcard ../common/*.h)
app := gnl-app

all: $(app)

$(app): $(src)
	gcc -o $(app) $(src)

$(src): $(hdr) $(hdr_comm)

clean:
	-@rm gnl-app
