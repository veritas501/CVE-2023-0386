.PHONY: all

all: poc

poc: poc.c
	gcc poc.c -o poc -static -no-pie -s -lfuse3 \
	    -L ./libfuse -I ./libfuse/include
