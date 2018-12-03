.PHONY: all
.DEFAULT_GOAL := all
cc:=gcc
clean:
	rm -rf packetCap

packetCap: pacc.c
	$(cc) -o $@ $<

all: packetCap
