noinst_LTLIBRARIES = libloader.la
libloader_la_SOURCES = loader.c loader.h

libloader_la_CFLAGS = \
	-g -Wall -Werror -DDEBUG -D_GNU_SOURCE \
	-std=gnu99 \
	-I$(top_srcdir)/src/veos/dma \
	-I$(top_srcdir)/src/pseudo \
	-I$(srcdir)/../psm \
	-I$(srcdir)/../amm \
	-I$(srcdir)/../common \
	-I$(srcdir)/../sys \
	-I$(srcdir)/.. \
	-I$(top_srcdir)/vhcall/include \
	-I$(top_srcdir)/include \
	-I@prefix@/include
