noinst_LTLIBRARIES = libpseudosys.la
libpseudosys_la_SOURCES = sys_offload.c sys_offload.h sys_accelerated_io.h \
			sys_accelerated_io.c sys_accelerated_io.h

libpseudosys_la_CFLAGS = \
	-g -Wall -Werror -DDEBUG -D_GNU_SOURCE -std=gnu99 \
	-I$(top_srcdir)/src/veos/dma \
	-I$(top_srcdir)/src/pseudo \
	-I$(srcdir)/../ived \
	-I$(srcdir)/../psm \
	-I$(srcdir)/../amm \
	-I$(srcdir)/../loader \
	-I$(srcdir)/../common \
	-I$(top_srcdir)/vhcall/include \
	-I$(top_srcdir)/include \
	-I@prefix@/include
