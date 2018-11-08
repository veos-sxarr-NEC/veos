noinst_LTLIBRARIES = libpseudoamm.la
libpseudoamm_la_SOURCES = \
	mm_transfer.c \
	mm_transfer.h \
	sys_mm.c \
	sys_mm.h \
	vemva_mgmt.c \
	vemva_mgmt.h \
	sys_shm.c \
	sys_shm.h

libpseudoamm_la_CFLAGS = \
	-g -Wall -Werror -DDEBUG -D_GNU_SOURCE \
	-std=gnu99 \
	-I$(top_srcdir)/src/veos/dma \
	-I$(top_srcdir)/src/pseudo \
	-I$(srcdir)/../psm \
	-I$(srcdir)/../common \
	-I$(srcdir)/../loader \
	-I$(srcdir)/../sys \
	-I$(top_srcdir)/vhcall/include \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/lib/libveosprotoc \
	-I@prefix@/include
