noinst_LIBRARIES = libveptrace.a
libveptrace_a_SOURCES = ptrace_comm.c ptrace_comm.h

libveptrace_a_CFLAGS = \
	-g -Wall -Werror -D_GNU_SOURCE -std=gnu99 \
	-I$(srcdir)/.. \
	-I$(top_srcdir)/src/veos/dma \
	-I$(top_srcdir)/src/veos/psm \
	-I$(top_srcdir)/src/veos/main \
	-I$(top_srcdir)/src/veos/amm \
	-I$(top_srcdir)/src/pseudo \
	-I$(top_srcdir)/include/ \
	-I$(top_builddir)/lib/libveosprotoc \
        -I@prefix@/include
