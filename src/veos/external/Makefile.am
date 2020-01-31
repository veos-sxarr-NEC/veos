noinst_LIBRARIES = libveexternal.a
libveexternal_a_SOURCES = rpm_comm.c rpm_comm.h

libveexternal_a_CFLAGS = \
	-g -Wall -Werror -D_GNU_SOURCE -std=gnu99 \
	-I$(top_srcdir)/src/veos/dma \
	-I$(top_srcdir)/src/veos/psm \
	-I$(top_srcdir)/src/veos/main \
	-I$(top_srcdir)/src/veos/amm \
	-I$(top_srcdir)/src/veos/pps \
	-I$(top_srcdir)/src/pseudo \
	-I$(top_srcdir)/include/ \
	-I$(top_builddir)/lib/libveosprotoc \
        -I@prefix@/include
