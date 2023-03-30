noinst_LTLIBRARIES = libpseudopsm_ve3.la

libpseudopsm_ve3_la_SOURCES = \
	exception.c

libpseudopsm_ve3_la_CFLAGS = \
	-g -Wall -Werror -DDEBUG -D_GNU_SOURCE -std=gnu99 \
	-D_VE_ARCH_VE3_ \
	-I$(top_srcdir)/lib/libvepseudo \
	-I$(top_srcdir)/lib/libvepseudo/common \
	-I$(top_srcdir)/lib/libvepseudo/psm \
	-I$(top_srcdir)/include \
	-I@prefix@/include
