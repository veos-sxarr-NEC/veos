noinst_LTLIBRARIES = libpseudopsm_ve1.la

libpseudopsm_ve1_la_SOURCES = \
	exception.c

libpseudopsm_ve1_la_CFLAGS = \
	-g -Wall -Werror -DDEBUG -D_GNU_SOURCE -std=gnu99 \
	-D_VE_ARCH_VE1_ \
	-I$(top_srcdir)/lib/libvepseudo \
	-I$(top_srcdir)/lib/libvepseudo/common \
	-I$(top_srcdir)/lib/libvepseudo/psm \
	-I$(top_srcdir)/include \
	-I@prefix@/include
