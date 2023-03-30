noinst_LTLIBRARIES = libpseudocommon_ve3.la

libpseudocommon_ve3_la_SOURCES = \
	sysve_os.c

libpseudocommon_ve3_la_CFLAGS = \
	-g -Wall -Werror -DDEBUG -D_GNU_SOURCE -std=gnu99 \
	-D_VE_ARCH_VE3_ \
	-I$(top_srcdir)/lib/libvepseudo \
	-I$(top_srcdir)/lib/libveosprotoc \
	-I$(top_srcdir)/lib/libvepseudo/common \
	-I$(top_srcdir)/include \
	-I@prefix@/include
