noinst_LIBRARIES = libvemain.a libvecommon.a
libvemain_a_SOURCES = \
	mm_common.h \
	veos.h \
	veos_init.c \
	veos_ipc.c \
	veos_handler.c \
	veos_handler.h \
	veos_main.c \
	sysve.c \
	userdma.c

libvemain_a_CFLAGS = \
	-g -Wall -Werror -D_GNU_SOURCE -std=gnu99 \
	-I$(top_srcdir)/lib/libvepseudo \
	-I$(srcdir)/../dma \
	-I$(srcdir)/../psm \
	-I$(srcdir)/../amm \
	-I$(srcdir)/../ived \
	-I$(srcdir)/../vemm \
	-I$(top_srcdir)/src/pseudo \
	-I$(top_srcdir)/lib/libived \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/lib/libveosprotoc \
	-I@prefix@/include

libvecommon_a_SOURCES = \
	vesync.h \
	vesync.c

libvecommon_a_CFLAGS = \
	-g -Wall -Werror -D_GNU_SOURCE -std=gnu99 \
	-I$(srcdir)/../dma \
	-I$(srcdir)/../amm \
	-I$(srcdir)/../psm \
	-I$(top_srcdir)/include \
	-I@prefix@/include
