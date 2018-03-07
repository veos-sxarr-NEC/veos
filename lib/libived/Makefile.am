SUBDIRS = 
noinst_LIBRARIES = libived.a

libived_a_SOURCES = \
	ived_common.h \
	ived_ipc.c \
	ived_ipc.h \
	ived_misc.h \
	ived_misc.c

libived_a_CFLAGS = \
	-g -Wall -Werror -D_GNU_SOURCE \
	-fPIC -std=gnu99 \
	-I$(srcdir) \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/lib/libveosprotoc \
	-I@prefix@/include
