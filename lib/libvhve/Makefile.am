lib_LTLIBRARIES = libvhve.la
libvhve_la_SOURCES = \
	vhve_common.c \
	vhve_common.h \
	vhve_socket.c \
	vhve_socket.h \
	vhve.h \
	libvhve.c

libvhve_la_CFLAGS = \
	-I../../include \
        -I../libvepseudo/common \
	-I../../src/veos/main \
        -I@prefix@/include \
        -g -Wall -Werror -D_GNU_SOURCE \
	-fPIC -std=gnu99

libvhve_la_LDFLAGS = -lpthread -version-info 1:0:0

#libvhve_la_LIBADD = \
#	$(top_builddir)/lib/libveosprotoc/libveosprotoc.la

include_HEADERS = vhve.h
