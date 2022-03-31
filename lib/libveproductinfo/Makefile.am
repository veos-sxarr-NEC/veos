lib_LTLIBRARIES = libveproductinfo.la
libveproductinfo_la_SOURCES = \
	productinfo.h \
	libveproductinfo.c 

libveproductinfo_la_CFLAGS = \
	-I../../include \
        -I../libvepseudo/common \
	-I../../src/veos/main \
        -I@prefix@/include \
	-I$(top_builddir)/lib/libveosprotoc \
        -g -Wall -Werror -D_GNU_SOURCE \
	-fPIC -std=gnu99

libveproductinfo_la_LDFLAGS = -version-info 1:0:0

include_HEADERS = productinfo.h
