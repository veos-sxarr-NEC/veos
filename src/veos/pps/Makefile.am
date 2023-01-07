noinst_LIBRARIES = libvepps.a
libvepps_a_SOURCES = \
	ve_swap_init.c \
	ve_swap_thread.c \
	ve_swap_out.c \
	ve_swap_in.c \
	ve_swap_sysve.c \
	ve_swap.h \
	ve_swap_request.h

libvepps_a_CFLAGS = \
	-g -Wall -Werror -D_GNU_SOURCE -std=gnu99

libvepps_a_CPPFLAGS = \
	-I@prefix@/include \
	-I$(srcdir)/../main \
	-I$(srcdir)/../amm \
	-I$(srcdir)/../psm \
	-I$(srcdir)/../dma \
	-I$(srcdir)/../external \
	-I$(srcdir)/../ived \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib/libveosprotoc \
	-I$(top_srcdir)/lib/libived
