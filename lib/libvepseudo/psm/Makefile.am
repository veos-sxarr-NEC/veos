noinst_LTLIBRARIES = libpseudopsm.la
libpseudopsm_la_SOURCES = \
	process_mgmt_comm.h \
	process_mgmt_comm.c \
	signal_comm.h \
	signal_comm.c \
	sys_process_mgmt.h \
	sys_process_mgmt.c \
	pseudo_ptrace.c \
	pseudo_ptrace.h \
	sys_signal.c \
	exception.h \
	ve_signal.h \
	exception.c

libpseudopsm_la_CFLAGS = \
	-g -Wall -Werror -DDEBUG -D_GNU_SOURCE -std=gnu99 \
	-I$(top_srcdir)/src/veos/dma \
	-I$(top_srcdir)/src/pseudo \
	-I$(srcdir)/../common \
	-I$(srcdir)/../amm \
	-I$(srcdir)/../loader \
	-I$(srcdir)/../sys \
	-I$(top_srcdir)/vhcall/include \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/lib/libveosprotoc \
	-I@prefix@/include \
	-I$(srcdir)/../ived
