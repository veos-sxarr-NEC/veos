noinst_LTLIBRARIES = libpseudocommon.la
libpseudocommon_la_SOURCES = \
	debugtool.c \
	handle.h \
	ve_socket.h \
	sys_common.h \
	vhcall_os.h \
	debugtool.h \
	ve_socket.c \
	vhcall_os.c \
	sys_common.c \
	syscall_impl.h \
	sysve_os.c \
	sysve_os.h \
	list.h \
	sys_veaio.c \
	sys_veaio.h

BUILT_SOURCES = \
	ve_syscall_no.h \
	ve_syscall_handler.h

libpseudocommon_la_CFLAGS = \
	-g -Wall -Werror -DDEBUG -D_GNU_SOURCE -std=gnu99 \
	-I$(top_srcdir)/src/veos/dma \
	-I$(top_srcdir)/src/pseudo \
	-I$(srcdir)/../psm \
	-I$(srcdir)/../amm \
	-I$(srcdir)/../loader \
	-I$(srcdir)/../sys \
	-I$(srcdir)/../ived \
	-I$(top_srcdir)/vhcall/include \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/lib/libveosprotoc \
	-I@prefix@/include

dist_noinst_DATA = syscall.tbl syscalltbl.sh

include_HEADERS = \
	libvepseudo.h

ve_syscall_no.h ve_syscall_handler.h: syscall.tbl syscalltbl.sh
	$(srcdir)/syscalltbl.sh $< ve_syscall_no.h ve_syscall_handler.h
