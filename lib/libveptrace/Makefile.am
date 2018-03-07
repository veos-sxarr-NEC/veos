lib_LTLIBRARIES = libveptrace.la
libveptrace_la_SOURCES = \
	sys_ptrace.c \
	ptrace_log.h \
	ptrace_log.c \
	internal.h \
	ve_ptrace.h \
	ptrace_comm.c \
	ptrace_comm.h

libveptrace_la_CFLAGS = \
	-I../libveosprotoc \
        -g -Wall -Werror -D_GNU_SOURCE \
	-fPIC -std=gnu99

libveptrace_la_LDFLAGS = -version-info 1:0:0

libveptrace_la_LIBADD = \
	$(top_builddir)/lib/libveosprotoc/libveosprotoc.la

include_HEADERS = ve_ptrace.h
