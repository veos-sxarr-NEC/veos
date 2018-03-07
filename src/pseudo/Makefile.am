ve_exec_CPPFLAGS = -g -Wall -Werror -D_GNU_SOURCE -std=gnu99

libexec_PROGRAMS = ve_exec
ve_exec_SOURCES = pseudo_process.c

ve_exec_CFLAGS = \
	-I$(top_srcdir)/lib/libvepseudo/psm \
	-I$(top_srcdir)/lib/libvepseudo/common \
	-I$(top_srcdir)/lib/libvepseudo/amm \
	-I$(top_srcdir)/lib/libvepseudo/loader \
	-I$(top_srcdir)/lib/libvepseudo/ived \
	-I$(top_srcdir)/lib/libvepseudo \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/lib/libveosprotoc \
	-I@prefix@/include

ve_exec_LDADD = \
	$(top_builddir)/lib/libvepseudo/libvepseudo.la
