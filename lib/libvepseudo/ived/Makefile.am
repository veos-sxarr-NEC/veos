noinst_LTLIBRARIES = libpseudoived.la
libpseudoived_la_SOURCES = \
	pseudo_veshm_pgmode.h \
	pseudo_veshm_pgmode.c \
	pseudo_veshm.h \
	pseudo_veshm.c \
	pseudo_cr.h \
	pseudo_ived_common.c \
	pseudo_ived_common.h \
	pseudo_cr.c \
	pseudo_vemm.c \
	pseudo_vhshm.c \
	pseudo_vhshm.h

libpseudoived_la_CFLAGS = \
	-g -Wall -Werror -DDEBUG -D_GNU_SOURCE \
	-std=gnu99 \
	-I$(srcdir) \
	-I$(srcdir)/../common \
	-I$(srcdir)/../amm \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib/libived \
	-I$(top_builddir)/lib/libveosprotoc \
	-I@prefix@/include
