sbin_PROGRAMS = ived 
ived_SOURCES = \
	ived.h \
	ived_ipc_func.h \
	ived_ipc_func.c \
	ived_main.h \
	ived_main.c \
	ived_core.h \
	ived_core.c \
	ived_veshm_core.h \
	veshm_core.h \
	veshm_core.c \
	veshm_ipc.h \
	veshm_ipc.c \
	ived_cr_core.h \
	cr_core.h \
	cr_core.c \
	cr_ipc.h \
	cr_ipc.c

ived_CFLAGS = \
	-g -Wall -Werror -D_GNU_SOURCE -std=gnu99 \
	-I$(top_srcdir)/lib/libived \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/lib/libveosprotoc \
	-I@prefix@/include

ived_LDADD = \
	$(top_builddir)/lib/libived/libived.a \
	$(top_builddir)/lib/libveosprotoc/libveosprotoc.la
