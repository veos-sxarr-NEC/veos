noinst_LIBRARIES = libveived.a
libveived_a_SOURCES = \
	veos_ived.c \
	veos_ived.h \
	veos_ived_private.h \
	veos_ived_common.c \
	veos_ived_common.h \
	veos_ived_misc.c \
	veos_ived_misc.h \
	veos_veshm.c \
	veos_veshm_core.h \
	veos_veshm.h \
	veos_veshm_interface.h \
	veos_veshm_interface.c \
	veos_veshm_ipc.h \
	veos_veshm_ipc.c \
	veos_cr.c \
	veos_cr.h \
	veos_vhshm.c \
	veos_vhshm.h

libveived_a_CFLAGS = \
	-g -Wall -Werror -D_GNU_SOURCE -std=gnu99 \
	-I$(srcdir) \
	-I$(srcdir)/.. \
	-I$(srcdir)/../main \
	-I$(srcdir)/../pps \
	-I$(srcdir)/../psm \
	-I$(srcdir)/../dma \
	-I$(srcdir)/../amm \
	-I$(top_srcdir)/lib/libived \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/lib/libveosprotoc \
        -I@prefix@/include
