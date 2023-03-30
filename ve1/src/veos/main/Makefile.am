noinst_LIBRARIES = libvecommon_ve1.a

libvecommon_ve1_a_SOURCES = \
	veos_ve1.h \
	veos_main.c \
	vesync.c

nodist_libvecommon_ve1_a_SOURCES = arch_ops.c
CLEANFILES = arch_ops.c
arch_ops.c:
	$(top_srcdir)/generate-arch_ops.py ve1 _veos_ve1_arch_ops \
	   $(srcdir)/../*/*.c > $@

libvecommon_ve1_a_CFLAGS = \
	-g -Wall -Werror -D_GNU_SOURCE -std=gnu99 \
	-D_VE_ARCH_VE1_ \
	-I$(srcdir)/../amm \
	-I$(top_srcdir)/src/veos \
	-I$(top_srcdir)/src/veos/main \
	-I$(top_srcdir)/src/veos/dma \
	-I$(top_srcdir)/src/veos/psm \
	-I$(top_srcdir)/include \
	-I@includedir@
