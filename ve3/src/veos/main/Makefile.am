noinst_LIBRARIES = libvecommon_ve3.a

libvecommon_ve3_a_SOURCES = \
	veos_main.c \
	veos_ve3.h \
	vesync.c

nodist_libvecommon_ve3_a_SOURCES = arch_ops.c

arch_ops.c:
	$(top_srcdir)/generate-arch_ops.py ve3 _veos_ve3_arch_ops \
	  $(srcdir)/../*/*.c > $@

libvecommon_ve3_a_CFLAGS = \
	-g -Wall -Werror -D_GNU_SOURCE -std=gnu99 \
	-D_VE_ARCH_VE3_ \
	-I$(srcdir)/../amm \
	-I$(top_srcdir)/src/veos \
	-I$(top_srcdir)/src/veos/main \
	-I$(top_srcdir)/src/veos/dma \
	-I$(top_srcdir)/include \
	-I@includedir@
