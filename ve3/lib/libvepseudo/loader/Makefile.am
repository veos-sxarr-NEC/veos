noinst_LTLIBRARIES = libloader_ve3.la
libloader_ve3_la_SOURCES = loader.c
nodist_libloader_ve3_la_SOURCES = arch_ops.c
CLEANFILES = arch_ops.c
arch_ops.c:
	$(top_srcdir)/generate-arch_ops.py ve3 _pseudo_ve3_arch_ops \
		$(srcdir)/../*/*.c > $@
libloader_ve3_la_CFLAGS = \
	-g -Wall -Werror -DDEBUG -D_GNU_SOURCE -std=gnu99 \
	-D_VE_ARCH_VE3_ \
	-I$(top_srcdir)/lib/libvepseudo/loader \
	-I$(top_srcdir)/lib/libvepseudo/common \
	-I$(top_srcdir)/lib/libvepseudo/amm \
	-I$(top_srcdir)/lib/libvepseudo \
	-I$(top_srcdir)/include \
	-I@includedir@
