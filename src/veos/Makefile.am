veos_CPPFLAGS = -g -Wall -Werror -D_GNU_SOURCE -D__PCIDEV_ENV -std=gnu99
sbin_PROGRAMS = veos
veos_SOURCES =
veos_CFLAGS = \
	-I$(srcdir)/dma \
	-I$(srcdir)/main \
	-I$(srcdir)/amm \
	-I$(srcdir)/psm \
	-I$(srcdir)/external \
	-I$(srcdir)/ptrace \
	-I$(top_srcdir)/vhcall/include \
	-I$(top_srcdir)/src/pseudo \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/lib/libveosprotoc \
	-I@prefix@/include

veos_LDADD = \
	./main/libvemain.a \
	./external/libveexternal.a \
	./ptrace/libveptrace.a \
	./dma/libvedma.a \
	./ived/libveived.a \
	./psm/libvepsm.a \
	./ived/libveived.a \
	./vemm/libveosvemm.a \
	./amm/libveamm.a \
	./main/libvecommon.a \
	$(top_builddir)/lib/libived/libived.a \
	$(top_builddir)/lib/libveosprotoc/libveosprotoc.la
SUBDIRS = main dma amm psm external ptrace ived vemm
