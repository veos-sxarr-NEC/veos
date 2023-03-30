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
	./pps/libvepps.a \
	$(top_builddir)/lib/libived/libived.a \
	$(top_builddir)/lib/libveosprotoc/libveosprotoc.la

SUBDIRS = main dma amm psm external ptrace ived vemm pps

noinst_HEADERS=veos_arch_ops.h

veos_LDFLAGS = 

if VEOS_VE1
veos_ve1_builddir = $(top_builddir)/ve1/src/veos
SUBDIRS += ../../ve1/src/veos
veos_LDADD += \
	$(veos_ve1_builddir)/main/libvecommon_ve1.a \
	$(veos_ve1_builddir)/dma/libvedma_ve1.a \
	$(veos_ve1_builddir)/amm/libveamm_ve1.a \
	$(veos_ve1_builddir)/psm/libvepsm_ve1.a \
	$(veos_ve1_builddir)/pps/libvepps_ve1.a
# TODO: add the other modules

veos_LDFLAGS += -u _veos_ve1_arch_def_ptr
endif
if VEOS_VE3
veos_ve3_builddir = $(top_builddir)/ve3/src/veos
SUBDIRS += ../../ve3/src/veos
veos_LDADD += \
	$(veos_ve3_builddir)/main/libvecommon_ve3.a \
	$(veos_ve3_builddir)/dma/libvedma_ve3.a \
	$(veos_ve3_builddir)/amm/libveamm_ve3.a \
	$(veos_ve3_builddir)/psm/libvepsm_ve3.a \
	$(veos_ve3_builddir)/pps/libvepps_ve3.a

veos_LDFLAGS += -u _veos_ve3_arch_def_ptr
endif
