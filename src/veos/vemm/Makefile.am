noinst_LIBRARIES = libveosvemm.a
libveosvemm_a_SOURCES = \
	veos_vemm.c \
	veos_vemm_handler.c

noinst_HEADERS = \
	veos_vemm.h \
	veos_vemm_handler.h \
	veos_vemm_log.h \
	vemmagent_fallback.h

if VEMM_AGENT_INCLUDE
vemmagent_include = -I@VEMM_AGENT_INCLUDEDIR@
else
vemmagent_include =
endif

libveosvemm_a_CPPFLAGS = \
	-D_GNU_SOURCE \
	-DVEMM_AGENT_LIBDIR=\"@VEMM_AGENT_LIBDIR@\" \
	$(vemmagent_include) \
	-I$(top_srcdir)/src/veos/psm \
	-I$(top_srcdir)/src/veos/amm \
	-I$(top_srcdir)/src/veos/main \
	-I$(top_srcdir)/src/veos/dma \
	-I$(top_srcdir)/src/veos/ived \
	-I$(top_srcdir)/lib/libived \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/lib/libveosprotoc \
	-I@prefix@/include

libveosvemm_a_CFLAGS = \
	-std=gnu99 -Wall
