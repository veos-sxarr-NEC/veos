noinst_LIBRARIES = libvedma_ve3.a
libvedma_ve3_a_SOURCES = \
	dma_ve3.h \
	dma_ve3_private.h \
	dma_hw_ve3.h \
	dma_reqlist_ve3.h \
	ve3dma_hw.h \
	dma_api.c \
	dma_hw.c \
	dma_intr.c \
	dma_reqlist.c

libvedma_ve3_a_CFLAGS = \
	-g -Wall -Werror -D_GNU_SOURCE -std=gnu99 \
	-D_VE_ARCH_VE3_ \
	-I$(top_srcdir)/src/veos \
	-I$(top_srcdir)/src/veos/dma \
	-I$(top_srcdir)/src/veos/psm \
	-I$(top_srcdir)/src/veos/main \
	-I$(top_srcdir)/include \
	-I@prefix@/include
