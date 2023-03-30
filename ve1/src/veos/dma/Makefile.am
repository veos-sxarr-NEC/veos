noinst_LIBRARIES = libvedma_ve1.a
libvedma_ve1_a_SOURCES = \
	dma_ve1.h \
	dma_ve1_private.h \
	dma_hw_ve1.h \
	dma_reqlist_ve1.h \
	ve1dma_hw.h \
	dma_api.c \
	dma_hw.c \
	dma_intr.c \
	dma_reqlist.c

libvedma_ve1_a_CFLAGS = \
	-g -Wall -Werror -D_GNU_SOURCE -std=gnu99 \
	-D_VE_ARCH_VE1_ \
	-I$(top_srcdir)/src/veos \
	-I$(top_srcdir)/src/veos/dma \
	-I$(top_srcdir)/src/veos/psm \
	-I$(top_srcdir)/src/veos/main \
	-I$(top_srcdir)/include \
	-I@prefix@/include
