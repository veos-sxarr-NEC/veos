noinst_LIBRARIES = libvedma.a
libvedma_a_SOURCES = \
	dma_api.c \
	dma_hw.c \
	dma_intr.c \
	dma_log.c \
	dma_reqlist.c \
	dma_reqlist_private.h \
	dma.h \
	dma_hw.h \
	dma_intr.h \
	dma_private.h \
	dma_reqlist.h \
	dma_reqlist_private.h \
	dma_log.h

libvedma_a_CFLAGS = \
	-g -Wall -Werror -D_GNU_SOURCE -std=gnu99 -D__PCIDEV_ENV \
	-I$(srcdir)/.. \
	-I$(srcdir)/../amm \
	-I$(srcdir)/../psm \
	-I$(srcdir)/../main \
	-I$(srcdir)/../pps \
	-I$(top_srcdir)/src/pseudo \
	-I$(top_srcdir)/include \
	-I@prefix@/include

