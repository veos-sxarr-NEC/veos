noinst_LIBRARIES = libveamm_ve3.a
libveamm_ve3_a_SOURCES = \
	alloc.c \
	ve_mem_ve3.h \
	ve_mem.c \
	pgtbl.c \
	dmaatb_api.c \
	cr_api.c \
	pciatb_api.c \
	vehva_mgmt_ve3.h \
	vehva_mgmt.c \
	mm_stat.c \
	ve_memory_ve3.c \
	ve_memory_ve3.h \
	elf_dump.c

libveamm_ve3_a_CFLAGS = \
	-g -Wall -Werror -D_GNU_SOURCE -std=gnu99 \
	-D_VE_ARCH_VE3_ \
	-I$(srcdir)/../psm \
	-I$(srcdir)/../main \
	-I$(top_srcdir)/src/veos \
	-I$(top_srcdir)/src/veos/amm \
	-I$(top_srcdir)/src/veos/psm \
	-I$(top_srcdir)/src/veos/dma \
	-I$(top_srcdir)/src/veos/main \
	-I$(top_srcdir)/src/veos/pps \
	-I$(top_srcdir)/ve3/include \
	-I$(top_srcdir)/include \
	-I@prefix@/include
