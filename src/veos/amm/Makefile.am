noinst_LIBRARIES = libveamm.a
libveamm_a_SOURCES = \
	ve_memory.c \
	ve_memory_def.h \
	amm_api.h \
	dma_api.c \
	ve_mem.c \
	mm_stat.c \
	ve_shm.c \
	pgtbl.c \
	mm_comm.c \
	pmap.c \
	elf_dump.c \
	elf_dump.h \
	mm_stat.h \
	ve_shm.h \
	ve_mem.h \
	pmap.h \
	dmaatb_api.c \
	dmaatb_api.h \
	pciatb_api.h \
	cr_api.c \
	cr_api.h \
	pciatb_api.c \
	vehva_mgmt.c \
	vehva_mgmt.h \
	../main/veos.h \
	pagetable.h \
	buddy.c \
	buddy.h


# ived and libived are used for Dummy AMM
libveamm_a_CFLAGS = \
	-g -Wall -Werror -D_GNU_SOURCE -std=gnu99 \
	-I$(srcdir)/.. \
	-I$(srcdir)/../dma \
	-I$(srcdir)/../psm \
	-I$(srcdir)/../main \
	-I$(top_srcdir)/src/veos/ived \
	-I$(top_srcdir)/src/veos/pps \
	-I$(top_srcdir)/src/veos/external \
	-I$(top_srcdir)/lib/libived \
	-I$(top_srcdir)/include/ \
	-I$(top_srcdir)/src/pseudo \
	-I$(top_builddir)/lib/libveosprotoc \
        -I@prefix@/include
