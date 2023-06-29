noinst_LIBRARIES = libvepsm_ve1.a
libvepsm_ve1_a_SOURCES = \
	clone_handler.c \
	ptrace_req.c \
	task_signal.c \
	task_signal_ve1.h \
	task_mgmt.c \
	task_mgmt_ve1.h \
	task_sched.c \
	task_sched_ve1.h \
	udma_ve1.h \
	udma.c \
	ptrace_req.c \
	ptrace_req_ve1.h \
	psm_comm.c

libvepsm_ve1_a_CFLAGS = \
	-g -Wall -Werror -D_GNU_SOURCE -std=gnu99 \
	-D_VE_ARCH_VE1_ \
	-I$(top_srcdir)/src/veos \
	-I$(top_srcdir)/src/veos/psm \
	-I$(top_srcdir)/src/veos/amm \
	-I$(top_srcdir)/src/veos/dma \
	-I$(top_srcdir)/src/veos/pps \
	-I$(top_srcdir)/src/veos/main \
	-I$(srcdir)/../dma \
	-I$(srcdir)/../amm \
	-I$(top_srcdir)/ve1/include \
	-I$(top_srcdir)/include \
	-I@includedir@
