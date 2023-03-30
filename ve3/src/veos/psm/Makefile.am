noinst_LIBRARIES = libvepsm_ve3.a
libvepsm_ve3_a_SOURCES = \
	clone_handler.c \
	ptrace_req.c \
	task_signal.c \
	task_signal_ve3.h \
	task_mgmt.c \
	task_mgmt_ve3.h \
	task_sched.c \
	task_sched_ve3.h \
	udma_ve3.h \
	udma.c \
	ptrace_req.c \
	ptrace_req_ve3.h

libvepsm_ve3_a_CFLAGS = \
	-g -Wall -Werror -D_GNU_SOURCE -std=gnu99 \
	-D_VE_ARCH_VE3_ \
	-I$(top_srcdir)/src/veos \
	-I$(top_srcdir)/src/veos/psm \
	-I$(top_srcdir)/src/veos/amm \
	-I$(top_srcdir)/src/veos/dma \
	-I$(top_srcdir)/src/veos/pps \
	-I$(top_srcdir)/src/veos/main \
	-I$(srcdir)/../dma \
	-I$(srcdir)/../amm \
	-I$(top_srcdir)/ve3/include \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/ve3/src/veos/main \
	-I@prefix@/include
