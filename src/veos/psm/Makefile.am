ve_coredump_helper_CPPFLAGS = -g -Wall -Werror -D_GNU_SOURCE -std=gnu99
libexec_PROGRAMS = ve_coredump_helper
ve_coredump_helper_SOURCES = ve_coredump_helper.c

noinst_LIBRARIES = libvepsm.a
libvepsm_a_SOURCES = \
	clone_handler.c \
	psm_comm.c \
	psm_stat.c \
	task_signal.c \
	task_mgmt.c \
	ve_clone.h \
	task_sched.c \
	task_exit.c \
	psm_comm.h \
	psm_stat.h \
	task_signal.h \
	task_mgmt.h \
	task_sched.h \
	ptrace_req.c \
	ptrace_req.h \
	locking_handler.c \
	locking_handler.h

# libived is used for Dummy AMM
libvepsm_a_CFLAGS = \
	-g -Wall -Werror -D_GNU_SOURCE -std=gnu99 \
	-I$(top_srcdir)/src/veos/dma \
	-I$(top_srcdir)/src/veos/amm \
	-I$(top_srcdir)/src/veos/main \
	-I$(top_srcdir)/src/veos/ived \
	-I$(top_srcdir)/src/veos/external \
	-I$(top_srcdir)/src/veos/ived \
	-I$(top_srcdir)/src/pseudo \
	-I$(top_srcdir)/lib/libived \
	-I$(top_srcdir)/include/ \
	-I$(top_builddir)/lib/libveosprotoc \
        -I@prefix@/include
