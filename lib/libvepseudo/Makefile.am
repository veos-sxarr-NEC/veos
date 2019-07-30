SUBDIRS = common amm loader psm sys ived
lib_LTLIBRARIES = libvepseudo.la
libvepseudo_la_SOURCES =

nobase_libvepseudo_headers_HEADERS = \
	amm/mm_transfer.h \
	amm/vemva_mgmt.h \
	amm/sys_mm.h \
	common/handle.h \
	common/list.h \
	common/sys_common.h \
	loader/loader.h \
	psm/process_mgmt_comm.h \
	psm/pseudo_ptrace.h \
	psm/sys_process_mgmt.h

nobase_nodist_libvepseudo_headers_HEADERS = \
	common/ve_syscall_no.h

dist_noinst_DATA = libvepseudo.map

libvepseudo_la_CFLAGS = \
	-g -Wall -Werror -D_GNU_SOURCE \
	-fPIC -std=gnu99 \
	-I$(top_srcdir)/src/veos/dma \
	-I$(top_srcdir)/src/pseudo \
	-Ipsm \
	-Icommon \
	-Iloader \
	-Isys \
	-Iamm \
	-Iived \
	-I$(top_srcdir)/vhcall/include \
	-I$(top_srcdir)/include \
	-I@prefix@/include

libvepseudo_la_LDFLAGS = -version-info 1:0:0 \
	-Wl,--version-script=$(srcdir)/libvepseudo.map

libvepseudo_la_LIBADD = \
	./common/libpseudocommon.la \
	./amm/libpseudoamm.la \
	./loader/libloader.la \
	./psm/libpseudopsm.la \
	./sys/libpseudosys.la \
	./ived/libpseudoived.la \
	$(top_builddir)/lib/libveosprotoc/libveosprotoc.la
