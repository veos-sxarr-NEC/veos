SUBDIRS = common amm loader psm sys ived
lib_LTLIBRARIES = libvepseudo.la
libvepseudo_la_SOURCES =

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

libvepseudo_la_LDFLAGS = -version-info 1:0:0

libvepseudo_la_LIBADD = \
	./common/libpseudocommon.la \
	./amm/libpseudoamm.la \
	./loader/libloader.la \
	./psm/libpseudopsm.la \
	./sys/libpseudosys.la \
	./ived/libpseudoived.la \
	$(top_builddir)/lib/libveosprotoc/libveosprotoc.la
