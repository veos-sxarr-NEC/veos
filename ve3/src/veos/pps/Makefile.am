noinst_LIBRARIES = libvepps_ve3.a

libvepps_ve3_a_SOURCES = \
	ve_swap_out.c \
	ve_swap_in.c 

libvepps_ve3_a_CFLAGS = \
	-g -Wall -Werror -D_GNU_SOURCE -std=gnu99 \
	-D_VE_ARCH_VE3_ \
	-I$(srcdir)/../main \
	-I$(srcdir)/../amm \
	-I$(top_srcdir)/src/veos \
	-I$(top_srcdir)/src/veos/main \
	-I$(top_srcdir)/src/veos/amm \
	-I$(top_srcdir)/src/veos/psm \
	-I$(top_srcdir)/src/veos/dma \
	-I$(top_srcdir)/src/veos/external \
	-I$(top_srcdir)/src/veos/ived \
	-I$(top_srcdir)/src/veos/pps \
	-I$(top_srcdir)/include \
	-I@includedir@
