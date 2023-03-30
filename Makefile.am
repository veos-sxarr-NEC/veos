ACLOCAL_AMFLAGS = -I m4
dist_noinst_DATA = veos.spec
SUBDIRS = conf lib src include scripts
if VEOS_VE1
SUBDIRS += ve1
endif
if VEOS_VE3
SUBDIRS += ve3
endif
dist_noinst_SCRIPTS = generate-arch_ops.py
EXTRA_DIST = \
	COPYING \
	README \
	doc \
	debian
