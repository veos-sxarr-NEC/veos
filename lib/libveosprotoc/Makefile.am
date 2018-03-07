SUBDIRS = veosproto
noinst_LTLIBRARIES = libveosprotoc.la

ived_message_sources = ived.pb-c.c ived.pb-c.h
pseudo_message_sources = proto_buff_schema.pb-c.c proto_buff_schema.pb-c.h
nodist_libveosprotoc_la_SOURCES = \
	$(ived_message_sources) $(pseudo_message_sources)
dist_noinst_DATA = ived.proto proto_buff_schema.proto
CLEANFILES = $(nodist_libveosipcmessages_la_SOURCES)

$(ived_message_sources): $(srcdir)/ived.proto Makefile
	protoc-c --proto_path=$(srcdir) --c_out=$(builddir) $<

$(pseudo_message_sources): $(srcdir)/proto_buff_schema.proto Makefile
	protoc-c --proto_path=$(srcdir) --c_out=$(builddir) $<
