ve_bin_SCRIPTS = ve_exec ve-libc-check
libexec_SCRIPTS = ve_release_resource
python_PYTHON = ve_delete_process.py ve_release_remote_resource.py
CLEANFILES = ve_exec ve_release_resource ve_delete_process.py ve_release_remote_resource.py ve-libc-check
EXTRA_DIST = ve_exec.in ve_release_resource.in ve_delete_process.in ve_release_remote_resource.in ve-libc-check.in

edit = sed -e 's|@ve_libexecdir[@]|$(ve_libexecdir)|g' \
           -e 's|@localstatedir[@]|$(localstatedir)|g' \
           -e 's|@VERSION[@]|$(VERSION)|g' \
           -e 's|@pythondir[@]|$(pythondir)|g' \
           -e 's|@libexecdir[@]|$(libexecdir)|g' \
           -e 's|@UDEVADM[@]|$(UDEVADM)|g' \
           -e 's|@ve_bindir[@]|$(ve_bindir)|g'

ve_exec: $(srcdir)/ve_exec.in
	$(edit) $< > $@

install-exec-hook:
	$(MKDIR_P) $(DESTDIR)$(ve_libexecdir)
	$(LN_S) -f `realpath --relative-to=$(DESTDIR)$(ve_libexecdir) \
                             $(DESTDIR)$(libexecdir)/ve_exec` \
	        $(DESTDIR)$(ve_libexecdir)/ve_exec

ve_release_resource: $(srcdir)/ve_release_resource.in
	$(edit) $< > $@

ve_delete_process.py: $(srcdir)/ve_delete_process.in
	$(edit) $< > $@

ve_release_remote_resource.py: $(srcdir)/ve_release_remote_resource.in
	$(edit) $< > $@

ve-libc-check: $(srcdir)/ve-libc-check.in
	$(edit) $< > $@

