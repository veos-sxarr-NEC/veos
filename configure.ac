#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([veos], [3.3.0])
AC_CONFIG_SRCDIR([lib/libvepseudo/psm/exception.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_AUX_DIR([./build-aux])
AM_INIT_AUTOMAKE([foreign -Wall -Werror])

RHEL_VERSION=$(cat /etc/redhat-release |  sed -e 's/.*\s\(@<:@0-9@:>@\)\..*/\1/')
PY_V=$(if test $RHEL_VERSION -eq 8 ; then echo 3; else echo 2; fi )
AM_PATH_PYTHON([$PY_V])

AC_ARG_WITH([release-id], [AS_HELP_STRING([--with-release-id],
	    [Specify release id])],
	    [RELEASE=${with_release_id}],
	    [RELEASE="1"])
AC_SUBST(RELEASE)
AC_ARG_WITH(ve-prefix, [AS_HELP_STRING([--with-ve-prefix],
	    [Specify prefix of VE software [/opt/nec/ve]])],
	    [ve_prefix=${with_ve_prefix}],
	    [ve_prefix=/opt/nec/ve])
AC_SUBST(ve_prefix)
AC_ARG_WITH(ve3-prefix, [AS_HELP_STRING([--with-ve3-prefix],
	    [Specify prefix of VE3 software [/opt/nec/ve3]])],
	    [ve3_prefix=${with_ve_prefix}],
	    [ve3_prefix=/opt/nec/ve3])
AC_SUBST(ve3_prefix)
AC_ARG_WITH(ve-bindir, [AS_HELP_STRING([--with-ve-bindir],
	    [VE bindir [ve-prefix/bin]])],
	    [ve_bindir=${with_ve_bindir}],
	    [ve_bindir=${ve_prefix}/bin])
AC_SUBST(ve_bindir)
AC_ARG_WITH(ve-libexecdir, [AS_HELP_STRING([--with-ve-libexecdir],
	    [VE libexecdir [ve-prefix/libexec]])],
	    [ve_libexecdir=${with_ve_libexecdir}],
	    [ve_libexecdir=${ve_prefix}/libexec])
AC_SUBST(ve_libexecdir)
AC_ARG_WITH(libexecdir, [AS_HELP_STRING([--with-libexecdir],
            [libexecdir [prefix/libexec]])],
            [libexecdir=${with_libexecdir}],
            [libexecdir=${prefix}/libexec])
AC_SUBST(libexecdir)
AC_ARG_WITH(ve-includedir, [AS_HELP_STRING([--with-ve-includedir],
	    [VE includedir [ve-prefix/include]])],
	    [ve_includedir=${with_ve_includedir}],
	    [ve_includedir=${ve_prefix}/include])
AC_SUBST(ve_includedir)
AC_ARG_WITH(ve3-includedir, [AS_HELP_STRING([--with-ve3-includedir],
	    [VE includedir for VE3 [ve3-prefix/include]])],
	    [ve3_includedir=${with_ve3_includedir}],
	    [ve3_includedir=${ve3_prefix}/include])
AC_SUBST(ve3_includedir)
AC_ARG_WITH(ve-musl-includedir, [AS_HELP_STRING([--with-ve-musl-includedir],
	    [VE includedir for musl])],
	    [ve_musl_includedir=${with_ve_musl_includedir}],
	    [])
AC_SUBST(ve_musl_includedir)
AC_ARG_WITH(ve-os-launcher-confdir, [AS_HELP_STRING([--with-ve-os-launcher-confdir],
	    [Specify configuration file directory of VE OS launcher
	    [sysconfdir/ve-os-launcher.d]])],
	    [ve_os_launcher_confdir=${with_ve_os_launcher_confdir}],
	    [ve_os_launcher_confdir=${sysconfdir}/ve-os-launcher.d])
AC_SUBST(ve_os_launcher_confdir)
AC_ARG_WITH(feature_listdir, [AS_HELP_STRING([--with-feature_listdir],
	    [List of features
	    [prefix/share]])],
	    [feature_listdir=${with_feature_listdir}],
	    [feature_listdir=${prefix}/share])
AC_SUBST(feature_listdir)
AC_ARG_WITH(binfmtdir, [AS_HELP_STRING([--with-binfmtdir],
	    [Specify binfmt configuration file directory for VE program 
	    [/usr/lib/binfmt.d]])],
	    [binfmtdir=${with_binfmtdir}],
	    [binfmtdir=/usr/lib/binfmt.d])
AC_SUBST(binfmtdir)
AC_ARG_WITH(limitsdir, [AS_HELP_STRING([--with-limitsdir],
	    [Specify pam_limits module configuration file directory for
	    VE program, [/etc/security/limits.d]])],
	    [limitsdir=${with_limitsdir}],
	    [limitsdir=/etc/security/limits.d])
AC_SUBST(limitsdir)
AC_ARG_WITH(veldconfdir, [AS_HELP_STRING([--with-veldconfdir],
            [Specify veos configuration file directory
            [/etc/ld.so.conf.d]])],
            [veldconfdir=${with_veldconfdir}],
            [veldconfdir=/etc/ld.so.conf.d])
AC_SUBST(veldconfdir)
AC_ARG_WITH(sysctldir, [AS_HELP_STRING([--with-sysctldir],
	    [Specify sysctl configuration file directory for VE program,
	    [/etc/sysctl.d]])],
	    [sysctldir=${with_sysctldir}],
	    [sysctldir=/etc/sysctl.d])
AC_SUBST(sysctldir)

AC_ARG_WITH([vemm-agent-includedir],
	AS_HELP_STRING([--with-vemm-agent-includedir],
	[header directory where VEMM agent header is installed. [includedir]]),
	[],[])
AC_SUBST(VEMM_AGENT_INCLUDEDIR, "${with_vemm_agent_includedir}")
AM_CONDITIONAL(VEMM_AGENT_INCLUDE, test x"${with_vemm_agent_includedir}" != x)
AC_ARG_WITH([vemm-agent-libdir], AS_HELP_STRING([--with-vemm-agent-libdir],
	[library directory where VEMM agent is installed. [libdir]]),
	[], [with_vemm_agent_libdir="${libdir}"])
AC_SUBST(VEMM_AGENT_LIBDIR, "${with_vemm_agent_libdir}")
AC_ARG_WITH([libvepseudo-headersdir],
	AS_HELP_STRING([--with-libvepseudo-headersdir],
	[Specify a directory where libvepseudo headers are installed.
	 [includedir/libvepseudo]]),
	[libvepseudo_headersdir=${with_libvepseudo_headersdir}],
	[libvepseudo_headersdir=${includedir}/libvepseudo])
AC_SUBST(libvepseudo_headersdir)

AC_ARG_WITH([ve1], AS_HELP_STRING([--with-ve1], [VE1 support]))
AM_CONDITIONAL([VEOS_VE1], [test x$with_ve1 != xno])
AC_ARG_WITH([ve3], AS_HELP_STRING([--with-ve3], [VE3 support]))
AM_CONDITIONAL([VEOS_VE3], [test x$with_ve3 != xno])

AM_PROG_AR
LT_INIT
AC_CONFIG_MACRO_DIR([m4])

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_MAKE_SET
AM_PROG_CC_C_O

AC_CHECK_PROGS([REALPATH], [realpath], [no])
if test "x$REALPATH" = xno; then
  AC_MSG_ERROR([realpath is not found.])
fi
AC_PATH_PROG([UDEVADM], [udevadm], [no])
if test "x$UDEVADM" = xno; then
  AC_MSG_ERROR([udevadm is not found.])
fi
# Checks for libraries.
LDFLAGS="$LDFLAGS -L${prefix}/lib -L${prefix}/lib64"
AC_CHECK_LIB(ved, vedl_wait_exception, [have_libved=yes], [have_libved=no])
    if test "x$have_libved" = xno; then
      AC_MSG_ERROR([libved support missing/incomplete])
    fi
    LIBVED_LIBS="-lved"
    # TODO: check libved >= 2.99.0

AC_CHECK_LIB([dl], [dlsym], [], [AC_MSG_ERROR([dl library support missing/incomplete])])
AC_CHECK_LIB([log4c], [log4c_init], [], [AC_MSG_ERROR([log4c library support missing/incomplete])])
AC_CHECK_LIB([pthread], [pthread_create], [], [AC_MSG_ERROR([pthread library support missing/incomplete])])
AC_CHECK_LIB([rt], [mq_open], [], [AC_MSG_ERROR([rt library support missing/incomplete])])
AC_CHECK_LIB([udev], [udev_device_get_syspath], [], [AC_MSG_ERROR([udev library support missing/incomplete])])
AC_CHECK_LIB([velayout], [ve_layout], [], [AC_MSG_ERROR([velayout support missing/incomplete])])
AC_CHECK_LIB([ved], [vedl_get_syscall_args], [], [AC_MSG_ERROR([libved support missing/incomplete])])
AC_CHECK_LIB([protobuf-c], [protobuf_c_message_pack], [], [AC_MSG_ERROR([protobuf library  support missing/incomplete])])
AC_CHECK_LIB([uuid], [uuid_generate], [], [AC_MSG_ERROR([uuid library support missing/incomplete])])
AC_CHECK_LIB([systemd], [sd_notify], [], [AC_MSG_ERROR([systemd library support missing/incomplete])])
AC_CHECK_LIB([procps], [openproc], [], [AC_MSG_ERROR([procps-ng-devel library support missing/incomplete])])
AC_CHECK_LIB([dhash], [hash_count], [], [AC_MSG_ERROR([dhash-devel library support missing/incomplete])])

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h limits.h stddef.h stdint.h stdlib.h string.h sys/socket.h sys/time.h unistd.h utime.h])
saved_no_vemm_CPPFLAGS="$CPPFLAGS"
CPPFLAGS="-I${with_vemm_agent_includedir} $CPPFLAGS"
AC_CHECK_HEADERS([vemmagent.h])
CPPFLAGS="$saved_no_vemm_CPPFLAGS"

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MMAP
AC_CHECK_FUNCS([clock_gettime ftruncate getpagesize gettimeofday memset munmap realpath select socket strchr strerror strtol])

AC_CONFIG_FILES([Makefile
		veos.spec
		conf/Makefile
		conf/limits.d/Makefile
		conf/sysctl.d/Makefile
		include/Makefile
		lib/Makefile
                lib/libived/Makefile
                lib/libveosprotoc/Makefile
                lib/libveosprotoc/veosproto/Makefile
		lib/libvepseudo/Makefile
		lib/libvepseudo/amm/Makefile
		lib/libvepseudo/common/Makefile
		lib/libvepseudo/loader/Makefile
		lib/libvepseudo/psm/Makefile
		lib/libvepseudo/sys/Makefile
                lib/libvepseudo/ived/Makefile
		lib/libveptrace/Makefile
		lib/libveptrace/veos_ptrace_comm.h
		lib/libvhve/Makefile
		lib/libveproductinfo/Makefile
		scripts/Makefile
		src/Makefile
                src/ived/Makefile
		src/pseudo/Makefile
		src/veos/Makefile
		src/veos/amm/Makefile
		src/veos/dma/Makefile
		src/veos/external/Makefile
		src/veos/ptrace/Makefile
		src/veos/ived/Makefile
		src/veos/main/Makefile
		src/veos/pps/Makefile
		src/veos/main/veos_sock.h
		src/veos/psm/Makefile
		src/veos/psm/ve_coredump_helper.h
		src/veos/vemm/Makefile
		src/ve_validate_bin/Makefile
		doc/Doxyfile
		doc/Doxyfile-libs
		debian/control
		debian/rules
		debian/veos-dev.install
		debian/veos-headers.install
		debian/veos.install
		debian/veos-libvepseudo-headers.install
		debian/veos-libveptrace.install
		debian/veos-musl-headers.install
		ve1/Makefile
		ve1/lib/Makefile
		ve1/lib/libvepseudo/Makefile
		ve1/lib/libvepseudo/amm/Makefile
		ve1/lib/libvepseudo/common/Makefile
		ve1/lib/libvepseudo/loader/Makefile
		ve1/lib/libvepseudo/psm/Makefile
		ve1/lib/libveptrace/Makefile
		ve1/src/Makefile
		ve1/src/veos/Makefile
		ve1/src/veos/amm/Makefile
		ve1/src/veos/dma/Makefile
		ve1/src/veos/main/Makefile
		ve1/src/veos/psm/Makefile
		ve1/src/veos/pps/Makefile
		ve3/Makefile
		ve3/lib/Makefile
		ve3/lib/libvepseudo/Makefile
		ve3/lib/libvepseudo/amm/Makefile
		ve3/lib/libvepseudo/common/Makefile
		ve3/lib/libvepseudo/loader/Makefile
		ve3/lib/libvepseudo/psm/Makefile
		ve3/lib/libveptrace/Makefile
		ve3/src/Makefile
		ve3/src/veos/Makefile
		ve3/src/veos/amm/Makefile
		ve3/src/veos/dma/Makefile
		ve3/src/veos/main/Makefile
		ve3/src/veos/psm/Makefile
		ve3/src/veos/pps/Makefile
		])


AC_OUTPUT

