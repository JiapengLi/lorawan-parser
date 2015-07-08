
AC_PREREQ([2.69])
AC_INIT(lorawan-parser, 1.0, gapleehit@gmail.com)

#AC_CONFIG_MACRO_DIR([m4])

AC_CONFIG_SRCDIR([configure.ac])

AC_CONFIG_AUX_DIR([.])

AM_INIT_AUTOMAKE([foreign -Wall -Werror])


# Checks for programs.
AC_PROG_CC
AC_PROG_CC_C99
AM_PROG_AR
AC_PROG_INSTALL
AC_PROG_MKDIR_P

# libtool initial
LT_INIT

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h stdint.h stdlib.h unistd.h sys/mman.h])
AC_CHECK_HEADERS([CUnit/Basic.h CUnit/CUCurses.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

LWP_CFLAGS='-I$(top_srcdir)/lib -I$(top_srcdir)/lw -I$(top_builddir)/include'
AC_SUBST(LWP_CFLAGS)

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_MMAP
AC_CHECK_FUNCS([munmap memset])

AC_CONFIG_FILES([
		Makefile
		lib/Makefile
		lw/Makefile
		util/parser/Makefile
		util/test/Makefile
		])

AC_OUTPUT
