
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

# Big endina support (default:no)
AC_ARG_ENABLE([big-endian],AS_HELP_STRING([--enable-big-endian],[Define ENABLE_BIG_ENDIAN macro]),[enable_big_endian=$enableval],[enable_big_endian="no"])
AC_MSG_CHECKING(for big endian flag)
AC_MSG_RESULT($enable_big_endian)
if test x"$enable_big_endian" = "xyes"
then
  CFLAGS="$CFLAGS -DENABLE_BIG_ENDIAN"
fi

ARFLAGS='rcs'

LWP_CFLAGS='-I$(top_srcdir)/lib/libloragw/inc -I$(top_srcdir)/lib -I$(top_srcdir)/lw'
AC_SUBST(LWP_CFLAGS)

# Checks for library functions.

# rpl_malloc problem AC_FUNC_MALLOC
AC_CHECK_FUNCS([malloc])
AC_FUNC_MMAP
AC_CHECK_FUNCS([munmap memset])

AC_CONFIG_FILES([
		Makefile
		lib/Makefile
		lib/libloragw/Makefile
		lib/libloragw/src/Makefile
		lw/Makefile
		util/Makefile
		util/parser/Makefile
		util/test/Makefile
		])

AC_OUTPUT
