bin_PROGRAMS = test
AM_CPPFLAGS = $(all_includes) $(LWP_CFLAGS)
AM_LDFLAGS = -lm -lrt -lpthread
test_SOURCES = main.c
test_LDADD = $(top_builddir)/lib/lib.la \
			$(top_builddir)/lw/liblorawan.la
