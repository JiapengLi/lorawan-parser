bin_PROGRAMS = lwp
AM_CPPFLAGS =  $(all_includes) $(LWP_CFLAGS)
AM_LDFLAGS = -lm -lrt -lpthread
lwp_SOURCES = main.c app.c conf.c pktfwd.c
lwp_LDADD = $(top_builddir)/lib/lib.la \
			$(top_builddir)/lw/liblorawan.la \
			$(top_builddir)/lib/libloragw/src/libloragw.la
