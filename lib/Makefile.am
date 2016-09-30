SUBDIRS = libloragw

AM_CPPFLAGS = $(all_includes) $(LWP_CFLAGS)
AM_LDFLAGS = -lpthread

noinst_LTLIBRARIES = lib.la
lib_la_SOURCES = parson.c \
				log.c \
				str2hex.c \
				aes.c \
				cmac.c \
				base64.c \
				json.c \
				netutil.c
