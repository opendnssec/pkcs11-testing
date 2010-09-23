# $Id$

MAINTAINERCLEANFILES =		$(srcdir)/Makefile.in

AM_CPPFLAGS = 			-I$(srcdir)/cryptoki_compat

# dist_man_MANS =		pkcs11-testing.1

bin_PROGRAMS =			pkcs11-testing

pkcs11_testing_SOURCES =	pkcs11-testing.cpp \
				getpw.cpp \
				library.cpp \
				mechanisms.cpp \
				publickey.cpp \
				import.cpp \
				session.cpp \
				showslots.cpp

EXTRA_DIST =			$(srcdir)/*.h \
				$(srcdir)/cryptoki_compat/*.h
