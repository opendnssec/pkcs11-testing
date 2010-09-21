dnl
dnl $Id$
dnl

##################
#                #
#    Version     #
#                #
################

# Program version

define([VERSION_MAJOR], [0])
define([VERSION_MINOR], [1])
define([VERSION_FIX], [0])
define([PACKAGE_SUFFIX], [a1])

##################
#                #
# Configure code #
#                #
##################

# Init
AC_PREREQ(2.61)
AC_INIT([pkcs11-testing],[VERSION_MAJOR.VERSION_MINOR.VERSION_FIX[]PACKAGE_SUFFIX])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_SRCDIR([src/Makefile.am])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE(foreign)
ACX_PREFIXHACK

# Checks for compilers
AC_PROG_CC
AC_PROG_CXX

# Compiler flags
ACX_PEDANTIC
ACX_STRICT

# Check for libraries
ACX_DLOPEN

# Check for functions
AC_CHECK_FUNCS(getpassphrase)

AC_DEFINE_UNQUOTED(
	[MAX_PIN_LEN],
	[255],
	[Maximum PIN length]
)
AC_DEFINE_UNQUOTED(
	[MIN_PIN_LEN],
	[4],
	[Minimum PIN length]
)

# Generate the libtool script and install script
AC_PROG_INSTALL
AC_PROG_LIBTOOL

# Generate the makefiles
AC_CONFIG_FILES([
	Makefile
	src/Makefile
])

AC_OUTPUT
