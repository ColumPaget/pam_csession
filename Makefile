CC=gcc
VERSION=0.0.1
CFLAGS=-g -O2 -fPIC -fno-stack-protector 
LIBS=
INSTALL=/bin/install -c
prefix=/
exec_prefix=${prefix}
bindir=${exec_prefix}/bin
libdir=${exec_prefix}/lib
mandir=${datarootdir}/man
datarootdir=${prefix}/share
sysconfdir=${prefix}/etc
FLAGS=$(CFLAGS) -DPACKAGE_NAME=\"\" -DPACKAGE_TARNAME=\"\" -DPACKAGE_VERSION=\"\" -DPACKAGE_STRING=\"\" -DPACKAGE_BUGREPORT=\"\" -DPACKAGE_URL=\"\" -DSTDC_HEADERS=1

all: pam_csession.so

pam_csession.so: common.h utility.o pam_module.c 
	$(CC) $(FLAGS) -c pam_module.c
	ld -x --shared -lpam -opam_csession.so pam_module.o utility.o 
	-strip pam_csession.so

utility.o: utility.h utility.c
	$(CC) $(FLAGS) -c utility.c

install: pam_csession.so
	$(INSTALL) -d $(DESTDIR)$(bindir)
	$(INSTALL) -d $(DESTDIR)$(libdir)/security
	$(INSTALL) -d $(DESTDIR)$(mandir)/man8
	$(INSTALL) pam_csession.so $(DESTDIR)$(libdir)/security
	$(INSTALL) pam_csession.8 $(DESTDIR)$(mandir)/man8

clean:
	-rm -f *.o *.so
	-rm -f config.log config.status */config.log */config.status
	-rm -fr autom4te.cache */autom4te.cache

distclean:
	-rm -f *.o *.so
	-rm -f config.log config.status */config.log */config.status Makefile */Makefile
	-rm -fr autom4te.cache */autom4te.cache

