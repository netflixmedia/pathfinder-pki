INCLUDE(UsePkgConfig)

PROJECT(PATHFINDER)
SET(PACKAGE_VERSION 0.2.6)

PKGCONFIG(libuniconf UNICONF_INCLUDEDIR UNICONF_LIBDIR UNICONF_LINKFLAGS UNICONF_CFLAGS)
PKGCONFIG(libwvdbus WVDBUS_INCLUDEDIR WVDBUS_LIBDIR WVDBUS_LINKFLAGS WVDBUS_CFLAGS)
PKGCONFIG(dbus-1 DBUS_INCLUDEDIR DBUS_LIBDIR DBUS_LINKFLAGS DBUS_CFLAGS)
PKGCONFIG(openssl OPENSSL_INCLUDEDIR OPENSSL_LIBDIR OPENSSL_LINKFLAGS OPENSSL_CFLAGS)
PKGCONFIG(nss NSS_INCLUDEDIR NSS_LIBDIR NSS_LINKFLAGS NSS_CFLAGS)

# wvdiriter in wvstreams will assert if we don't have these set... since this is how wvstreams 
# is normally compiled. can't we do something simpler?
SET(EXTRA_CFLAGS "${WVDBUS_CFLAGS} -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64 -g")
SET(EXTRA_LINKFLAGS "${WVDBUS_LINKFLAGS}")

INCLUDE_DIRECTORIES(${PATHFINDER_SOURCE_DIR} 
                    ${PATHFINDER_SOURCE_DIR}/x509path 
		    ${PATHFINDER_SOURCE_DIR}/libpathfinder)

ADD_LIBRARY(pathology STATIC pathfinder.cc pathvalidator.cc downloader.cc pathserver.cc)
SET_TARGET_PROPERTIES(pathology
		      PROPERTIES COMPILE_FLAGS "${EXTRA_CFLAGS}")

ADD_EXECUTABLE(pathverify pathverify.cc)
TARGET_LINK_LIBRARIES(pathverify pathology x509path)
SET_TARGET_PROPERTIES(pathverify 
		      PROPERTIES COMPILE_FLAGS "${EXTRA_CFLAGS}" LINK_FLAGS "${EXTRA_LINKFLAGS}")

ADD_EXECUTABLE(pathfinderd pathfinderd.cc)
TARGET_LINK_LIBRARIES(pathfinderd pathology x509path)
SET_TARGET_PROPERTIES(pathfinderd
		      PROPERTIES COMPILE_FLAGS ${EXTRA_CFLAGS} LINK_FLAGS ${EXTRA_LINKFLAGS})

ADD_EXECUTABLE(pathclient pathclient.cc)
TARGET_LINK_LIBRARIES(pathclient)
SET_TARGET_PROPERTIES(pathclient
		      PROPERTIES COMPILE_FLAGS ${EXTRA_CFLAGS} LINK_FLAGS ${EXTRA_LINKFLAGS})

INSTALL(TARGETS pathverify pathclient
	RUNTIME DESTINATION bin)

INSTALL(TARGETS pathfinderd
	RUNTIME DESTINATION sbin)

INSTALL(FILES README AUTHORS LICENSE pathfinderd.ini.sample DESTINATION share/doc/pathfinder)

ADD_EXECUTABLE(openssltest openssltest.cc)
TARGET_LINK_LIBRARIES(openssltest pathfinder-openssl-1)
SET_TARGET_PROPERTIES(openssltest 
		      PROPERTIES COMPILE_FLAGS "${DBUS_CFLAGS}" LINK_FLAGS "${OPENSSL_LINKFLAGS} ${DBUS_LINKFLAGS}")

ADD_EXECUTABLE(nsstest nsstest.cc)
TARGET_LINK_LIBRARIES(nsstest pathfinder-nss-1)
SET_TARGET_PROPERTIES(nsstest
		      PROPERTIES COMPILE_FLAGS "${DBUS_CFLAGS} ${NSS_CFLAGS}" LINK_FLAGS "${DBUS_LINKFLAGS} ${NSS_LINKFLAGS}")

SUBDIRS(t x509path libpathfinder)

IF(NOT DEFINED CMAKE_INSTALL_LIBDIR)
   SET(CMAKE_INSTALL_LIBDIR "/usr/lib")
ENDIF(NOT DEFINED CMAKE_INSTALL_LIBDIR)

CONFIGURE_FILE(version.h.in version.h)
CONFIGURE_FILE(pathfinder-nss-uninstalled.pc.in pathfinder-nss-uninstalled.pc
	       @ONLY)
CONFIGURE_FILE(pathfinder-openssl-uninstalled.pc.in 
	       pathfinder-openssl-uninstalled.pc
	       @ONLY)
CONFIGURE_FILE(pathfinder-nss.pc.in pathfinder-nss.pc
	       @ONLY)
CONFIGURE_FILE(pathfinder-openssl.pc.in pathfinder-openssl.pc
	       @ONLY)

INSTALL(FILES pathfinder-nss.pc pathfinder-openssl.pc
	      DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")

INSTALL (FILES pathclient.3 pathverify.3
	      DESTINATION share/man/man3)

INSTALL (FILES pathfinderd.8
	      DESTINATION share/man/man8)

INSTALL (FILES pathfinderd-dbus.conf
	      DESTINATION /etc/dbus-1/system.d
	      RENAME pathfinderd.conf)

ENABLE_TESTING()
ADD_TEST(all valgrind --tool=memcheck t/all.t)

SET(CPACK_PACKAGE_NAME "pathfinder")
SET(CPACK_PACKAGE_DESCRIPTION_SUMMARY "pathfinder")
SET(CPACK_PACKAGE_VERSION_MAJOR "0")
SET(CPACK_PACKAGE_VERSION_MINOR "2")
SET(CPACK_PACKAGE_VERSION_PATCH "5")
SET(CPACK_SOURCE_IGNORE_FILES "/.git/;.gitignore;.*~;/.svn/;CMakeFiles/;CMakeCache.txt;/Testing/;DartTestfile.txt;.pc$;.cmake;/_CPack_Packages/;version.h$;.tar.gz;.tar.Z;.*#.*";/pathviewer-0.1.0-Source/;Makefile)
INCLUDE(CPack)
