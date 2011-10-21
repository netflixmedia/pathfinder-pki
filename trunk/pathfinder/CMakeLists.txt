INCLUDE(UsePkgConfig)
find_package(PkgConfig)
cmake_minimum_required(VERSION 2.4.7)

if(COMMAND cmake_policy)
    cmake_policy(SET CMP0003 NEW)
endif(COMMAND cmake_policy)

PROJECT(PATHFINDER)
SET(PACKAGE_VERSION 1.1.4)

pkg_check_modules(UNICONF libuniconf)
pkg_check_modules(NSS nss)
pkg_check_modules(DBUS dbus-1)
pkg_check_modules(OPENSSL openssl)
pkg_check_modules(WVDBUS libwvdbus)

#PKGCONFIG(libuniconf UNICONF_INCLUDEDIR UNICONF_LIBDIR UNICONF_LINKFLAGS UNICONF_CFLAGS)
PKGCONFIG(libwvdbus WVDBUS_INCLUDEDIR WVDBUS_LIBDIR WVDBUS_LINKFLAGS WVDBUS_CFLAGS)
PKGCONFIG(dbus-1 DBUS_INCLUDEDIR DBUS_LIBDIR DBUS_LINKFLAGS DBUS_CFLAGS)
PKGCONFIG(openssl OPENSSL_INCLUDEDIR OPENSSL_LIBDIR OPENSSL_LINKFLAGS OPENSSL_CFLAGS)
PKGCONFIG(nss NSS_INCLUDEDIR NSS_LIBDIR NSS_LINKFLAGS NSS_CFLAGS)

IF (NOT DBUS_CFLAGS)
	MESSAGE(FATAL_ERROR, "You need to have DBUS Development packages installed to build Pathfinder.")
ENDIF(NOT DBUS_CFLAGS)

IF (NOT WVDBUS_CFLAGS)
	MESSAGE(FATAL_ERROR, "You must have the WvStreams DBus Development packages installed to build Pathfinder.")
ENDIF (NOT WVDBUS_CFLAGS)

FIND_PATH(LDAP_INCLUDEDIR ldap.h)

if(APPLE)
   FIND_LIBRARY(LDAP_LIBS NAMES LDAP
        PATHS
        /System/Library/Frameworks
        /Library/Frameworks
   )
else(APPLE)
   FIND_LIBRARY(LDAP_LIBS NAMES ldap)
   FIND_LIBRARY(LBER_LIBS NAMES lber)
endif(APPLE)

if(LDAP_INCLUDEDIR AND LDAP_LIBS)
   if(LBER_LIBS)
     set(LDAP_FOUND TRUE)
     set(LDAP_LIBRARIES ${LDAP_LIBS} ${LBER_LIBS})
   endif(LBER_LIBS)
endif(LDAP_INCLUDEDIR AND LDAP_LIBS)

if(LDAP_FOUND)
    # One of these days, properly parse out what may be an alternate -L
    # linker directive. Until then, hacky hacky.
    message(STATUS "${LDAP_LIBS}")
    set(LDAP_LINKFLAGS "-lldap")
    if(${LDAP_INCLUDEDIR} STREQUAL "/usr/include")
	set(LDAP_CFLAGS "")
    else(${LDAP_INCLUDEDIR} STREQUAL "/usr/include")
	set(LDAP_CFLAGS "-I${LDAP_INCLUDEDIR}")
    endif(${LDAP_INCLUDEDIR} STREQUAL "/usr/include")
else(LDAP_FOUND)
    message(FATAL_ERROR "You need to have the LDAP Development packages installed to build Pathfinder.")
endif(LDAP_FOUND)

# wvdiriter in wvstreams will assert if we don't have these set... since this is how wvstreams 
# is normally compiled. can't we do something simpler? Also, take advantage
# of this silliness to add in an Apple specific compiler flag. We should
# find out the RIGHT way to do this, but for now, this works.
if(APPLE)
    SET(EXTRA_CFLAGS "${WVDBUS_CFLAGS} -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64 -g -DAPPLE -I/sw/include")
elseif(${CMAKE_SYSTEM_NAME} MATCHES SunOS)
    SET(EXTRA_CFLAGS "${WVDBUS_CFLAGS} -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64 -g -DSOLARIS -I/opt/csw/include")
    SET(CMAKE_AR "gar")
else(APPLE)
    SET(EXTRA_CFLAGS "${WVDBUS_CFLAGS} -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64 -g")
endif(APPLE)

SET(EXTRA_LINKFLAGS "${WVDBUS_LINKFLAGS} ${LDAP_LINKFLAGS} ${OPENSSL_LINKFLAGS}")

INCLUDE_DIRECTORIES(${PATHFINDER_SOURCE_DIR} 
                    ${PATHFINDER_SOURCE_DIR}/x509path 
		    ${PATHFINDER_SOURCE_DIR}/libpathfinder)

ADD_LIBRARY(pathology STATIC pathfinder.cc revocationfinder.cc pathvalidator.cc downloader.cc pathserver.cc util.cc)
SET_TARGET_PROPERTIES(pathology
		      PROPERTIES COMPILE_FLAGS "${EXTRA_CFLAGS}")

ADD_EXECUTABLE(pathverify pathverify.cc)
TARGET_LINK_LIBRARIES(pathverify pathology x509path ${WVDBUS_LIBRARIES} ${OPENSSL_LIBRARIES} ${LDAP_LIBS})
SET_TARGET_PROPERTIES(pathverify 
		      PROPERTIES COMPILE_FLAGS "${EXTRA_CFLAGS}" LINK_FLAGS "${EXTRA_LINKFLAGS}")

ADD_EXECUTABLE(pathfinderd pathfinderd.cc)
TARGET_LINK_LIBRARIES(pathfinderd pathology x509path ${WVDBUS_LIBRARIES} ${OPENSSL_LIBRARIES} ${LDAP_LIBS})
SET_TARGET_PROPERTIES(pathfinderd
		      PROPERTIES COMPILE_FLAGS "${EXTRA_CFLAGS}" LINK_FLAGS "${EXTRA_LINKFLAGS}")

ADD_EXECUTABLE(pathclient pathclient.cc util.cc)
TARGET_LINK_LIBRARIES(pathclient ${WVDBUS_LIBRARIES} ${OPENSSL_LIBRARIES})
SET_TARGET_PROPERTIES(pathclient
		      PROPERTIES COMPILE_FLAGS "${EXTRA_CFLAGS}" LINK_FLAGS "${EXTRA_LINKFLAGS}")

INSTALL(TARGETS pathverify pathclient
	RUNTIME DESTINATION bin)

INSTALL(TARGETS pathfinderd
	RUNTIME DESTINATION sbin)

INSTALL(FILES README AUTHORS LICENSE pathfinderd.ini.sample DESTINATION share/doc/pathfinder)

ADD_EXECUTABLE(openssltest openssltest.cc)
TARGET_LINK_LIBRARIES(openssltest pathfinder-openssl-1 ${OPENSSL_LIBRARIES} ${DBUS_LIBRARIES})
SET_TARGET_PROPERTIES(openssltest 
		      PROPERTIES COMPILE_FLAGS "${DBUS_CFLAGS} ${EXTRA_CFLAGS}" LINK_FLAGS "${OPENSSL_LINKFLAGS} ${DBUS_LINKFLAGS}")

IF(NSS_CFLAGS)
ADD_EXECUTABLE(nsstest nsstest.cc)
TARGET_LINK_LIBRARIES(nsstest pathfinder-nss-1 ${NSS_LIBRARIES} ${DBUS_LIBRARIES})
SET_TARGET_PROPERTIES(nsstest
		      PROPERTIES COMPILE_FLAGS "${DBUS_CFLAGS} ${NSS_CFLAGS}" LINK_FLAGS "${DBUS_LINKFLAGS} ${NSS_LINKFLAGS}")
ENDIF(NSS_CFLAGS)

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

SET(CPACK_PACKAGE_NAME "pathfinder")
SET(CPACK_PACKAGE_DESCRIPTION_SUMMARY "pathfinder")
SET(CPACK_PACKAGE_VERSION_MAJOR "1")
SET(CPACK_PACKAGE_VERSION_MINOR "1")
SET(CPACK_PACKAGE_VERSION_PATCH "3")
SET(CPACK_SOURCE_IGNORE_FILES "/.git/;.gitignore;.*~;/.svn/;CMakeFiles/;CMakeCache.txt;/Testing/;DartTestfile.txt;.pc$;.cmake;/_CPack_Packages/;version.h$;.tar.gz;.tar.Z;.*#.*";/pathviewer-0.1.0-Source/;Makefile)
INCLUDE(CPack)
