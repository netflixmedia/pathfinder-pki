ADD_LIBRARY(pathfinder-nss-1 SHARED libpathfinder.cc libpathfinder-nss.cc)
ADD_LIBRARY(pathfinder-nss-1-static STATIC libpathfinder.cc libpathfinder-openssl.cc)

ADD_LIBRARY(pathfinder-openssl-1 SHARED libpathfinder.cc libpathfinder-openssl.cc)
ADD_LIBRARY(pathfinder-openssl-1-static STATIC libpathfinder.cc libpathfinder-openssl.cc)

SET(LIBPATHFINDER_NSS_CFLAGS "${DBUS_CFLAGS} ${NSS_CFLAGS}")
SET(LIBPATHFINDER_OPENSSL_CFLAGS "${DBUS_CFLAGS} ${OPENSSL_CFLAGS}")

SET_TARGET_PROPERTIES(pathfinder-nss-1
		      PROPERTIES COMPILE_FLAGS "${LIBPATHFINDER_NSS_CFLAGS}")
SET_TARGET_PROPERTIES(pathfinder-nss-1 PROPERTIES VERSION 1.0.0 SOVERSION 1 )
SET_TARGET_PROPERTIES(pathfinder-nss-1 PROPERTIES CLEAN_DIRECT_OUTPUT 1)

SET_TARGET_PROPERTIES(pathfinder-nss-1-static PROPERTIES CLEAN_DIRECT_OUTPUT 1)
SET_TARGET_PROPERTIES(pathfinder-nss-1-static PROPERTIES OUTPUT_NAME "libpathfinder-nss-1")
SET_TARGET_PROPERTIES(pathfinder-nss-1-static PROPERTIES COMPILE_FLAGS "${DBUS_CFLAGS} ${NSS_CFLAGS} -fPIC")

SET_TARGET_PROPERTIES(pathfinder-openssl-1
		      PROPERTIES COMPILE_FLAGS "${LIBPATHFINDER_OPENSSL_CFLAGS}")
SET_TARGET_PROPERTIES(pathfinder-openssl-1 PROPERTIES VERSION 1.0.0 SOVERSION 1 )
SET_TARGET_PROPERTIES(pathfinder-openssl-1 PROPERTIES CLEAN_DIRECT_OUTPUT 1)

SET_TARGET_PROPERTIES(pathfinder-openssl-1-static PROPERTIES CLEAN_DIRECT_OUTPUT 1)
SET_TARGET_PROPERTIES(pathfinder-openssl-1-static PROPERTIES OUTPUT_NAME "libpathfinder-openssl-1")
SET_TARGET_PROPERTIES(pathfinder-openssl-1-static PROPERTIES COMPILE_FLAGS "${DBUS_CFLAGS} ${OPENSSL_CFLAGS} -fPIC")


INSTALL(TARGETS pathfinder-nss-1 pathfinder-openssl-1 pathfinder-nss-1-static 
	pathfinder-openssl-1-static LIBRARY DESTINATION lib ARCHIVE DESTINATION lib)
INSTALL(FILES libpathfinder-nss.h libpathfinder-openssl.h libpathfinder.h
	      DESTINATION include/pathfinder-1)
