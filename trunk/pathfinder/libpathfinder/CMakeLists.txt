ADD_LIBRARY(pathfinder-nss-1 SHARED libpathfinder.cc libpathfinder-nss.cc)
ADD_LIBRARY(pathfinder-openssl-1 SHARED libpathfinder.cc libpathfinder-openssl.cc)

SET(LIBPATHFINDER_NSS_CFLAGS "${DBUS_CFLAGS} ${NSS_CFLAGS}")
SET(LIBPATHFINDER_OPENSSL_CFLAGS "${DBUS_CFLAGS} ${NSS_CFLAGS}")

SET_TARGET_PROPERTIES(pathfinder-nss-1
		      PROPERTIES COMPILE_FLAGS "${LIBPATHFINDER_NSS_CFLAGS}")
SET_TARGET_PROPERTIES(pathfinder-nss-1 PROPERTIES VERSION 1.0.0 SOVERSION 1 )

SET_TARGET_PROPERTIES(pathfinder-openssl-1
		      PROPERTIES COMPILE_FLAGS "${LIBPATHFINDER_OPENSSL_CFLAGS}")
SET_TARGET_PROPERTIES(pathfinder-openssl-1 PROPERTIES VERSION 1.0.0 SOVERSION 1 )

INSTALL(TARGETS pathfinder-nss-1 pathfinder-openssl-1
	LIBRARY DESTINATION lib)
INSTALL(FILES libpathfinder-nss.h libpathfinder-openssl.h libpathfinder.h
	      DESTINATION include/pathfinder-1)
