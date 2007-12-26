ADD_LIBRARY(wvdbus STATIC wvdbusconn.cc wvdbuslistener.cc wvdbusservconn.cc wvdbuswatch.cc
            wvdbusconnp.cc wvdbusmsg.cc wvdbusserver.cc)
SET_TARGET_PROPERTIES(wvdbus
		      PROPERTIES COMPILE_FLAGS ${EXTRA_CFLAGS})
