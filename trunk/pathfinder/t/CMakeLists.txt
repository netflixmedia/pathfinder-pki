PKGCONFIG(libwvtest WVTEST_INCLUDEDIR WVTEST_LIBDIR WVTEST_LINKFLAGS WVTEST_CFLAGS)

ADD_EXECUTABLE(all.t sigverif.t.cc certrevoke.t.cc testmethods.t.cc 
	       namechaining.t.cc validityperiods.t.cc certpolicies.t.cc
	       requireexplicitpolicy.t.cc policymapping.t.cc inhibitpolicymapping.t.cc 
	       basicconstraints.t.cc crldistpoint.t.cc)
TARGET_LINK_LIBRARIES(all.t pathology x509path)

SET_TARGET_PROPERTIES(all.t 
		      PROPERTIES COMPILE_FLAGS "${UNICONF_CFLAGS} ${WVTEST_CFLAGS} ${EXTRA_CFLAGS}"
		      		 LINK_FLAGS "${UNICONF_LINKFLAGS} ${WVTEST_LINKFLAGS}")
