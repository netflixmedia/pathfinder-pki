PKGCONFIG(libwvtest WVTEST_INCLUDEDIR WVTEST_LIBDIR WVTEST_LINKFLAGS WVTEST_CFLAGS)

ADD_EXECUTABLE(all.t pathserver.t.cc sigverif.t.cc certrevoke.t.cc 
  testmethods.t.cc namechaining.t.cc validityperiods.t.cc certpolicies.t.cc
  requireexplicitpolicy.t.cc policymapping.t.cc inhibitpolicymapping.t.cc 
  basicconstraints.t.cc crldistpoint.t.cc wvcrlcache.t.cc pathvalidator.t.cc
  revocationfinder.t.cc pathfinder.t.cc wvx509path.t.cc util.t.cc
  download.t.cc)
TARGET_LINK_LIBRARIES(all.t pathology x509path)

SET_TARGET_PROPERTIES(all.t 
  PROPERTIES COMPILE_FLAGS "${WVDBUS_CFLAGS} ${WVTEST_CFLAGS} ${EXTRA_CFLAGS}"
  LINK_FLAGS "${WVDBUS_LINKFLAGS} ${WVTEST_LINKFLAGS} ${OPENSSL_LINKFLAGS} ${LDAP_LINKFLAGS}")

ADD_CUSTOM_TARGET(test COMMAND t/testrun.sh DEPENDS all.t WORKING_DIRECTORY .)