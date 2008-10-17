ADD_LIBRARY(x509path STATIC wvcrlcache.cc wvx509path.cc wvx509store.cc 
  wvx509policytree.cc)
SET_TARGET_PROPERTIES(x509path
		      PROPERTIES COMPILE_FLAGS ${EXTRA_CFLAGS})
