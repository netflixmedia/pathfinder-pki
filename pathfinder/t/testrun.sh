#!/bin/sh

# stupid script to execute WvStreams unit test stuff. right now only set up to 
# run tests with in-tree version of wvstreams, but should be extendable to 
# do so out of tree as well

WVTESTHELPER="$WVSTREAMS_SRC/wvtestrun"
SUPPRESSIONS="$WVSTREAMS_SRC/wvstreams.supp"
VALGRIND="valgrind --tool=memcheck --leak-check=yes --num-callers=10 --log-file=valgrind.log --suppressions=$SUPPRESSIONS"

$WVTESTHELPER $VALGRIND t/all.t $TESTNAME
