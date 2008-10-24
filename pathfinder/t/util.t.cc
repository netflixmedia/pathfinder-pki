#include <wvfile.h>
#include <wvfileutils.h>
#include <wvtest.h>
#include <wvx509mgr.h>
#include "testmethods.t.h"
#include "util.h"


WVTEST_MAIN("guess encoding")
{
    WvX509Mgr ca("CN=test.foo.com,DC=foo,DC=com", DEFAULT_KEYLEN, true);
    WvString fname = wvtmpfilename("pathfinder-encoding-");
    
    WvDynBuf buf;
    ca.encode(WvX509::CertDER, buf);
    size_t old_used = buf.used();
    WVPASSEQ(guess_encoding(buf), WvX509::CertDER);
    WVPASSEQ(old_used, buf.used());

    {
        WvFile f(fname, O_CREAT|O_WRONLY);
        f.write(buf);
    }

    WVPASSEQ(guess_encoding(fname), WvX509::CertFileDER);

    ::unlink(fname);

    buf.zap();
    ca.encode(WvX509::CertPEM, buf);
    old_used = buf.used();
    WVPASSEQ(guess_encoding(buf), WvX509::CertPEM);
    WVPASSEQ(old_used, buf.used());

    {
        WvFile f(fname, O_CREAT|O_WRONLY);
        f.write(buf);       
    }

    WVPASSEQ(guess_encoding(fname), WvX509::CertFilePEM);

    ::unlink(fname);
}
