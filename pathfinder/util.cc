#include <wvfile.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <assert.h>
#include "util.h"

using namespace boost;

WvX509::DumpMode guess_encoding(WvBuf &buf)
{
    if (buf.used() < 10)
        return WvX509::CertDER;

    if (!strncmp("-----BEGIN", (const char *) buf.peek(0, 10), 10))
        return WvX509::CertPEM;

    return WvX509::CertDER;
}


WvX509::DumpMode guess_encoding(WvStringParm fname)
{
    WvFile f(fname, O_RDONLY);
    WvDynBuf buf;
    size_t read = f.read(buf, 10);

    WvX509::DumpMode mode = guess_encoding(buf);
    if (mode == WvX509::CertPEM)
        return WvX509::CertFilePEM;

    return WvX509::CertFileDER;
}

bool is_md(shared_ptr<WvX509> &x509)
{	
    X509 *cert = x509->get_cert();
    int alg = OBJ_obj2nid(cert->sig_alg->algorithm);
    
    if (alg == NID_md5WithRSAEncryption || alg == NID_md2WithRSAEncryption)
        return true;
      
    return false;
}

