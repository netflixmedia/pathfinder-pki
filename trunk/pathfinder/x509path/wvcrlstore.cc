#include "wvcrlstore.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <wvfile.h>
#include <wvstrutils.h>

using namespace boost;


WvCRLStore::WvCRLStore(WvStringParm _dir) :
    log("WvCRLStore", WvLog::Debug5)
{
    dir = _dir;
}


bool WvCRLStore::exists(WvStringParm crldp)
{
    WvString path("%s/%s", dir, url_encode(crldp));

    struct stat st;
    if (stat(path, &st) != 0 ||
        !S_ISREG(st.st_mode))
        return false;

    return true;
}


shared_ptr<WvCRL> WvCRLStore::get(WvStringParm crldp) 
{
    if (exists(crldp))
    {
        shared_ptr<WvCRL> crl(new WvCRL);
        WvString path("%s/%s", dir, url_encode(crldp));

        crl->decode(WvCRL::CRLFilePEM, path);
        if (!crl->isok()) 
            crl->decode(WvCRL::CRLFileDER, path);

        if (!crl->isok())
        {
            log(WvLog::Warning, "WARNING: Tried to add CRL from file %s, "
                "but loaded CRL not ok!\n", path);
            return shared_ptr<WvCRL>();
        }
        
        return crl;
    }

    return shared_ptr<WvCRL>();
}


void WvCRLStore::add(WvStringParm url, WvBuf &buf)
{
    WvString path("%s/%s", dir, url_encode(url));

    //  FIXME: blocking operation

    log("Writing %s (uri: %s) to crlstore.\n", path, url);
    WvFile f(path, O_CREAT|O_WRONLY);
    f.write(buf);
}
