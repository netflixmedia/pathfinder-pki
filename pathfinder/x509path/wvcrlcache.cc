#include "wvcrlcache.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <wvfile.h>
#include <wvstrutils.h>

using namespace boost;


WvCRLCache::WvCRLCache(WvStringParm _dir) :
    log("CRL Cache", WvLog::Debug5)
{
    dir = _dir;
}


shared_ptr<WvCRL> WvCRLCache::get(WvStringParm crldp) 
{
    WvString path("%s/%s", dir, url_encode(crldp));
    struct stat st;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode))
        return shared_ptr<WvCRL>();

    if (crlmap.count(crldp.cstr()) && crlmap[crldp.cstr()].mtime == st.st_mtime)
        return crlmap[crldp.cstr()].crl;

    shared_ptr<WvCRL> crl(new WvCRL);
    crl->decode(WvCRL::CRLFilePEM, path);
    if (!crl->isok()) 
        crl->decode(WvCRL::CRLFileDER, path);
    
    if (!crl->isok())
    {
        log(WvLog::Warning, "WARNING: Tried to add CRL from file %s, "
            "but loaded CRL not ok!\n", path);
        return shared_ptr<WvCRL>();
    }
        
    crlmap[crldp.cstr()] = CRLCacheEntry(st.st_mtime, crl);
    return crl;
}


void WvCRLCache::add(WvStringParm url, WvBuf &buf)
{
    WvString path("%s/%s", dir, url_encode(url));

    //  FIXME: blocking operation

    log("Writing %s (uri: %s) to crlcache.\n", path, url);
    WvFile f(path, O_CREAT|O_WRONLY);
    f.write(buf);
}
