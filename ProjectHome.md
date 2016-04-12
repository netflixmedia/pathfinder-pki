PathFinder is designed to provide a mechanism for any program to perform
[RFC3280](http://www.ietf.org/rfc/rfc3280.txt)-compliant path validation of X509 certificates, even when some of the intermediate certificates are not present on the local machine. By design, Pathfinder automatically downloads any such certificates from the Internet as needed using the AIA and CRL distribution point extensions of the certificates it is processing. It has the ability to do revocation status checking either using CRL or OCSP, or both. And, given the recent vulnerabilities that have rendered the MD5 algorithm highly suspect, it allows the administrator to choose to not validate certificates using that algorithm anywhere in the trust path.

For the convenience of those using OpenSSL or NSS (Netscape Security Services), two libraries containing a Pathfinder callback suitable for use with an SSL connection are provided with the main distribution.

It does its best to pass [NIST PKITS](http://csrc.nist.gov/groups/ST/crypto_apps_infra/pki/pkitesting.html), although it has not been submitted yet for formal validation.

If you are looking for a demonstration of Pathfinder, you may be interested in [Pathviewer](Pathviewer.md),
which provides a graphical view of path validation via a GTK+ interface.

For patches to integrate Pathfinder with certain common applications please see:
  * [Apache (mod\_ssl)](http://www.carillon.ca/products/pf_apache2.php)
  * [OpenLDAP](http://www.carillon.ca/products/pf_openldap.php)
  * [FreeRadius](http://www.carillon.ca/products/pf_freeradius.php)
