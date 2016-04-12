An RFC3280 compliant X.509 certificate validator.

# Introduction #

One thing has been missing for quite a while in the Linux and Open Source community, and that is a standard way to validate X.509 certificates. Now, there have been some efforts, as the Netscape/Mozilla LibNSS people have done quite a bit of work, and the [Ägypten project](http://www.gnupg.org/aegypten/) has an implementation that works with a good portion of programs that use gpgsm. But, for the most part, it appears that there hasn't been an effort to create a common framework that allows for the definition and configuration of trust anchors, and the validation of X.509 certificates. So, [Carillon Information Security](http://www.carillon.ca) decided to sponsor a project to create that framework.

# Details #

The goals of Pathfinder are to enable:

  * Bridge Aware PKI validation
  * Certificate Policy mapping and validation
  * Full Authority Info Access certificate fetching
  * Dynamic CRL fetching
  * OCSP support for revocation checking, using the responder specified in the Authority Info Access extension.
  * Easy Integration into both the OpenSSL and Netscape LibNSS frameworks.