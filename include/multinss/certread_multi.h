/*
 * This file is part of multinss.
 *
 * multinss is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * multinss is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser Public License for more details.
 *
 * You should have received a copy of the GNU Lesser Public License
 * along with multinss.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef MULTINSS_CERTREAD_MULTI_H

typedef struct CERTCertificateStr CERTCertificate;

namespace multinss {

class DBContext;

/**
 * @brief Read a certificate in some foreign format and convert it to NSS internal format.
 * @param certbuf the buffer containing the certificate
 * @param certlen the length of the buffer
 * @note currently supports netscape base64 ascii encoded raw certs
 *  and netscape binary DER typed files.
 *
 * @return
 */
CERTCertificate *CERT_DecodeCertFromPackage(const DBContext *context, char *certbuf, int certlen);

}

#endif //MULTINSS_CERTREAD_MULTI_H
