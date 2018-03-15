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

#include <multinss/certread_multi.h>
#include <multinss/DBContext.h>

#include <nss/cert.h>
#include <nss/pkim.h>

namespace multinss {

typedef struct {
  PLArenaPool *arena;
  SECItem cert;
} collect_args;

static SECStatus
collect_certs(void *arg, SECItem **certs, int numcerts)
{
  SECStatus rv;
  collect_args *collectArgs;

  collectArgs = reinterpret_cast<collect_args *>(arg);

  rv = SECITEM_CopyItem(collectArgs->arena, &collectArgs->cert, *certs);

  return (rv);
}

CERTCertificate *
CERT_DecodeCertFromPackage(const DBContext *const context, char *certbuf, int certlen) {
  collect_args collectArgs;
  SECStatus rv;
  CERTCertificate *cert = NULL;

  collectArgs.arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);

  rv = CERT_DecodeCertPackage(certbuf, certlen, collect_certs,
                              (void *) &collectArgs);
  if (rv == SECSuccess) {
    cert = CERT_NewTempCertificate(context->getDbHandle(),
                                   &collectArgs.cert, NULL,
                                   PR_FALSE, PR_TRUE);
  }

  PORT_FreeArena(collectArgs.arena, PR_FALSE);

  return (cert);
}

}
