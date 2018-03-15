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

#include <multinss/certificate_multi.h>
#include <multinss/DBContext.h>

struct NSSCertificateStr;
typedef struct NSSCertificateStr NSSCertificate;
typedef struct nssCertificateStoreTraceStr nssCertificateStoreTrace;

namespace multinss {

PRStatus
nssCertificate_Destroy(const DBContext *const context, NSSCertificate *c)
{
  nssCertificateStoreTrace lockTrace = { NULL, NULL, PR_FALSE, PR_FALSE };
  nssCertificateStoreTrace unlockTrace = { NULL, NULL, PR_FALSE, PR_FALSE };

  if (c) {
    PRUint32 i;
    nssDecodedCert *dc = c->decoding;
    NSSTrustDomain *td = context->getTrustDomain(); // STAN_GetDefaultTrustDomain();
    NSSCryptoContext *cc = c->object.cryptoContext;

    PR_ASSERT(c->object.refCount > 0);

    /* --- LOCK storage --- */
    if (cc) {
      nssCertificateStore_Lock(cc->certStore, &lockTrace);
    } else {
      nssTrustDomain_LockCertCache(td);
    }
    if (PR_ATOMIC_DECREMENT(&c->object.refCount) == 0) {
      /* --- remove cert and UNLOCK storage --- */
      if (cc) {
        nssCertificateStore_RemoveCertLOCKED(cc->certStore, c);
        nssCertificateStore_Unlock(cc->certStore, &lockTrace,
                                   &unlockTrace);
      } else {
        nssTrustDomain_RemoveCertFromCacheLOCKED(td, c);
        nssTrustDomain_UnlockCertCache(td);
      }
      /* free cert data */
      for (i = 0; i < c->object.numInstances; i++) {
        nssCryptokiObject_Destroy(c->object.instances[i]);
      }
      nssPKIObject_DestroyLock(&c->object);
      nssArena_Destroy(c->object.arena);
      nssDecodedCert_Destroy(dc);
    } else {
      /* --- UNLOCK storage --- */
      if (cc) {
        nssCertificateStore_Unlock(cc->certStore,
                                   &lockTrace,
                                   &unlockTrace);
      } else {
        nssTrustDomain_UnlockCertCache(td);
      }
    }
  }
  return PR_SUCCESS;
}

}
