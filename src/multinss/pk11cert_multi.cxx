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

#include <multinss/pk11cert_multi.h>
#include <multinss/DBContext.h>

#include <nss/pkitm.h>
#include <nss/dev3hack.h> // PK11Slot_GetNSSToken
#include <nss/dev.h>
#include <nss/pkim.h>

namespace multinss {

static void
transfer_token_certs_to_collection(const DBContext *const context, nssList *certList, NSSToken *token,
                                   nssPKIObjectCollection *collection)
{
  NSSCertificate **certs;
  PRUint32 i, count;
  NSSToken **tokens, **tp;
  count = nssList_Count(certList);
  if (count == 0) {
    return;
  }
  certs = nss_ZNEWARRAY(NULL, NSSCertificate *, count);
  if (!certs) {
    return;
  }
  nssList_GetArray(certList, (void **)certs, count);
  for (i = 0; i < count; i++) {
    tokens = nssPKIObject_GetTokens(&certs[i]->object, NULL);
    if (tokens) {
      for (tp = tokens; *tp; tp++) {
        if (*tp == token) {
          nssPKIObjectCollection_AddObject(collection,
                                           (nssPKIObject *)certs[i]);
        }
      }
      nssTokenArray_Destroy(tokens);
    }
    CERT_DestroyCertificate(STAN_GetCERTCertificateOrRelease(context, certs[i]));
  }
  nss_ZFreeIf(certs);
}

SECStatus
PK11_TraverseCertsInSlot(const DBContext *const context, PK11SlotInfo *slot,
                         SECStatus (*callback)(CERTCertificate *, void *), void *arg)
{
  PRStatus nssrv;
  NSSTrustDomain *td = context->getTrustDomain(); // STAN_GetDefaultTrustDomain();
  NSSToken *tok;
  nssList *certList = NULL;
  nssCryptokiObject **instances;
  nssPKIObjectCollection *collection;
  NSSCertificate **certs;
  nssTokenSearchType tokenOnly = nssTokenSearchType_TokenOnly;
  tok = PK11Slot_GetNSSToken(slot);
  if (!nssToken_IsPresent(tok)) {
    return SECSuccess;
  }
  collection = nssCertificateCollection_Create(td, NULL);
  if (!collection) {
    return SECFailure;
  }
  certList = nssList_Create(NULL, PR_FALSE);
  if (!certList) {
    nssPKIObjectCollection_Destroy(collection);
    return SECFailure;
  }
  (void)nssTrustDomain_GetCertsFromCache(td, certList);
  transfer_token_certs_to_collection(certList, tok, collection);
  instances = nssToken_FindObjects(tok, NULL, CKO_CERTIFICATE,
                                   tokenOnly, 0, &nssrv);
  nssPKIObjectCollection_AddInstances(collection, instances, 0);
  nss_ZFreeIf(instances);
  nssList_Destroy(certList);
  certs = nssPKIObjectCollection_GetCertificates(collection,
                                                 NULL, 0, NULL);
  nssPKIObjectCollection_Destroy(collection);
  if (certs) {
    CERTCertificate *oldie;
    NSSCertificate **cp;
    for (cp = certs; *cp; cp++) {
      oldie = STAN_GetCERTCertificate(*cp);
      if (!oldie) {
        continue;
      }
      if ((*callback)(oldie, arg) != SECSuccess) {
        nssrv = PR_FAILURE;
        break;
      }
    }
    nssCertificateArray_Destroy(certs);
  }
  return (nssrv == PR_SUCCESS) ? SECSuccess : SECFailure;
}

}
