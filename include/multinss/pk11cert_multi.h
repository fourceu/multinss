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

#ifndef MULTINSS_PK11CERT_MULTI_H
#define MULTINSS_PK11CERT_MULTI_H

#include <nss/seccomon.h>

typedef struct PK11SlotInfoStr PK11SlotInfo;          /* defined in secmodti.h */
typedef struct CERTCertificateStr CERTCertificate;

namespace multinss {

class DBContext;

SECStatus
PK11_TraverseCertsInSlot(const DBContext *const context, PK11SlotInfo *slot,
                         SECStatus (*callback)(CERTCertificate *, void *), void *arg);

}

#endif //MULTINSS_PK11CERT_MULTI_H
