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

#ifndef MULTINSS_PK11AUTH_MULTI_H
#define MULTINSS_PK11AUTH_MULTI_H

#include <nspr/prtypes.h>
#include <nss/seccomon.h>

typedef struct PK11SlotInfoStr PK11SlotInfo;

namespace multinss {

class DBContext;

PRBool pk11_LoginStillRequired(const DBContext *const context, PK11SlotInfo *slot, void *wincx);

SECStatus PK11_Authenticate(const DBContext *const context, PK11SlotInfo *slot, PRBool loadCerts, void *wincx);

PRBool PK11_IsLoggedIn(const DBContext *const context, PK11SlotInfo *slot, void *wincx);

}

#endif //MULTINSS_PK11AUTH_MULTI_H
