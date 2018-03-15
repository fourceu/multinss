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

#include <multinss/pk11auth_multi.h>
#include <multinss/DBContext.h>

#include <nss/secmodi.h>
#include <nss/pk11pub.h>

namespace multinss {

PRBool
pk11_LoginStillRequired(const DBContext *const context, PK11SlotInfo *slot, void *wincx) {
  return PK11_NeedLogin(slot) && !PK11_IsLoggedIn(context, slot, wincx);
}

SECStatus
PK11_Authenticate(const DBContext *const context, PK11SlotInfo *slot, PRBool loadCerts, void *wincx) {
  if (!slot) {
    return SECFailure;
  }
  if (pk11_LoginStillRequired(context, slot, wincx)) {
    return PK11_DoPassword(context, slot, slot->session, loadCerts, wincx,
                           PR_FALSE, PR_FALSE);
  }
  return SECSuccess;
}

PRBool
PK11_IsLoggedIn(const DBContext *const context, PK11SlotInfo *slot, void *wincx) {
  CK_SESSION_INFO sessionInfo;
  int askpw = slot->askpw;
  int timeout = slot->timeout;
  CK_RV crv;
  PRIntervalTime curTime;
  static PRIntervalTime login_delay_time = 0;

  if (login_delay_time == 0) {
    login_delay_time = PR_SecondsToInterval(1);
  }

  /* If we don't have our own password default values, use the system
   * ones */
  if ((slot->defaultFlags & PK11_OWN_PW_DEFAULTS) == 0) {
    PK11SlotInfo *def_slot = PK11_GetInternalKeySlot(context);

    if (def_slot) {
      askpw = def_slot->askpw;
      timeout = def_slot->timeout;
      PK11_FreeSlot(def_slot);
    }
  }

  if ((wincx != NULL) && (PK11_Global.isLoggedIn != NULL) &&
      (*PK11_Global.isLoggedIn)(slot, wincx) == PR_FALSE) {
    return PR_FALSE;
  }

  /* forget the password if we've been inactive too long */
  if (askpw == 1) {
    PRTime currtime = PR_Now();
    PRTime result;
    PRTime mult;

    LL_I2L(result, timeout);
    LL_I2L(mult, 60 * 1000 * 1000);
    LL_MUL(result, result, mult);
    LL_ADD(result, result, slot->authTime);
    if (LL_CMP(result, <, currtime)) {
      PK11_EnterSlotMonitor(slot);
      PK11_GETTAB(slot)->C_Logout(slot->session);
      slot->lastLoginCheck = 0;
      PK11_ExitSlotMonitor(slot);
    } else {
      slot->authTime = currtime;
    }
  }

  PK11_EnterSlotMonitor(slot);
  if (pk11_InDelayPeriod(slot->lastLoginCheck, login_delay_time, &curTime)) {
    sessionInfo.state = slot->lastState;
    crv = CKR_OK;
  } else {
    crv = PK11_GETTAB(slot)->C_GetSessionInfo(slot->session, &sessionInfo);
    if (crv == CKR_OK) {
      slot->lastState = sessionInfo.state;
      slot->lastLoginCheck = curTime;
    }
  }
  PK11_ExitSlotMonitor(slot);
  /* if we can't get session info, something is really wrong */
  if (crv != CKR_OK) {
    slot->session = CK_INVALID_SESSION;
    return PR_FALSE;
  }

  switch (sessionInfo.state) {
    case CKS_RW_PUBLIC_SESSION:
    case CKS_RO_PUBLIC_SESSION:
    default:
      break; /* fail */
    case CKS_RW_USER_FUNCTIONS:
    case CKS_RW_SO_FUNCTIONS:
    case CKS_RO_USER_FUNCTIONS:
      return PR_TRUE;
  }
  return PR_FALSE;
}

}
