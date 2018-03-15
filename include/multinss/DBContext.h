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

#ifndef MULTINSS_DBCONTEXT_H
#define MULTINSS_DBCONTEXT_H

#include <nss/pkit.h>
#include <nss/secmodt.h>

namespace multinss {

class DBContext {
public:
  DBContext();

  CERTCertDBHandle *getDbHandle() const;
  void setDbHandle(CERTCertDBHandle *);

  PK11PasswordFunc getPasswordCb() const;
  void setPasswordCb(PK11PasswordFunc);

  SECMODModule *getInternalModule() const;
  void setInternalModule(SECMODModule *);

  PK11SlotInfo *getInternalKeySlot() const;
  void setInternalKeySlot(PK11SlotInfo *);

  NSSTrustDomain *getTrustDomain() const;
  void setTrustDomain(NSSTrustDomain *);

private:
  CERTCertDBHandle *db_handle;
  PK11PasswordFunc password_cb;
  SECMODModule *internal_module;
  PK11SlotInfo *internal_key_slot;
  NSSTrustDomain *trust_domain;
};

}

#endif //MULTINSS_DBCONTEXT_H
