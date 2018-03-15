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

#include <multinss/DBContext.h>

namespace multinss {

DBContext::DBContext() : db_handle(nullptr),
                         password_cb(nullptr),
                         internal_module(nullptr),
                         internal_key_slot(nullptr),
                         trust_domain(nullptr) {

}

CERTCertDBHandle *DBContext::getDbHandle() const {
  return db_handle;
}

void DBContext::setDbHandle(CERTCertDBHandle *value) {
  db_handle = value;
}

PK11PasswordFunc DBContext::getPasswordCb() const {
  return password_cb;
}

void DBContext::setPasswordCb(PK11PasswordFunc value) {
  password_cb = value;
}

SECMODModule *DBContext::getInternalModule() const {
  return internal_module;
}

void DBContext::setInternalModule(SECMODModule *value) {
  internal_module = value;
}

PK11SlotInfo *DBContext::getInternalKeySlot() const {
  return internal_key_slot;
}

void DBContext::setInternalKeySlot(PK11SlotInfo *value) {
  internal_key_slot = value;
}

NSSTrustDomain *DBContext::getTrustDomain() const {
  return trust_domain;
}

void DBContext::setTrustDomain(NSSTrustDomain *value) {
  trust_domain = value;
}

}
