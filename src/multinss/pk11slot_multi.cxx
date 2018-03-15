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

namespace multinss {

PK11SlotInfo *
PK11_GetInternalKeySlot(const DBContext& context) {
  SECMODModule *mod;

  if (context.getInternalKeySlot() != nullptr) { // pk11InternalKeySlot
    return PK11_ReferenceSlot(context.getInternalKeySlot());
  }

  mod = context.getInternalModule(); //SECMOD_GetInternalModule();
  PORT_Assert(mod != NULL);
  if (!mod) {
    PORT_SetError(SEC_ERROR_NO_MODULE);
    return NULL;
  }
  return PK11_ReferenceSlot(mod->isFIPS ? mod->slots[0] : mod->slots[1]);
}

}
