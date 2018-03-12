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

namespace multinss {

class DBContext {
public:
  DBContext();

  CERTCertDBHandle *getDbHandle() const;
  void setDbHandle(CERTCertDBHandle *);

private:
  CERTCertDBHandle *db_handle;
};

}

#endif //MULTINSS_DBCONTEXT_H
