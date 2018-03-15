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


#ifndef MULTINSS_CERTIFICATE_MULTI_H
#define MULTINSS_CERTIFICATE_MULTI_H

#include <nspr/prtypes.h>

#include <nss/pkit.h>

namespace multinss {

class DBContext;

PRStatus nssCertificate_Destroy(const DBContext *const context, NSSCertificate *c);

}

#endif //MULTINSS_CERTIFICATE_MULTI_H
