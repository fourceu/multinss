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

#include <gtest/gtest.h>

#include <multinss/DBContext.h>
#include <nss/secmodt.h>

TEST(DBContextTests, ctor) {
  auto instance = new multinss::DBContext();

  EXPECT_NE(nullptr, instance);

  delete instance;
}

TEST(DBContextTests, getDBHandle) {
  multinss::DBContext context;

  EXPECT_EQ(nullptr, context.getDbHandle());
}

TEST(DBContextTests, setDBHandle) {
  multinss::DBContext context;
  CERTCertDBHandle handle;

  EXPECT_EQ(nullptr, context.getDbHandle());

  context.setDbHandle(&handle);
  EXPECT_EQ(&handle, context.getDbHandle());
}

TEST(DBContextTests, getPasswordCb) {
  multinss::DBContext context;

  EXPECT_EQ(nullptr, context.getPasswordCb());
}

TEST(DBContextTests, setPasswordCb) {
  multinss::DBContext context;
  PK11PasswordFunc pw_cb;

  EXPECT_EQ(nullptr, context.getPasswordCb());

  context.setPasswordCb(pw_cb);
  EXPECT_EQ(pw_cb, context.getPasswordCb());
}

TEST(DBContextTests, getInternalModule) {
  multinss::DBContext context;

  EXPECT_EQ(nullptr, context.getInternalModule());
}

TEST(DBContextTests, setInternalModule) {
  multinss::DBContext context;
  SECMODModule module;

  EXPECT_EQ(nullptr, context.getInternalModule());

  context.setInternalModule(&module);
  EXPECT_EQ(&module, context.getInternalModule());
}

TEST(DBContextTests, getInternalKeySlot) {
  multinss::DBContext context;

  EXPECT_EQ(nullptr, context.getInternalKeySlot());
}

TEST(DBContextTests, setInternalKeySlot) {
  multinss::DBContext context;
  PK11SlotInfo *slot; // Something random and uninitialised - perfect for our test!

  EXPECT_EQ(nullptr, context.getInternalKeySlot());

  context.setInternalKeySlot(slot);
  EXPECT_EQ(slot, context.getInternalKeySlot());
}

TEST(DBContextTests, getTrustDomain) {
  multinss::DBContext context;

  EXPECT_EQ(nullptr, context.getTrustDomain());
}

TEST(DBContextTests, setTrustDomain) {
  multinss::DBContext context;
  NSSTrustDomain *domain; // Something random and uninitialised - perfect for our test!

  EXPECT_EQ(nullptr, context.getTrustDomain());

  context.setTrustDomain(domain);
  EXPECT_EQ(domain, context.getTrustDomain());
}
