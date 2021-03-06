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

/**
 * Implements a main() method for unit tests
 */

#include <gmock/gmock.h>
#include <boost/log/core.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/trivial.hpp>

int main(int argc, char **argv) {
  boost::log::core::get()->set_filter(
      boost::log::trivial::severity > boost::log::trivial::info);

  ::testing::InitGoogleMock(&argc, argv);
  return RUN_ALL_TESTS();
}
