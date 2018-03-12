# This file is part of multinss.
#
# multinss is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# multinss is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser Public License for more details.
#
# You should have received a copy of the GNU Lesser Public License
# along with multinss.  If not, see <http://www.gnu.org/licenses/>.

project(unittests CXX)

# Set the target name policy to allow the reserved target name "test" to be used
if (POLICY CMP0037)
    message(STATUS "Setting target name policy to OLD (allowing use of reserved target names)")
    cmake_policy(SET CMP0037 OLD)
endif ()

include_directories(../../src "${CMAKE_CURRENT_SOURCE_DIR}" "${GTEST_INCLUDE_DIRS}")

set(test_SRCS
        main.cxx
        multinss/DBContextTests.cxx
)

ADD_EXECUTABLE(${PROJECT_NAME} ${test_SRCS})
ADD_DEPENDENCIES(${PROJECT_NAME} googletest)
TARGET_LINK_LIBRARIES(${PROJECT_NAME} ${CMAKE_PROJECT_NAME} ${Boost_LIBRARIES} ${GTEST_LIBRARIES} pthread)

if (BUILD_GTEST_FILTER)
    SET(GTEST_FILTER --gtest_filter=${BUILD_GTEST_FILTER})
endif ()

SET(UNIT_TEST_BINARY "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}${CMAKE_EXECUTABLE_SUFFIX}")

ADD_CUSTOM_TARGET(test "${UNIT_TEST_BINARY}"
    --gtest_output=xml
    ${GTEST_FILTER}
    DEPENDS ${PROJECT_NAME}
    COMMENT "Executing unit tests..."
    VERBATIM SOURCES ${test_SRCS})

if (BUILD_COVERAGE)
    SETUP_TARGET_FOR_COVERAGE(
	    coverage                        # Name for custom target.
        "${UNIT_TEST_BINARY}"           # Name of the test driver executable that runs the tests.
                                        # NOTE! This should always have a ZERO as exit code
                                        # otherwise the coverage generation will not complete.
        unit_test_coverage              # Name of output directory.
    )
    ADD_DEPENDENCIES(coverage test)
    SETUP_TARGET_FOR_COVERAGE_COBERTURA(
	    coverage_cobertura              # Name for custom target.
        "${UNIT_TEST_BINARY}"           # Name of the test driver executable that runs the tests.
                                        # NOTE! This should always have a ZERO as exit code
                                        # otherwise the coverage generation will not complete.
        unit_test_coverage_cobertura    # cobertura output is generated as _outputname.xml
    )
endif ()
