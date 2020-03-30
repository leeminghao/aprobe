#
# Copyright (C) 2020 Mingo All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

cmake_minimum_required(VERSION 3.4.1)

set(CMAKE_VERBOSE_MAKEFILE on)

add_library(aprobe SHARED
  aprobe_manager.cpp
  elf_interface.cpp
  file.cpp
  process_map.cpp)

target_include_directories(aprobe PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/include)

find_library(log-lib log)

target_link_libraries(aprobe ${log-lib})

# copy out the lib binary and remove generated files
set(distribution_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../distribution)
set_target_properties(aprobe
                      PROPERTIES
                      LIBRARY_OUTPUT_DIRECTORY
                      "${distribution_DIR}/aprobe/lib/${ANDROID_ABI}")

add_custom_command(TARGET aprobe POST_BUILD
                   COMMAND "${CMAKE_COMMAND}" -E
                   copy_directory "${CMAKE_CURRENT_SOURCE_DIR}/include/aprobe"
                   "${distribution_DIR}/aprobe/include/aprobe"
                   COMMENT "Copying aprobe to output directory")
