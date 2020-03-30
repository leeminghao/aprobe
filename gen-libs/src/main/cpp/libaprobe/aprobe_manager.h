/****************************************************************************
 *
 * Copyright 2020 Mingo All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/
#pragma once

#include "map_info.h"
#include "process_map.h"

#include <deque>
#include <string>
#include <unordered_map>

#include <aprobe/aprobe.h>
#include <aprobe/macros.h>

namespace aprobe {

struct ProbeInfo {
  std::string symbol_name;
  uint64_t    handler;
};

class AprobeManager final : public Aprobe {
 public:
  AprobeManager();
  ~AprobeManager() override;

  int Register(const std::string& regex, const std::string symbol_name,
               uint64_t handler) override;

  int Load() override;

 private:
  std::deque<ProbeInfo> queued_requests_;
  std::unordered_map<std::string, MapInfo> cache_;

  DISALLOW_COPY_AND_ASSIGN(AprobeManager);
};

}  // namespace aprobe
