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

#include "debug.h"
#include "aprobe_manager.h"

#include <stdint.h>

#include <aprobe/err.h>

namespace aprobe {

namespace {

static constexpr char kProcSelfMaps[] = "/proc/self/maps";

}

AprobeManager::AprobeManager() { }

AprobeManager::~AprobeManager() {}

int AprobeManager::Register(const std::string& regex, const std::string symbol_name, uint64_t handler) {
  if (symbol_name.empty() || !handler) {
    return ERR_INVALID_ARGS;
  }
  queued_requests_.push_back(ProbeInfo{symbol_name, handler});

  return OK;
}

int AprobeManager::Load() {
  auto callback = [&](uint64_t start, uint64_t end, uint16_t flags, uint64_t pgoff, ino_t inode, const char* name) {
    // Filter all of the cannot hook regions.
    if (name == nullptr || pgoff != 0) return;
    if ((flags & PROT_READ) == 0 || (flags & PROT_SHARED) != 0)  return;
    if (strlen(name) == 0 || name[0] == '[') return;

    const std::string pathname(name);
    if (pathname.find("libnative-lib.so") == std::string::npos) return;

    cache_[pathname] = MapInfo{start, end, flags, pgoff, inode, name, nullptr};
    ElfInterface *elf = new ElfInterface(pathname, start);
    elf->Init();
    cache_[pathname].elf.reset(elf);

    for (const auto& req : queued_requests_) {
      elf->Hook(req.symbol_name, req.handler);
    }
  };

  if (!ReadMapFile(kProcSelfMaps, callback)) {
    return ERR_MAPS_UNKNOWN;
  }

  return OK;
}

std::unique_ptr<Aprobe> Aprobe::Create() {
  return std::unique_ptr<Aprobe>{ new AprobeManager() };
}

}  // namespace aprobe
