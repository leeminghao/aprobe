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

#include <link.h>

#include <string>

#include <aprobe/macros.h>

namespace aprobe {

class ElfInterface {
 public:
  ElfInterface(const std::string& pathname, uint64_t base_addr);
  virtual ~ElfInterface();

  int Init();
  int Hook(const std::string& symbol_name, uint64_t handler);

 private:
  ElfW(Phdr) *GetProgramSegment(ElfW(Word) type);
  ElfW(Phdr) *GetProgramSegment(ElfW(Word) type, ElfW(Off) offset);

  bool LookupSymbolIndex(const std::string& symbol_name, uint32_t *symbol_index);
  bool LookupHash(const std::string& symbol_name, uint32_t *symbol_index);
  bool LookupGnuHash(const std::string& symbol_name, uint32_t *symbol_index);
  bool LookupGnuHashDef(const std::string& symbol_name, uint32_t *symbol_index);
  bool LookupGnuHashUndef(const std::string& symbol_name, uint32_t *symbol_index);

  uint32_t ElfHash(const std::string& str);
  uint32_t ElfGnuHash(const std::string& str);

  int FindAndReplaceFunc(const std::string& section, bool is_plt,
                         const std::string& symbol_name,
                         void *new_func, void **old_func,
                         uint32_t symbol_index, void *rel_common,
                         bool *found);
  int ReplaceFunc(const std::string& symbol_name, ElfW(Addr) addr,
                  void *new_func, void **old_func);

  std::string pathname_;

  ElfW(Addr)  base_addr_{0};
  ElfW(Addr)  bias_addr_{0};

  ElfW(Ehdr) *ehdr_{nullptr};
  ElfW(Phdr) *phdr_{nullptr};

  ElfW(Dyn)  *dyn_{nullptr};    //.dynamic
  ElfW(Word)  dyn_sz_{0};

  const char *strtab_{nullptr}; //.dynstr (string-table)
  ElfW(Sym)  *symtab_{nullptr}; //.dynsym (symbol-index to string-table's offset)

  ElfW(Addr)  relplt_{0}; //.rel.plt or .rela.plt
  ElfW(Word)  relplt_sz_{0};

  ElfW(Addr)  reldyn_{0}; //.rel.dyn or .rela.dyn
  ElfW(Word)  reldyn_sz_{0};

  ElfW(Addr)  relandroid_{0}; //android compressed rel or rela
  ElfW(Word)  relandroid_sz_{0};

  // for ELF hash
  uint32_t   *bucket_{nullptr};
  uint32_t    bucket_cnt_{0};
  uint32_t   *chain_{0};
  uint32_t    chain_cnt_{0}; // invalid for GNU hash

  // append for GNU hash
  uint32_t    symoffset_{0};
  ElfW(Addr) *bloom_{nullptr};
  uint32_t    bloom_sz_{0};
  uint32_t    bloom_shift_{0};

  bool        use_rela_{false};
  bool        use_gnu_hash_{false};

  DISALLOW_COPY_AND_ASSIGN(ElfInterface);
};

}  // namespace
