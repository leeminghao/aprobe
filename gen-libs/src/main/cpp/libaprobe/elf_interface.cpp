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
#include "elf_interface.h"

#include <errno.h>
#include <string.h>
#include <sys/mman.h>

#include <aprobe/err.h>

#if defined(__arm__)
#define ELF_R_GENERIC_JUMP_SLOT R_ARM_JUMP_SLOT      //.rel.plt
#define ELF_R_GENERIC_GLOB_DAT  R_ARM_GLOB_DAT       //.rel.dyn
#define ELF_R_GENERIC_ABS       R_ARM_ABS32          //.rel.dyn
#elif defined(__aarch64__)
#define ELF_R_GENERIC_JUMP_SLOT R_AARCH64_JUMP_SLOT
#define ELF_R_GENERIC_GLOB_DAT  R_AARCH64_GLOB_DAT
#define ELF_R_GENERIC_ABS       R_AARCH64_ABS64
#elif defined(__i386__)
#define ELF_R_GENERIC_JUMP_SLOT R_386_JMP_SLOT
#define ELF_R_GENERIC_GLOB_DAT  R_386_GLOB_DAT
#define ELF_R_GENERIC_ABS       R_386_32
#elif defined(__x86_64__)
#define ELF_R_GENERIC_JUMP_SLOT R_X86_64_JUMP_SLOT
#define ELF_R_GENERIC_GLOB_DAT  R_X86_64_GLOB_DAT
#define ELF_R_GENERIC_ABS       R_X86_64_64
#endif

#if defined(__LP64__)
#define ELF_R_SYM(info)  ELF64_R_SYM(info)
#define ELF_R_TYPE(info) ELF64_R_TYPE(info)
#else
#define ELF_R_SYM(info)  ELF32_R_SYM(info)
#define ELF_R_TYPE(info) ELF32_R_TYPE(info)
#endif

#define PAGE_START(addr) ((addr) & PAGE_MASK)
#define PAGE_END(addr)   (PAGE_START(addr + sizeof(uintptr_t) - 1) + PAGE_SIZE)
#define PAGE_COVER(addr) (PAGE_END(addr) - PAGE_START(addr))

namespace aprobe {

ElfInterface::ElfInterface(const std::string& pathname, uint64_t base_addr)
    : pathname_(pathname) {
  base_addr_ = (ElfW(Addr))base_addr;
}

ElfInterface::~ElfInterface() {
}

int ElfInterface::Init() {
  ehdr_ = (ElfW(Ehdr) *)base_addr_;
  // segmentation fault sometimes
  phdr_ = (ElfW(Phdr) *)(base_addr_ + ehdr_->e_phoff);

  // find the first load-segment with offset 0
  ElfW(Phdr) *phdr0 = GetProgramSegment(PT_LOAD, 0);
  if (NULL == phdr0) {
    LOGE("Can NOT found the first load segment. %s", pathname_.c_str());
    return ERR_BAD_ELF;
  }

  // save load bias addr
  if (base_addr_ < phdr0->p_vaddr) {
    return ERR_BAD_ELF;
  }
  bias_addr_ = base_addr_ - phdr0->p_vaddr;

  // find dynamic-segment
  ElfW(Phdr) *dhdr = GetProgramSegment(PT_DYNAMIC);
  if (NULL == dhdr) {
    LOGE("Can NOT found dynamic segment. %s", pathname_.c_str());
    return ERR_BAD_ELF;
  }

  // parse dynamic-segment
  dyn_          = (ElfW(Dyn) *)(bias_addr_ + dhdr->p_vaddr);
  dyn_sz_       = dhdr->p_memsz;
  ElfW(Dyn) *dyn     = dyn_;
  ElfW(Dyn) *dyn_end = dyn_ + (dyn_sz_ / sizeof(ElfW(Dyn)));
  uint32_t  *raw;
  for(; dyn < dyn_end; ++dyn)
  {
    switch(dyn->d_tag) //segmentation fault sometimes
    {
      case DT_NULL:
        //the end of the dynamic-section
        dyn = dyn_end;
        break;
      case DT_STRTAB:
        {
          strtab_ = (const char *)(bias_addr_ + dyn->d_un.d_ptr);
          if ((ElfW(Addr))(strtab_) < base_addr_) {
            return ERR_BAD_ELF;
          }
          break;
        }
      case DT_SYMTAB:
        {
          symtab_ = (ElfW(Sym) *)(bias_addr_ + dyn->d_un.d_ptr);
          if ((ElfW(Addr))(symtab_) < base_addr_) {
            return ERR_BAD_ELF;
          }
          break;
        }
      case DT_PLTREL:
        use_rela_ = (dyn->d_un.d_val == DT_RELA ? true : false);
        break;
      case DT_JMPREL:
        {
          relplt_ = (ElfW(Addr))(bias_addr_ + dyn->d_un.d_ptr);
          if ((ElfW(Addr))(relplt_) < base_addr_) {
            return ERR_BAD_ELF;
          }
          break;
        }
      case DT_PLTRELSZ:
        relplt_sz_ = dyn->d_un.d_val;
        break;
      case DT_REL:
      case DT_RELA:
        {
          reldyn_ = (ElfW(Addr))(bias_addr_ + dyn->d_un.d_ptr);
          if ((ElfW(Addr))(reldyn_) < base_addr_) {
            return ERR_BAD_ELF;
          }
          break;
        }
      case DT_RELSZ:
      case DT_RELASZ:
        reldyn_sz_ = dyn->d_un.d_val;
        break;
      case DT_ANDROID_REL:
      case DT_ANDROID_RELA:
        {
          relandroid_ = (ElfW(Addr))(bias_addr_ + dyn->d_un.d_ptr);
          if ((ElfW(Addr))(relandroid_) < base_addr_) {
            return ERR_BAD_ELF;
          }
          break;
        }
      case DT_ANDROID_RELSZ:
      case DT_ANDROID_RELASZ:
        relandroid_sz_ = dyn->d_un.d_val;
        break;
      case DT_HASH:
        {
          // ignore DT_HASH when ELF contains DT_GNU_HASH hash table
          if (use_gnu_hash_) continue;

          raw = (uint32_t *)(bias_addr_ + dyn->d_un.d_ptr);
          if ((ElfW(Addr))raw < base_addr_) {
            return ERR_BAD_ELF;
          }
          bucket_cnt_  = raw[0];
          chain_cnt_   = raw[1];
          bucket_      = &raw[2];
          chain_       = &(bucket_[bucket_cnt_]);
          break;
        }
      case DT_GNU_HASH:
        {
          raw = (uint32_t *)(bias_addr_ + dyn->d_un.d_ptr);
          if ((ElfW(Addr))raw < base_addr_) {
            return ERR_BAD_ELF;
          }
          bucket_cnt_  = raw[0];
          symoffset_   = raw[1];
          bloom_sz_    = raw[2];
          bloom_shift_ = raw[3];
          bloom_       = (ElfW(Addr) *)(&raw[4]);
          bucket_      = (uint32_t *)(&(bloom_[bloom_sz_]));
          chain_       = (uint32_t *)(&(bucket_[bucket_cnt_]));
          use_gnu_hash_ = true;
          break;
        }
      default:
        break;
    }
  }

  //check android rel/rela
  if (relandroid_ != 0) {
    const char *rel = (const char *)relandroid_;
    if(relandroid_sz_ < 4 ||
       rel[0] != 'A' || rel[1] != 'P' ||
       rel[2] != 'S' || rel[3] != '2') {
      LOGE("android rel/rela format error\n");
      return ERR_BAD_ELF;
    }

    relandroid_ += 4;
    relandroid_sz_ -= 4;
  }

  LOGV("init OK: %s (%s %s PLT:%u DYN:%u ANDROID:%u)\n", pathname_.c_str(),
       use_rela_ ? "RELA" : "REL",
       use_gnu_hash_ ? "GNU_HASH" : "ELF_HASH",
       relplt_sz_, reldyn_sz_, relandroid_sz_);

  return OK;
}

int ElfInterface::Hook(const std::string& symbol_name, uint64_t handler) {
  uint32_t  symidx;
  void     *rel_common;
  bool      found;
  int       r;
  uint8_t  *start, *end;

  if (pathname_.empty()) {
    return ERR_NOT_FOUND;
  }

  if (symbol_name.empty() || !handler) {
    return ERR_INVALID_ARGS;
  }

  LOGV("hooking %s in %s\n", symbol_name.c_str(), pathname_.c_str());

  // find symbol index by symbol name
  if (!LookupSymbolIndex(symbol_name, &symidx)) return OK;

  // replace for .rel(a).plt
  if (0 != relplt_) {
    start = (uint8_t*)relplt_;
    end = start + relplt_sz_;
    while (start < end) {
      rel_common = (void*)start;
      if ((r = FindAndReplaceFunc((use_rela_ ? ".rela.plt" : ".rel.plt"), 1,
                                  symbol_name, (void*)handler, nullptr,
                                  symidx, rel_common, &found))) {
        return r;
      }
      if (found) return OK;
      start += (use_rela_ ? sizeof(ElfW(Rela)) : sizeof(ElfW(Rel)));
    }
  }

  // replace for .rel(a).dyn
  if (0 != reldyn_) {
    start = (uint8_t*)reldyn_;
    end  = start + reldyn_sz_;
    while (start < end) {
      rel_common = (void*)start;
      if ((r = FindAndReplaceFunc((use_rela_ ? ".rela.dyn" : ".rel.dyn"), 0,
                                  symbol_name, (void*)handler, nullptr,
                                  symidx, rel_common, nullptr))) {
        return r;
      }
      start += (use_rela_ ? sizeof(ElfW(Rela)) : sizeof(ElfW(Rel)));
    }
  }

  return OK;
}


ElfW(Phdr) *ElfInterface::GetProgramSegment(ElfW(Word) type) {
  ElfW(Phdr) *phdr;

  for (phdr = phdr_; phdr < phdr_ + ehdr_->e_phnum; ++phdr) {
    if (phdr->p_type == type) {
      return phdr;
    }
  }
  return NULL;
}

ElfW(Phdr) *ElfInterface::GetProgramSegment(ElfW(Word) type, ElfW(Off) offset) {
  ElfW(Phdr) *phdr;

  for (phdr = phdr_; phdr < phdr_ + ehdr_->e_phnum; ++phdr) {
    if (phdr->p_type == type && phdr->p_offset == offset) {
      return phdr;
    }
  }
  return NULL;
}

bool ElfInterface::LookupSymbolIndex(const std::string& symbol_name,
                                  uint32_t *symbol_index) {
  if (use_gnu_hash_) {
    return LookupGnuHash(symbol_name, symbol_index);
  } else {
    return LookupHash(symbol_name, symbol_index);
  }
}

bool ElfInterface::LookupHash(const std::string& symbol_name,
                             uint32_t *symbol_index) {
  uint32_t    hash = ElfHash(symbol_name);
  const char *symbol_cur;

  for (uint32_t i = bucket_[hash % bucket_cnt_]; 0 != i; i = chain_[i]) {
    symbol_cur = strtab_ + symtab_[i].st_name;

    if (0 == strcmp(symbol_name.c_str(), symbol_cur)) {
      *symbol_index = i;
      LOGV("found %s at symidx: %u (ELF_HASH)\n",
           symbol_name.c_str(), *symbol_index);
      return true;
    }
  }

  return false;
}

bool ElfInterface::LookupGnuHash(const std::string& symbol_name,
                                uint32_t *symbol_index) {
  if (LookupGnuHashDef(symbol_name, symbol_index)) {
    return true;
  }
  if (LookupGnuHashUndef(symbol_name, symbol_index)) {
    return true;
  }
  return false;
}

bool ElfInterface::LookupGnuHashDef(const std::string& symbol_name,
                                   uint32_t *symbol_index) {
  static uint32_t elfclass_bits = sizeof(ElfW(Addr)) * 8;
  uint32_t hash = ElfGnuHash(symbol_name);
  size_t word = bloom_[(hash / elfclass_bits) % bloom_sz_];
  size_t mask = 0
      | (size_t)1 << (hash % elfclass_bits)
      | (size_t)1 << ((hash >> bloom_shift_) % elfclass_bits);

  //if at least one bit is not set, this symbol is surely missing
  if ((word & mask) != mask) return false;

  //ignore STN_UNDEF
  uint32_t i = bucket_[hash % bucket_cnt_];
  if (i < symoffset_) return false;

  // loop through the chain
  while (true) {
    const char     *symname = strtab_ + symtab_[i].st_name;
    const uint32_t  symhash = chain_[i - symoffset_];

    if ((hash | (uint32_t)1) == (symhash | (uint32_t)1) &&
        0 == strcmp(symbol_name.c_str(), symname)) {
      *symbol_index = i;
      LOGV("found %s at symidx: %u (GNU_HASH DEF)\n",
           symbol_name.c_str(), *symbol_index);
      return true;
    }

    // chain ends with an element with the lowest bit set to 1
    if (symhash & (uint32_t)1) break;

    i++;
  }

  return false;
}

bool ElfInterface::LookupGnuHashUndef(const std::string& symbol_name,
                                     uint32_t *symbol_index) {
  for (uint32_t i = 0; i < symoffset_; ++i) {
    const char *symname = strtab_ + symtab_[i].st_name;
    if (0 == strcmp(symname, symbol_name.c_str())) {
      *symbol_index = i;
      LOGV("found %s at symidx: %u (GNU_HASH UNDEF)\n",
           symbol_name.c_str(), *symbol_index);
      return true;
    }
  }

  return false;
}

uint32_t ElfInterface::ElfHash(const std::string& str) {
  uint32_t hash = 0, g;

  for (int i = 0; i < str.length(); ++i) {
    hash = (hash << 4) + str.at(i);
    g = hash & 0xf0000000;
    hash ^= g;
    hash ^= g >> 24;
  }

  return hash;
}

uint32_t ElfInterface::ElfGnuHash(const std::string& str) {
  uint32_t hash = 5381;

  for (int i = 0; i < str.length(); ++i) {
    hash += (hash << 5) + str.at(i);
  }

  return hash;
}

int ElfInterface::FindAndReplaceFunc(
    const std::string& section, bool is_plt,
    const std::string& symbol_name,
    void *new_func, void **old_func,
    uint32_t symbol_index, void *rel_common, bool *found) {

    ElfW(Rela)    *rela;
    ElfW(Rel)     *rel;
    ElfW(Addr)     r_offset;
    size_t         r_info;
    size_t         r_sym;
    size_t         r_type;
    ElfW(Addr)     addr;
    int            r;

    if (NULL != found) *found = false;

    if (use_rela_) {
        rela = (ElfW(Rela) *)rel_common;
        r_info = rela->r_info;
        r_offset = rela->r_offset;
    } else {
        rel = (ElfW(Rel) *)rel_common;
        r_info = rel->r_info;
        r_offset = rel->r_offset;
    }

    // check sym
    r_sym = ELF_R_SYM(r_info);
    if (r_sym != symbol_index) return OK;

    // check type
    r_type = ELF_R_TYPE(r_info);
    if (is_plt && r_type != ELF_R_GENERIC_JUMP_SLOT) return OK;
    if (!is_plt && (r_type != ELF_R_GENERIC_GLOB_DAT && r_type != ELF_R_GENERIC_ABS)) return OK;

    // we found it
    LOGV("found %s at %s offset: %p\n", symbol_name.c_str(), section.c_str(), (void *)r_offset);
    if (NULL != found) *found = true;

    // do replace
    addr = bias_addr_ + r_offset;
    if (addr < base_addr_) return ERR_BAD_ELF;
    if ((r = ReplaceFunc(symbol_name, addr, new_func, old_func))) {
      LOGE("replace function failed: %s at %s\n",
           symbol_name.c_str(), section.c_str());
      return r;
    }

    return OK;
}

int ElfInterface::ReplaceFunc(const std::string& symbol_name, ElfW(Addr) addr,
                              void *new_func, void **old_func) {
  void         *old_addr;
  unsigned int  old_prot = 0;
  unsigned int  need_prot = PROT_READ | PROT_WRITE;
  int           r;

  // already replaced?
  // here we assume that we always have read permission, is this a problem?
  if (*(void **)addr == new_func) return OK;

  // get old prot
  // TODO:

  if (old_prot != need_prot) {
    //set new prot
    if (mprotect((void *)PAGE_START(addr), PAGE_COVER(addr), (int)need_prot)) {
      LOGE("set addr prot failed: %d", errno);
      return ERR_NOT_MPROTECT;
    }
  }

  // save old func
  old_addr = *(void **)addr;
  if (NULL != old_func) *old_func = old_addr;

  // replace func
  *(void **)addr = new_func; // segmentation fault sometimes

  /*if (old_prot != need_prot) {
    //restore the old prot
    if (mprotect((void *)PAGE_START(addr), PAGE_COVER(addr), (int)old_prot)) {
      LOGW("restore addr prot failed. ret: %d", errno);
    }
    }*/

  // clear cache
  __builtin___clear_cache((char *)PAGE_START(addr), (char *)PAGE_END(addr));

  LOGV("HOOK OK %p: %p -> %p %s %s\n", (void *)addr, old_addr,
       new_func, symbol_name.c_str(), pathname_.c_str());

  return OK;
}

}  // namespace aprobe
