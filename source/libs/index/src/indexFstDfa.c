/*
 * Copyright (c) 2019 TAOS Data, Inc. <jhtao@taosdata.com>
 *
 * This program is free software: you can use, redistribute, and/or modify
 * it under the terms of the GNU Affero General Public License, version 3
 * or later ("AGPL"), as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "indexFstDfa.h"
#include "thash.h"

const static uint32_t STATE_LIMIT = 1000;

static int dfaInstsEqual(const void *a, const void *b, size_t size) {
  SArray *ar = (SArray *)a;
  SArray *br = (SArray *)b;
  size_t  al = ar != NULL ? taosArrayGetSize(ar) : 0;
  size_t  bl = br != NULL ? taosArrayGetSize(br) : 0;
  if (al != bl) {
    return -1;
  }
  for (int i = 0; i < al; i++) {
    uint32_t v1 = *(uint32_t *)taosArrayGet(ar, i);
    uint32_t v2 = *(uint32_t *)taosArrayGet(br, i);
    if (v1 != v2) {
      return -1;
    }
  }
  return 0;
}
FstDfaBuilder *dfaBuilderCreate(SArray *insts) {
  FstDfaBuilder *builder = taosMemoryCalloc(1, sizeof(FstDfaBuilder));
  if (builder == NULL) {
    return NULL;
  }

  SArray *states = taosArrayInit(4, sizeof(State));

  builder->dfa = dfaCreate(insts, states);
  builder->cache = taosHashInit(
      4, taosGetDefaultHashFunction(POINTER_BYTES == sizeof(int64_t) ? TSDB_DATA_TYPE_BIGINT : TSDB_DATA_TYPE_INT),
      false, HASH_NO_LOCK);
  taosHashSetEqualFp(builder->cache, dfaInstsEqual);
  return builder;
}
void dfaBuilderDestroy(FstDfaBuilder *builder) {
  if (builder == NULL) {
    return;
  }
  void *pIter = builder->cache != NULL ? taosHashIterate(builder->cache, NULL) : NULL;
  while (pIter) {
    SArray **key = pIter;
    taosArrayDestroy(*key);
    pIter = taosHashIterate(builder->cache, pIter);
  }
  taosHashCleanup(builder->cache);
}

FstDfa *dfaBuilderBuild(FstDfaBuilder *builder) {
  uint32_t      sz = taosArrayGetSize(builder->dfa->insts);
  FstSparseSet *cur = sparSetCreate(sz);
  FstSparseSet *nxt = sparSetCreate(sz);

  dfaAdd(builder->dfa, cur, 0);

  SArray * states = taosArrayInit(0, sizeof(uint32_t));
  uint32_t result;
  if (dfaBuilderCachedState(builder, cur, &result)) {
    taosArrayPush(states, &result);
  }
  SHashObj *seen = taosHashInit(12, taosGetDefaultHashFunction(TSDB_DATA_TYPE_INT), false, HASH_NO_LOCK);
  while (taosArrayGetSize(states) != 0) {
    result = *(uint32_t *)taosArrayPop(states);
    for (int i = 0; i < 256; i++) {
      uint32_t ns, dummpy = 0;
      if (dfaBuilderRunState(builder, cur, nxt, result, i, &ns)) {
        if (taosHashGet(seen, &ns, sizeof(ns)) == NULL) {
          taosHashPut(seen, &ns, sizeof(ns), &dummpy, sizeof(dummpy));
          taosArrayPush(states, &ns);
        }
      }
      if (taosArrayGetSize(builder->dfa->states) > STATE_LIMIT) {
        // Too many state;
        //
      }
    }
  }
  taosArrayDestroy(states);
  taosHashCleanup(seen);
  return builder->dfa;
}

bool dfaBuilderRunState(FstDfaBuilder *builder, FstSparseSet *cur, FstSparseSet *next, uint32_t state, uint8_t byte,
                        uint32_t *result) {
  sparSetClear(cur);
  State *t = taosArrayGet(builder->dfa->states, state);
  for (int i = 0; i < taosArrayGetSize(t->insts); i++) {
    uint32_t ip = *(int32_t *)taosArrayGet(t->insts, i);
    sparSetAdd(cur, ip);
  }
  dfaRun(builder->dfa, cur, next, byte);

  t = taosArrayGet(builder->dfa->states, state);

  uint32_t nxtState;
  if (dfaBuilderCachedState(builder, next, &nxtState)) {
    t->next[byte] = nxtState;
    *result = nxtState;
    return true;
  }
  return false;
}

bool dfaBuilderCachedState(FstDfaBuilder *builder, FstSparseSet *set, uint32_t *result) {
  // impl cache state
  return true;
}

FstDfa *dfaCreate(SArray *insts, SArray *states) {
  FstDfa *dfa = taosMemoryCalloc(1, sizeof(FstDfa));
  if (dfa == NULL) {
    return NULL;
  }

  dfa->insts = insts;
  dfa->states = states;
  return dfa;
}
bool dfaIsMatch(FstDfa *dfa, uint32_t si) {
  // impl match
  return true;
}
bool dfaAccept(FstDfa *dfa, uint32_t si, uint8_t byte, uint32_t *result) {
  // impl accept
  return true;
}
void dfaAdd(FstDfa *dfa, FstSparseSet *set, uint32_t ip) {
  // impl add
  return;
}
bool dfaRun(FstDfa *dfa, FstSparseSet *from, FstSparseSet *to, uint8_t byte) {
  // impl run
  return true;
}
