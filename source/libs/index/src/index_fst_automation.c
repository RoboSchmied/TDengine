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

#include "index_fst_automation.h"


StartWithStateValue *startWithStateValueCreate(StartWithStateKind kind, ValueType ty, void *val) {
  StartWithStateValue *nsv = calloc(1, sizeof(StartWithStateValue));
  if (nsv == NULL) { return NULL; }

  nsv->kind = kind;
  nsv->type = ty;
  if (ty == FST_INT) {
    nsv->val = *(int *)val;
  } else if (ty == FST_CHAR) {
    size_t len = strlen((char *)val);  
    nsv->ptr = (char *)calloc(1, len + 1);  
    memcpy(nsv->ptr, val, len);
  } else if (ty == FST_ARRAY) {
    //TODO, 
    //nsv->arr = taosArrayFromList() 
  }
  return nsv;
}
void startWithStateValueDestroy(StartWithStateValue *sv) {
  if (sv == NULL) { return; }

  if (sv->type == FST_INT) {
    //  
  } else if (sv->type == FST_CHAR) {
    free(sv->ptr);
  } else if (sv->type == FST_ARRAY) {
    taosArrayDestroy(sv->arr);
  }
  free(sv); 
}
StartWithStateValue *startWithStateValueDump(StartWithStateValue *sv) {
  StartWithStateValue *nsv = calloc(1, sizeof(StartWithStateValue));
  if (nsv == NULL) { return NULL; }

  nsv->kind = sv->kind;
  nsv->type= sv->type;
  if (nsv->type == FST_INT) {
    nsv->val = sv->val;
  } else if (nsv->type == FST_CHAR) {
    size_t len = strlen(sv->ptr);
    nsv->ptr = (char *)calloc(1, len + 1);
    memcpy(nsv->ptr, sv->ptr, len);
  } else if (nsv->type == FST_ARRAY) {
  }
  return nsv;
}


// prefix query, impl later

static void* prefixStart(AutomationCtx *ctx) {  
  StartWithStateValue *data = (StartWithStateValue *)(ctx->data);
  
  return data;
};
static bool prefixIsMatch(AutomationCtx *ctx, void *data) {
  return true;
} 
static bool prefixCanMatch(AutomationCtx *ctx, void *data) {
  return true;
}
static bool prefixWillAlwaysMatch(AutomationCtx *ctx, void *state) {
  return true;
}
static void* prefixAccept(AutomationCtx *ctx, void *state, uint8_t byte) {
  return NULL;
}
static void* prefixAcceptEof(AutomationCtx *ctx, void *state) {
  return NULL;
}

// pattern query, impl later

static void* patternStart(AutomationCtx *ctx) {
  return NULL;
}
static bool patternIsMatch(AutomationCtx *ctx, void *data) {
  return true;
} 
static bool patternCanMatch(AutomationCtx *ctx, void *data) {
  return true;
} 
static bool patternWillAlwaysMatch(AutomationCtx *ctx, void *state) {
  return true;
}

static void* patternAccept(AutomationCtx *ctx, void *state, uint8_t byte) {
  return NULL;
}

static void* patternAcceptEof(AutomationCtx *ctx, void *state) {
  return NULL;
}

AutomationFunc automFuncs[]  = {{
    prefixStart,        
    prefixIsMatch, 
    prefixCanMatch,
    prefixWillAlwaysMatch,
    prefixAccept,
    prefixAcceptEof
  },  
  {
    patternStart,
    patternIsMatch,
    patternCanMatch,
    patternWillAlwaysMatch,
    patternAccept,
    patternAcceptEof
  }
  // add more search type
};

AutomationCtx* automCtxCreate(void *data, AutomationType type) {
  AutomationCtx *ctx = calloc(1, sizeof(AutomationCtx));
  if (ctx == NULL) { return NULL; }

  if (type == AUTOMATION_PREFIX) {
    StartWithStateValue *swsv = (StartWithStateValue *)calloc(1, sizeof(StartWithStateValue));   
    swsv->kind  = Done; 
    //swsv->value = NULL; 
    ctx->data = (void *)swsv;
  } else if (type == AUTMMATION_MATCH) {
      
  } else {
    // add more search type
  }

  ctx->type = type;
  return ctx; 
} 
void automCtxDestroy(AutomationCtx *ctx) {
  if (ctx->type == AUTOMATION_PREFIX) {
    free(ctx->data);
  } else if (ctx->type == AUTMMATION_MATCH) {
  }
  free(ctx);
}
