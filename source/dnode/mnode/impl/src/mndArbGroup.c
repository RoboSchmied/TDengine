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

#define _DEFAULT_SOURCE
#include "mndArbGroup.h"
#include "audit.h"
#include "mndDnode.h"
#include "mndPrivilege.h"
#include "mndShow.h"
#include "mndTrans.h"
#include "mndUser.h"
#include "mndVgroup.h"

#define ARBGROUP_VER_NUMBER   1
#define ARBGROUP_RESERVE_SIZE 64

static SSdbRow *mndArbGroupActionDecode(SSdbRaw *pRaw);
static int32_t  mndArbGroupActionInsert(SSdb *pSdb, SArbGroup *pGroup);
static int32_t  mndArbGroupActionUpdate(SSdb *pSdb, SArbGroup *pOld, SArbGroup *pNew);
static int32_t  mndArbGroupActionDelete(SSdb *pSdb, SArbGroup *pGroup);

static void mndArbGroupDupObj(SArbGroup *pGroup, SArbGroup *pNew);
static void mndArbGroupSetAssignedLeader(SArbGroup *pGroup, int32_t index);
static void mndArbGroupResetAssignedLeader(SArbGroup *pGroup);

static int32_t mndArbGroupUpdateTrans(SMnode *pMnode, SArbGroup *pNew);

static int32_t mndProcessArbHbTimer(SRpcMsg *pReq);
static int32_t mndProcessArbCheckSyncTimer(SRpcMsg *pReq);
static int32_t mndProcessArbHbRsp(SRpcMsg *pRsp);
static int32_t mndProcessArbCheckSyncRsp(SRpcMsg *pRsp);
static int32_t mndProcessArbSetAssignedLeaderRsp(SRpcMsg *pRsp);
static int32_t mndRetrieveArbGroups(SRpcMsg *pReq, SShowObj *pShow, SSDataBlock *pBlock, int32_t rows);
static void    mndCancelGetNextArbGroup(SMnode *pMnode, void *pIter);

static int32_t mndArbCheckToken(const char *token1, const char *token2) {
  return strncmp(token1, token2, TSDB_ARB_TOKEN_SIZE);
}

int32_t mndInitArbGroup(SMnode *pMnode) {
  SSdbTable table = {
      .sdbType = SDB_ARBGROUP,
      .keyType = SDB_KEY_INT32,
      .encodeFp = (SdbEncodeFp)mndArbGroupActionEncode,
      .decodeFp = (SdbDecodeFp)mndArbGroupActionDecode,
      .insertFp = (SdbInsertFp)mndArbGroupActionInsert,
      .updateFp = (SdbUpdateFp)mndArbGroupActionUpdate,
      .deleteFp = (SdbDeleteFp)mndArbGroupActionDelete,
  };

  mndSetMsgHandle(pMnode, TDMT_MND_ARB_HEARTBEAT_TIMER, mndProcessArbHbTimer);
  mndSetMsgHandle(pMnode, TDMT_MND_ARB_CHECK_SYNC_TIMER, mndProcessArbCheckSyncTimer);
  mndSetMsgHandle(pMnode, TDMT_VND_ARB_HEARTBEAT_RSP, mndProcessArbHbRsp);
  mndSetMsgHandle(pMnode, TDMT_VND_ARB_CHECK_SYNC_RSP, mndProcessArbCheckSyncRsp);
  mndSetMsgHandle(pMnode, TDMT_SYNC_SET_ASSIGNED_LEADER_RSP, mndProcessArbSetAssignedLeaderRsp);

  mndAddShowRetrieveHandle(pMnode, TSDB_MGMT_TABLE_ARBGROUP, mndRetrieveArbGroups);
  mndAddShowFreeIterHandle(pMnode, TSDB_MGMT_TABLE_ARBGROUP, mndCancelGetNextArbGroup);

  return sdbSetTable(pMnode->pSdb, table);
}

void mndCleanupArbGroup(SMnode *pMnode) {}

SArbGroup *mndAcquireArbGroup(SMnode *pMnode, int32_t groupId) {
  SArbGroup *pGroup = sdbAcquire(pMnode->pSdb, SDB_ARBGROUP, &groupId);
  if (pGroup == NULL && terrno == TSDB_CODE_SDB_OBJ_NOT_THERE) {
    terrno = TSDB_CODE_MND_ARBGROUP_NOT_EXIST;
  }
  return pGroup;
}

void mndReleaseArbGroup(SMnode *pMnode, SArbGroup *pGroup) {
  SSdb *pSdb = pMnode->pSdb;
  sdbRelease(pSdb, pGroup);
}

void mndArbGroupInitFromVgObj(SVgObj *pVgObj, SArbGroup *outGroup) {
  ASSERT(pVgObj->replica == 2);
  memset(outGroup, 0, sizeof(SArbGroup));
  outGroup->dbUid = pVgObj->dbUid;
  outGroup->groupId = pVgObj->vgId;
  for (int i = 0; i < 2; i++) {
    SArbGroupMember *pMember = &outGroup->members[i];
    pMember->info.dnodeId = pVgObj->vnodeGid[i].dnodeId;
  }
}

SSdbRaw *mndArbGroupActionEncode(SArbGroup *pGroup) {
  terrno = TSDB_CODE_OUT_OF_MEMORY;

  int32_t  size = sizeof(SArbGroup) + ARBGROUP_RESERVE_SIZE;
  SSdbRaw *pRaw = sdbAllocRaw(SDB_ARBGROUP, ARBGROUP_VER_NUMBER, size);
  if (pRaw == NULL) goto _OVER;

  int32_t dataPos = 0;
  SDB_SET_INT32(pRaw, dataPos, pGroup->groupId, _OVER)
  SDB_SET_INT64(pRaw, dataPos, pGroup->dbUid, _OVER)
  for (int i = 0; i < 2; i++) {
    SArbGroupMember *pMember = &pGroup->members[i];
    SDB_SET_INT32(pRaw, dataPos, pMember->info.dnodeId, _OVER)
    SDB_SET_BINARY(pRaw, dataPos, pMember->state.token, TSDB_ARB_TOKEN_SIZE, _OVER)
  }
  SDB_SET_INT8(pRaw, dataPos, pGroup->isSync, _OVER)

  SArbAssignedLeader *pLeader = &pGroup->assignedLeader;
  SDB_SET_INT32(pRaw, dataPos, pLeader->dnodeId, _OVER)
  SDB_SET_BINARY(pRaw, dataPos, pLeader->token, TSDB_ARB_TOKEN_SIZE, _OVER)

  SDB_SET_RESERVE(pRaw, dataPos, ARBGROUP_RESERVE_SIZE, _OVER)

  terrno = 0;

_OVER:
  if (terrno != 0) {
    mError("arbgroup:%d, failed to encode to raw:%p since %s", pGroup->groupId, pRaw, terrstr());
    sdbFreeRaw(pRaw);
    return NULL;
  }

  mTrace("arbgroup:%d, encode to raw:%p, row:%p", pGroup->groupId, pRaw, pGroup);
  return pRaw;
}

static SSdbRow *mndArbGroupActionDecode(SSdbRaw *pRaw) {
  terrno = TSDB_CODE_OUT_OF_MEMORY;
  SSdbRow   *pRow = NULL;
  SArbGroup *pGroup = NULL;

  int8_t sver = 0;
  if (sdbGetRawSoftVer(pRaw, &sver) != 0) goto _OVER;

  if (sver != ARBGROUP_VER_NUMBER) {
    terrno = TSDB_CODE_SDB_INVALID_DATA_VER;
    goto _OVER;
  }

  pRow = sdbAllocRow(sizeof(SArbGroup));
  if (pRow == NULL) goto _OVER;

  pGroup = sdbGetRowObj(pRow);
  if (pGroup == NULL) goto _OVER;

  int32_t dataPos = 0;
  SDB_GET_INT32(pRaw, dataPos, &pGroup->groupId, _OVER)
  SDB_GET_INT64(pRaw, dataPos, &pGroup->dbUid, _OVER)
  for (int i = 0; i < 2; i++) {
    SArbGroupMember *pMember = &pGroup->members[i];
    SDB_GET_INT32(pRaw, dataPos, &pMember->info.dnodeId, _OVER)
    SDB_GET_BINARY(pRaw, dataPos, pMember->state.token, TSDB_ARB_TOKEN_SIZE, _OVER)

    pMember->state.nextHbSeq = 0;
    pMember->state.responsedHbSeq = -1;
    pMember->state.lastHbMs = 0;
  }
  SDB_GET_INT8(pRaw, dataPos, &pGroup->isSync, _OVER)

  SArbAssignedLeader *pLeader = &pGroup->assignedLeader;
  SDB_GET_INT32(pRaw, dataPos, &pLeader->dnodeId, _OVER)
  SDB_GET_BINARY(pRaw, dataPos, pLeader->token, TSDB_ARB_TOKEN_SIZE, _OVER)

  SDB_GET_RESERVE(pRaw, dataPos, ARBGROUP_RESERVE_SIZE, _OVER)

  terrno = 0;

_OVER:
  if (terrno != 0) {
    mError("arbgroup:%d, failed to decode from raw:%p since %s", pGroup == NULL ? 0 : pGroup->groupId, pRaw, terrstr());
    taosMemoryFreeClear(pRow);
    return NULL;
  }

  mTrace("arbgroup:%d, decode from raw:%p, row:%p", pGroup->groupId, pRaw, pGroup);
  return pRow;
}

static int32_t mndArbGroupActionInsert(SSdb *pSdb, SArbGroup *pGroup) {
  mTrace("arbgroup:%d, perform insert action, row:%p", pGroup->groupId, pGroup);
  return 0;
}

static int32_t mndArbGroupActionDelete(SSdb *pSdb, SArbGroup *pGroup) {
  mTrace("arbgroup:%d, perform delete action, row:%p", pGroup->groupId, pGroup);
  return 0;
}

static int32_t mndArbGroupActionUpdate(SSdb *pSdb, SArbGroup *pOld, SArbGroup *pNew) {
  mTrace("arbgroup:%d, perform update action, old row:%p new row:%p", pOld->groupId, pOld, pNew);
  for (int i = 0; i < 2; i++) {
    memcpy(pOld->members[i].state.token, pNew->members[i].state.token, TSDB_ARB_TOKEN_SIZE);
  }
  pOld->isSync = pNew->isSync;
  pOld->assignedLeader.dnodeId = pNew->assignedLeader.dnodeId;
  memcpy(pOld->assignedLeader.token, pNew->assignedLeader.token, TSDB_ARB_TOKEN_SIZE);
  return 0;
}

int32_t mndSetCreateArbGroupRedoLogs(STrans *pTrans, SArbGroup *pGroup) {
  SSdbRaw *pRedoRaw = mndArbGroupActionEncode(pGroup);
  if (pRedoRaw == NULL) return -1;
  if (mndTransAppendRedolog(pTrans, pRedoRaw) != 0) return -1;
  if (sdbSetRawStatus(pRedoRaw, SDB_STATUS_CREATING) != 0) return -1;
  return 0;
}

int32_t mndSetCreateArbGroupUndoLogs(STrans *pTrans, SArbGroup *pGroup) {
  SSdbRaw *pUndoRaw = mndArbGroupActionEncode(pGroup);
  if (pUndoRaw == NULL) return -1;
  if (mndTransAppendUndolog(pTrans, pUndoRaw) != 0) return -1;
  if (sdbSetRawStatus(pUndoRaw, SDB_STATUS_DROPPED) != 0) return -1;
  return 0;
}

int32_t mndSetCreateArbGroupCommitLogs(STrans *pTrans, SArbGroup *pGroup) {
  SSdbRaw *pCommitRaw = mndArbGroupActionEncode(pGroup);
  if (pCommitRaw == NULL) return -1;
  if (mndTransAppendCommitlog(pTrans, pCommitRaw) != 0) return -1;
  if (sdbSetRawStatus(pCommitRaw, SDB_STATUS_READY) != 0) return -1;
  return 0;
}

static int32_t mndSetDropArbGroupRedoLogs(STrans *pTrans, SArbGroup *pGroup) {
  SSdbRaw *pRedoRaw = mndArbGroupActionEncode(pGroup);
  if (pRedoRaw == NULL) return -1;
  if (mndTransAppendRedolog(pTrans, pRedoRaw) != 0) return -1;
  if (sdbSetRawStatus(pRedoRaw, SDB_STATUS_DROPPING) != 0) return -1;
  return 0;
}

int32_t mndSetDropArbGroupCommitLogs(STrans *pTrans, SArbGroup *pGroup) {
  SSdbRaw *pCommitRaw = mndArbGroupActionEncode(pGroup);
  if (pCommitRaw == NULL) return -1;
  if (mndTransAppendCommitlog(pTrans, pCommitRaw) != 0) return -1;
  if (sdbSetRawStatus(pCommitRaw, SDB_STATUS_DROPPED) != 0) return -1;
  return 0;
}

static void *mndBuildArbHeartBeatReq(int32_t *pContLen, char *arbToken, int32_t dnodeId, SArray *hbMembers) {
  SVArbHeartBeatReq req = {0};
  req.dnodeId = dnodeId;
  req.arbToken = arbToken;
  req.hbMembers = hbMembers;

  int32_t contLen = tSerializeSVArbHeartBeatReq(NULL, 0, &req);
  if (contLen <= 0) return NULL;
  void *pReq = rpcMallocCont(contLen);
  if (pReq == NULL) return NULL;

  tSerializeSVArbHeartBeatReq(pReq, contLen, &req);
  *pContLen = contLen;
  return pReq;
}

static void mndSendArbHeartBeatReq(SDnodeObj *pDnode, char *arbToken, SArray *hbMembers) {
  int32_t contLen = 0;
  void   *pHead = mndBuildArbHeartBeatReq(&contLen, arbToken, pDnode->id, hbMembers);
  SRpcMsg rpcMsg = {.msgType = TDMT_VND_ARB_HEARTBEAT, .pCont = pHead, .contLen = contLen};

  SEpSet  epSet = mndGetDnodeEpset(pDnode);
  int32_t code = tmsgSendReq(&epSet, &rpcMsg);
  if (code != 0) {
    mError("dnodeId:%d, failed to send arb-hb request to dnode since 0x%x", pDnode->id, code);
  } else {
    mTrace("dnodeId:%d, send arb-hb request to dnode", pDnode->id);
  }
}

static int32_t mndProcessArbHbTimer(SRpcMsg *pReq) {
  SMnode    *pMnode = pReq->info.node;
  SSdb      *pSdb = pMnode->pSdb;
  SArbGroup *pArbGroup = NULL;
  void      *pIter = NULL;

  SHashObj *pDnodeHash = taosHashInit(64, taosGetDefaultHashFunction(TSDB_DATA_TYPE_INT), false, HASH_NO_LOCK);

  // collect member of same dnode
  while (1) {
    pIter = sdbFetch(pSdb, SDB_ARBGROUP, pIter, (void **)&pArbGroup);
    if (pIter == NULL) break;

    for (int i = 0; i < 2; i++) {
      SArbGroupMember *pMember = &pArbGroup->members[i];
      int32_t          dnodeId = pMember->info.dnodeId;
      void            *pObj = taosHashGet(pDnodeHash, &dnodeId, sizeof(int32_t));
      SArray          *hbMembers = NULL;
      if (pObj) {
        hbMembers = *(SArray **)pObj;
      } else {
        hbMembers = taosArrayInit(16, sizeof(SVArbHbReqMember));
        taosHashPut(pDnodeHash, &dnodeId, sizeof(int32_t), &hbMembers, POINTER_BYTES);
      }
      SVArbHbReqMember reqMember = {.groupId = pArbGroup->groupId, .hbSeq = pMember->state.nextHbSeq++};
      taosArrayPush(hbMembers, &reqMember);
    }
    sdbRelease(pSdb, pArbGroup);
  }

  char arbToken[TSDB_ARB_TOKEN_SIZE];
  mndGetArbToken(pMnode, arbToken);

  pIter = NULL;
  while (1) {
    pIter = taosHashIterate(pDnodeHash, pIter);
    if (pIter == NULL) break;

    int32_t dnodeId = *(int32_t *)taosHashGetKey(pIter, NULL);
    SArray *hbMembers = *(SArray **)pIter;

    SDnodeObj *pDnode = mndAcquireDnode(pMnode, dnodeId);
    if (pDnode == NULL) {
      mError("dnodeId:%d, timer failed to send arb-hb request, failed find dnode", dnodeId);
      taosArrayDestroy(hbMembers);
      continue;
    }

    mndSendArbHeartBeatReq(pDnode, arbToken, hbMembers);

    mndReleaseDnode(pMnode, pDnode);
    taosArrayDestroy(hbMembers);
  }
  taosHashCleanup(pDnodeHash);

  return 0;
}

static void *mndBuildArbCheckSyncReq(int32_t *pContLen, int32_t groupId, char *arbToken, char *member0Token,
                                     char *member1Token) {
  SVArbCheckSyncReq req = {0};
  req.arbToken = arbToken;
  req.member0Token = member0Token;
  req.member1Token = member1Token;

  int32_t reqLen = tSerializeSVArbCheckSyncReq(NULL, 0, &req);
  int32_t contLen = reqLen + sizeof(SMsgHead);

  if (contLen <= 0) return NULL;
  SMsgHead *pHead = rpcMallocCont(contLen);
  if (pHead == NULL) return NULL;

  pHead->contLen = htonl(contLen);
  pHead->vgId = htonl(groupId);
  tSerializeSVArbCheckSyncReq((char*)pHead + sizeof(SMsgHead), contLen, &req);
  *pContLen = contLen;
  return pHead;
}

static void mndSendArbCheckSyncReq(SMnode *pMnode, int32_t groupId, char *arbToken, char *member0Token,
                                   char *member1Token) {
  int32_t contLen = 0;
  void   *pHead = mndBuildArbCheckSyncReq(&contLen, groupId, arbToken, member0Token, member1Token);
  SRpcMsg rpcMsg = {.msgType = TDMT_VND_ARB_CHECK_SYNC, .pCont = pHead, .contLen = contLen};

  SEpSet  epSet = mndGetVgroupEpsetById(pMnode, groupId);
  if (epSet.numOfEps == 0) {
    mError("groupId:%d, failed to send check-sync request since no epSet found", groupId);
    return;
  }

  int32_t code = tmsgSendReq(&epSet, &rpcMsg);
  if (code != 0) {
    mError("groupId:%d, failed to send check-sync request since 0x%x", groupId, code);
  } else {
    mDebug("groupId:%d, send check-sync request", groupId);
  }
}

static bool mndCheckArbMemberHbTimeout(SArbGroup *pArbGroup, int32_t index, int64_t nowMs) {
  SArbGroupMember *pArbMember = &pArbGroup->members[index];
  return pArbMember->state.lastHbMs < (nowMs - ARBITRATOR_TIMEOUT_SEC * 1000);
}

static void *mndBuildArbSetAssignedLeaderReq(int32_t *pContLen, int32_t groupId, char *arbToken, char *memberToken) {
  SVArbSetAssignedLeaderReq req = {0};
  req.arbToken = arbToken;
  req.memberToken = memberToken;

  int32_t reqLen = tSerializeSVArbSetAssignedLeaderReq(NULL, 0, &req);
  int32_t contLen = reqLen + sizeof(SMsgHead);

  if (contLen <= 0) return NULL;
  SMsgHead *pHead = rpcMallocCont(contLen);
  if (pHead == NULL) return NULL;

  pHead->contLen = htonl(contLen);
  pHead->vgId = htonl(groupId);
  tSerializeSVArbSetAssignedLeaderReq((char *)pHead + sizeof(SMsgHead), contLen, &req);
  *pContLen = contLen;
  return pHead;
}

static void mndSendArbSetAssignedLeaderReq(SMnode *pMnode, int32_t dnodeId, int32_t groupId, char *arbToken,
                                           char *memberToken) {
  int32_t contLen = 0;
  void   *pHead = mndBuildArbSetAssignedLeaderReq(&contLen, groupId, arbToken, memberToken);
  SRpcMsg rpcMsg = {.msgType = TDMT_SYNC_SET_ASSIGNED_LEADER, .pCont = pHead, .contLen = contLen};

  SEpSet epSet = mndGetDnodeEpsetById(pMnode, dnodeId);
  if (epSet.numOfEps == 0) {
    mError("dnodeId:%d vgId:%d, failed to send arb-set-assigned request to dnode since no epSet found", dnodeId,
           groupId);
    return;
  }
  int32_t code = tmsgSendReq(&epSet, &rpcMsg);
  if (code != 0) {
    mError("dnodeId:%d vgId:%d, failed to send arb-set-assigned request to dnode since 0x%x", dnodeId, groupId, code);
  } else {
    mInfo("dnodeId:%d vgId:%d, send arb-set-assigned request to dnode", dnodeId, groupId);
  }
}

static int32_t mndProcessArbCheckSyncTimer(SRpcMsg *pReq) {
  SMnode    *pMnode = pReq->info.node;
  SSdb      *pSdb = pMnode->pSdb;
  SArbGroup *pArbGroup = NULL;
  void      *pIter = NULL;

  char arbToken[TSDB_ARB_TOKEN_SIZE];
  mndGetArbToken(pMnode, arbToken);

  while (1) {
    pIter = sdbFetch(pSdb, SDB_ARBGROUP, pIter, (void **)&pArbGroup);
    if (pIter == NULL) break;

    int32_t groupId = pArbGroup->groupId;
    int64_t nowMs = taosGetTimestampMs();

    bool member0IsTimeout = mndCheckArbMemberHbTimeout(pArbGroup, 0, nowMs);
    bool member1IsTimeout = mndCheckArbMemberHbTimeout(pArbGroup, 1, nowMs);
    int32_t currentAssignedDnodeId = pArbGroup->assignedLeader.dnodeId;

    // 1. both of the two members are timeout => skip
    if (member0IsTimeout && member1IsTimeout) {
      sdbRelease(pSdb, pArbGroup);
      continue;
    }

    // 2. no member is timeout => check sync
    if (member0IsTimeout == false && member1IsTimeout == false) {
      // no assigned leader and not sync
      if (currentAssignedDnodeId == 0 && !pArbGroup->isSync) {
        mndSendArbCheckSyncReq(pMnode, pArbGroup->groupId, arbToken, pArbGroup->members[0].state.token,
                               pArbGroup->members[1].state.token);
      }
      sdbRelease(pSdb, pArbGroup);
      continue;
    }

    // 3. one of the members is timeout => set assigned leader
    int32_t candidateIndex = member0IsTimeout ? 1 : 0;
    SArbGroupMember* pMember = &pArbGroup->members[candidateIndex];

    // has assigned leader and dnodeId not match => skip
    if (currentAssignedDnodeId != 0 && currentAssignedDnodeId != pMember->info.dnodeId) {
      mInfo("arb skip to set assigned leader to vgId:%d dnodeId:%d, assigned leader has been set to dnodeId:%d",
            groupId, pMember->info.dnodeId, currentAssignedDnodeId);
      sdbRelease(pSdb, pArbGroup);
      continue;
    }

    // not sync => skip
    if (pArbGroup->isSync == false) {
      mInfo("arb skip to set assigned leader to vgId:%d dnodeId:%d, arb group is not sync", groupId,
            pMember->info.dnodeId);
      sdbRelease(pSdb, pArbGroup);
      continue;
    }

    // no assigned leader => write to sdb
    if (currentAssignedDnodeId == 0) {
      SArbGroup newGroup = {0};
      mndArbGroupDupObj(pArbGroup, &newGroup);
      mndArbGroupSetAssignedLeader(&newGroup, candidateIndex);
      mndArbGroupUpdateTrans(pMnode, &newGroup);
    }

    mndSendArbSetAssignedLeaderReq(pMnode, pMember->info.dnodeId, groupId, arbToken, pMember->state.token);

    sdbRelease(pSdb, pArbGroup);
  }

  return 0;
}

static void mndArbGroupDupObj(SArbGroup *pGroup, SArbGroup *pNew) { memcpy(pNew, pGroup, sizeof(SArbGroup)); }

static void mndArbGroupSetAssignedLeader(SArbGroup *pGroup, int32_t index) {
  SArbGroupMember *pMember = &pGroup->members[index];

  pGroup->assignedLeader.dnodeId = pMember->info.dnodeId;
  strncpy(pGroup->assignedLeader.token, pMember->state.token, TSDB_ARB_TOKEN_SIZE);
}

static void mndArbGroupResetAssignedLeader(SArbGroup *pGroup) {
  pGroup->assignedLeader.dnodeId = 0;
  memset(pGroup->assignedLeader.token, 0, TSDB_ARB_TOKEN_SIZE);
}

static int32_t mndArbGroupUpdateTrans(SMnode *pMnode, SArbGroup *pNew) {
  int32_t ret = -1;
  STrans *pTrans = mndTransCreate(pMnode, TRN_POLICY_ROLLBACK, TRN_CONFLICT_ARBGROUP, NULL, "update-arbgroup");
  if (pTrans == NULL) {
    mError("failed to update arbgroup in create trans, vgId:%d, since %s", pNew->groupId, terrstr());
    goto _OVER;
  }

  mInfo("trans:%d, used to update arbgroup:%d, member0:[%d][%s] member1:[%d][%s] isSync:%d assigned:[%d][%s]",
        pTrans->id, pNew->groupId, pNew->members[0].info.dnodeId, pNew->members[0].state.token,
        pNew->members[1].info.dnodeId, pNew->members[1].state.token, pNew->isSync, pNew->assignedLeader.dnodeId,
        pNew->assignedLeader.token);

  mndTransSetArbGroupId(pTrans, pNew->groupId);
  if (mndTransCheckConflict(pMnode, pTrans) != 0) {
    mndTransDrop(pTrans);
    ret = 0;
    goto _OVER;
  }

  if (mndSetCreateArbGroupCommitLogs(pTrans, pNew) != 0) {
    mndTransDrop(pTrans);
    mError("failed to update arbgroup in set commit log, vgId:%d, since %s", pNew->groupId, terrstr());
    goto _OVER;
  }

  if (mndTransPrepare(pMnode, pTrans) != 0) goto _OVER;

  ret = 0;

_OVER:
  mndTransDrop(pTrans);
  return ret;
}

static void mndUpdateArbHeartBeat(SMnode *pMnode, int32_t dnodeId, SArray *memberArray) {
  int64_t nowMs = taosGetTimestampMs();

  size_t size = taosArrayGetSize(memberArray);
  for (size_t i = 0; i < size; i++) {
    SVArbHbRspMember *pRspMember = taosArrayGet(memberArray, i);

    SArbGroup       *pGroup = sdbAcquire(pMnode->pSdb, SDB_ARBGROUP, &pRspMember->groupId);
    SArbGroupMember *pMember = NULL;

    int index = 0;
    for (; index < 2; index++) {
      pMember = &pGroup->members[index];
      if (pMember->info.dnodeId == dnodeId) {
        break;
      }
      pMember = NULL;
    }

    if (pMember == NULL) {
      sdbRelease(pMnode->pSdb, pGroup);
      mInfo("dnodeId:%d vgId:%d, arb token update check failed, no obj found", dnodeId, pRspMember->groupId);
      continue;
    }

    if (pMember->state.responsedHbSeq >= pRspMember->hbSeq) {
      // skip
      sdbRelease(pMnode->pSdb, pGroup);
      mInfo("dnodeId:%d vgId:%d, skip arb token update, heart beat seq expired, local:%d msg:%d", dnodeId,
            pRspMember->groupId, pMember->state.responsedHbSeq, pRspMember->hbSeq);
      continue;
    }

    // update hb state
    pMember->state.responsedHbSeq = pRspMember->hbSeq;
    pMember->state.lastHbMs = nowMs;
    if (mndArbCheckToken(pMember->state.token, pRspMember->memberToken) == 0) {
      // skip
      sdbRelease(pMnode->pSdb, pGroup);
      mDebug("dnodeId:%d vgId:%d, skip arb token update, token matched", dnodeId, pRspMember->groupId);
      continue;
    }

    // update token
    SArbGroup newGroup = {0};
    mndArbGroupDupObj(pGroup, &newGroup);
    memcpy(newGroup.members[index].state.token, pRspMember->memberToken, TSDB_ARB_TOKEN_SIZE);
    newGroup.isSync = false;

    bool resetAssigned = false;
    if (pMember->info.dnodeId == pGroup->assignedLeader.dnodeId) {
      mndArbGroupResetAssignedLeader(&newGroup);
      resetAssigned = true;
    }

    mInfo("dnodeId:%d vgId:%d, arb token updating, resetAssigned:%d", dnodeId, pRspMember->groupId, resetAssigned);

    if (mndArbGroupUpdateTrans(pMnode, &newGroup) != 0) {
      sdbRelease(pMnode->pSdb, pGroup);
      break;
    }

    sdbRelease(pMnode->pSdb, pGroup);
  }
}

static void mndUpdateArbSync(SMnode *pMnode, int32_t groupId, char *member0Token, char *member1Token, bool newIsSync) {
  SArbGroup *pGroup = sdbAcquire(pMnode->pSdb, SDB_ARBGROUP, &groupId);
  if (pGroup == NULL) {
    terrno = TSDB_CODE_NOT_FOUND;
    mInfo("failed to update arb sync, groupId:%d not found", groupId);
    goto _OVER;
  }

  if (pGroup->assignedLeader.dnodeId != 0) {
    terrno = TSDB_CODE_SUCCESS;
    mInfo("skip to update arb sync, groupId:%d has assigned leader:%d", groupId, pGroup->assignedLeader.dnodeId);
    goto _OVER;
  }

  char *local0Token = pGroup->members[0].state.token;
  char *local1Token = pGroup->members[1].state.token;
  if (mndArbCheckToken(local0Token, member0Token) != 0 || mndArbCheckToken(local1Token, member1Token) != 0) {
    terrno = TSDB_CODE_MND_ARB_TOKEN_MISMATCH;
    mInfo("skip to update arb sync, memberToken mismatch local:[%s][%s], msg:[%s][%s]", local0Token, local1Token,
          member0Token, member1Token);
    goto _OVER;
  }

  // compare and set isSync
  if (pGroup->isSync != newIsSync) {
    SArbGroup newGroup = {0};
    mndArbGroupDupObj(pGroup, &newGroup);
    newGroup.isSync = newIsSync;

    mInfo("vgId:%d, arb isSync updating, new isSync:%d", groupId, newIsSync);

    mndArbGroupUpdateTrans(pMnode, &newGroup);
  }

  terrno = TSDB_CODE_SUCCESS;

_OVER:
  sdbRelease(pMnode->pSdb, pGroup);
}

static int32_t mndProcessArbHbRsp(SRpcMsg *pRsp) {
  SMnode *pMnode = pRsp->info.node;
  SSdb   *pSdb = pMnode->pSdb;

  char arbToken[TSDB_ARB_TOKEN_SIZE];
  mndGetArbToken(pMnode, arbToken);

  SVArbHeartBeatRsp arbHbRsp = {0};
  if (tDeserializeSVArbHeartBeatRsp(pRsp->pCont, pRsp->contLen, &arbHbRsp) != 0) {
    terrno = TSDB_CODE_INVALID_MSG;
    goto _OVER;
  }

  if (mndArbCheckToken(arbToken, arbHbRsp.arbToken) != 0) {
    mInfo("arb hearbeat skip update for dnodeId:%d, arb token mismatch, local:[%s] msg:[%s]", arbHbRsp.dnodeId,
          arbToken, arbHbRsp.arbToken);
    terrno = TSDB_CODE_MND_ARB_TOKEN_MISMATCH;
    goto _OVER;
  }

  mndUpdateArbHeartBeat(pMnode, arbHbRsp.dnodeId, arbHbRsp.hbMembers);

_OVER:
  tFreeSVArbHeartBeatRsp(&arbHbRsp);
  return terrno == TSDB_CODE_SUCCESS ? 0 : -1;
}

static int32_t mndProcessArbCheckSyncRsp(SRpcMsg *pRsp) {
  SMnode *pMnode = pRsp->info.node;
  SSdb   *pSdb = pMnode->pSdb;

  char arbToken[TSDB_ARB_TOKEN_SIZE];
  mndGetArbToken(pMnode, arbToken);

  SVArbCheckSyncRsp syncRsp = {0};
  if (tDeserializeSVArbCheckSyncRsp(pRsp->pCont, pRsp->contLen, &syncRsp) != 0) {
    terrno = TSDB_CODE_INVALID_MSG;
    mInfo("arb sync check failed, since:%s", tstrerror(pRsp->code));
    goto _OVER;
  }

  if (mndArbCheckToken(arbToken, syncRsp.arbToken) != 0) {
    mInfo("skip update arb sync for groupId:%d, arb token mismatch, local:[%s] msg:[%s]", syncRsp.groupId,
          arbToken, syncRsp.arbToken);
    terrno = TSDB_CODE_MND_ARB_TOKEN_MISMATCH;
    goto _OVER;
  }

  bool newIsSync = (syncRsp.errCode == TSDB_CODE_SUCCESS);
  mndUpdateArbSync(pMnode, syncRsp.groupId, syncRsp.member0Token, syncRsp.member1Token, newIsSync);

_OVER:
  tFreeSVArbCheckSyncRsp(&syncRsp);
  return terrno == TSDB_CODE_SUCCESS ? 0 : -1;
}

static int32_t mndProcessArbSetAssignedLeaderRsp(SRpcMsg *pRsp) {
  SMnode *pMnode = pRsp->info.node;
  SSdb   *pSdb = pMnode->pSdb;

  char arbToken[TSDB_ARB_TOKEN_SIZE];
  mndGetArbToken(pMnode, arbToken);

  SVArbSetAssignedLeaderRsp setAssignedRsp = {0};
  if (tDeserializeSVArbSetAssignedLeaderRsp(pRsp->pCont, pRsp->contLen, &setAssignedRsp) != 0) {
    terrno = TSDB_CODE_INVALID_MSG;
    mInfo("arb set assigned failed, des failed since:%s", tstrerror(pRsp->code));
    return -1;
  }

  if (mndArbCheckToken(arbToken, setAssignedRsp.arbToken) != 0) {
    mInfo("skip update arb assigned for groupId:%d, arb token mismatch, local:[%s] msg:[%s]", setAssignedRsp.groupId,
          arbToken, setAssignedRsp.arbToken);
    terrno = TSDB_CODE_MND_ARB_TOKEN_MISMATCH;
    goto _OVER;
  }

  SArbGroup* pGroup = mndAcquireArbGroup(pMnode, setAssignedRsp.groupId);
  if (!pGroup) {
    mError("failed to set arb assigned for groupId:%d, since:%s", setAssignedRsp.groupId, terrstr());
    goto _OVER;
  }

  if (mndArbCheckToken(pGroup->assignedLeader.token, setAssignedRsp.memberToken) != 0) {
    mInfo("skip update arb assigned for groupId:%d, member token mismatch, local:[%s] msg:[%s]", setAssignedRsp.groupId,
          pGroup->assignedLeader.token, setAssignedRsp.memberToken);
    terrno = TSDB_CODE_MND_ARB_TOKEN_MISMATCH;
    goto _OVER;
  }

  if (pRsp->code != TSDB_CODE_SUCCESS) {
    SArbGroup newGroup = {0};
    mndArbGroupDupObj(pGroup, &newGroup);
    mndArbGroupResetAssignedLeader(&newGroup);

    mInfo("vgId:%d, arb resetting assigned leader", setAssignedRsp.groupId);

    mndArbGroupUpdateTrans(pMnode, &newGroup);
    goto _OVER;
  }

  if (pGroup->isSync) {
    SArbGroup newGroup = {0};
    mndArbGroupDupObj(pGroup, &newGroup);
    newGroup.isSync = false;

    mInfo("vgId:%d, arb isSync is setting to false", setAssignedRsp.groupId);

    mndArbGroupUpdateTrans(pMnode, &newGroup);
    goto _OVER;
  }

_OVER:
  tFreeSVArbSetAssignedLeaderRsp(&setAssignedRsp);
  return terrno == TSDB_CODE_SUCCESS ? 0 : -1;
}

static int32_t mndRetrieveArbGroups(SRpcMsg *pReq, SShowObj *pShow, SSDataBlock *pBlock, int32_t rows) {
  SMnode    *pMnode = pReq->info.node;
  SSdb      *pSdb = pMnode->pSdb;
  int32_t    numOfRows = 0;
  int32_t    cols = 0;
  SArbGroup *pGroup = NULL;

  while (numOfRows < rows) {
    pShow->pIter = sdbFetch(pSdb, SDB_ARBGROUP, pShow->pIter, (void **)&pGroup);
    if (pShow->pIter == NULL) break;

    cols = 0;
    SColumnInfoData *pColInfo = taosArrayGet(pBlock->pDataBlock, cols++);
    colDataSetVal(pColInfo, numOfRows, (const char *)&pGroup->groupId, false);

    for (int i = 0; i < 2; i++) {
      SArbGroupMember *pMember = &pGroup->members[i];
      pColInfo = taosArrayGet(pBlock->pDataBlock, cols++);
      colDataSetVal(pColInfo, numOfRows, (const char *)&pMember->info.dnodeId, false);
    }

    pColInfo = taosArrayGet(pBlock->pDataBlock, cols++);
    colDataSetVal(pColInfo, numOfRows, (const char *)&pGroup->isSync, false);

    pColInfo = taosArrayGet(pBlock->pDataBlock, cols++);
    colDataSetVal(pColInfo, numOfRows, (const char *)&pGroup->assignedLeader.dnodeId, false);

    char token[TSDB_ARB_TOKEN_SIZE + VARSTR_HEADER_SIZE] = {0};
    STR_WITH_MAXSIZE_TO_VARSTR(token, pGroup->assignedLeader.token, TSDB_ARB_TOKEN_SIZE + VARSTR_HEADER_SIZE);
    pColInfo = taosArrayGet(pBlock->pDataBlock, cols++);
    colDataSetVal(pColInfo, numOfRows, (const char *)token, false);

    numOfRows++;
    sdbRelease(pSdb, pGroup);
  }

  pShow->numOfRows += numOfRows;

  return numOfRows;
}

static void mndCancelGetNextArbGroup(SMnode *pMnode, void *pIter) {
  SSdb *pSdb = pMnode->pSdb;
  sdbCancelFetch(pSdb, pIter);
}

int32_t mndGetArbGroupSize(SMnode *pMnode) {
  SSdb *pSdb = pMnode->pSdb;
  return sdbGetSize(pSdb, SDB_ARBGROUP);
}
