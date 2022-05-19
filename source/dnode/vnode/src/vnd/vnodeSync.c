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

#include "vnd.h"

int32_t vnodeSyncOpen(SVnode *pVnode, char *path) {
  SSyncInfo syncInfo;
  syncInfo.vgId = pVnode->config.vgId;
  SSyncCfg *pCfg = &(syncInfo.syncCfg);
  pCfg->replicaNum = pVnode->config.syncCfg.replicaNum;
  pCfg->myIndex = pVnode->config.syncCfg.myIndex;
  memcpy(pCfg->nodeInfo, pVnode->config.syncCfg.nodeInfo, sizeof(pCfg->nodeInfo));

  snprintf(syncInfo.path, sizeof(syncInfo.path), "%s/sync", path);
  syncInfo.pWal = pVnode->pWal;

  syncInfo.pFsm = syncVnodeMakeFsm(pVnode);
  syncInfo.msgcb = NULL;
  syncInfo.FpSendMsg = vnodeSyncSendMsg;
  syncInfo.FpEqMsg = vnodeSyncEqMsg;

  pVnode->sync = syncOpen(&syncInfo);
  assert(pVnode->sync > 0);

  // for test
  setPingTimerMS(pVnode->sync, 3000);
  setElectTimerMS(pVnode->sync, 500);
  setHeartbeatTimerMS(pVnode->sync, 100);

  return 0;
}

int32_t vnodeSyncStart(SVnode *pVnode) {
  syncStart(pVnode->sync);
  return 0;
}

void vnodeSyncClose(SVnode *pVnode) {
  // stop by ref id
  syncStop(pVnode->sync);
}

void vnodeSyncSetMsgCb(SVnode *pVnode) { syncSetMsgCb(pVnode->sync, &pVnode->msgCb); }

int32_t vnodeSyncEqMsg(const SMsgCb *msgcb, SRpcMsg *pMsg) { return tmsgPutToQueue(msgcb, SYNC_QUEUE, pMsg); }

int32_t vnodeSyncSendMsg(const SEpSet *pEpSet, SRpcMsg *pMsg) {
  pMsg->info.noResp = 1;
  return tmsgSendReq(pEpSet, pMsg);
}

int32_t vnodeSyncGetSnapshotCb(struct SSyncFSM *pFsm, SSnapshot *pSnapshot) {
  SVnode *pVnode = (SVnode *)(pFsm->data);
  vnodeGetSnapshot(pVnode, pSnapshot);

  /*
  pSnapshot->data = NULL;
  pSnapshot->lastApplyIndex = 0;
  pSnapshot->lastApplyTerm = 0;
  */

  return 0;
}

void vnodeSyncCommitCb(struct SSyncFSM *pFsm, const SRpcMsg *pMsg, SFsmCbMeta cbMeta) {
  SyncIndex beginIndex = SYNC_INDEX_INVALID;
  if (pFsm->FpGetSnapshot != NULL) {
    SSnapshot snapshot;
    pFsm->FpGetSnapshot(pFsm, &snapshot);
    beginIndex = snapshot.lastApplyIndex;
  }

  if (cbMeta.index > beginIndex) {
    char logBuf[256];
    snprintf(
        logBuf, sizeof(logBuf),
        "==callback== ==CommitCb== execute, pFsm:%p, index:%ld, isWeak:%d, code:%d, state:%d %s, beginIndex :%ld\n",
        pFsm, cbMeta.index, cbMeta.isWeak, cbMeta.code, cbMeta.state, syncUtilState2String(cbMeta.state), beginIndex);
    syncRpcMsgLog2(logBuf, (SRpcMsg *)pMsg);

    SVnode       *pVnode = (SVnode *)(pFsm->data);
    SyncApplyMsg *pSyncApplyMsg = syncApplyMsgBuild2(pMsg, pVnode->config.vgId, &cbMeta);
    SRpcMsg       applyMsg;
    syncApplyMsg2RpcMsg(pSyncApplyMsg, &applyMsg);
    syncApplyMsgDestroy(pSyncApplyMsg);

    /*
        SRpcMsg applyMsg;
        applyMsg = *pMsg;
        applyMsg.pCont = rpcMallocCont(applyMsg.contLen);
        assert(applyMsg.contLen == pMsg->contLen);
        memcpy(applyMsg.pCont, pMsg->pCont, applyMsg.contLen);
    */

    // recover handle for response
    SRpcMsg saveRpcMsg;
    int32_t ret = syncGetAndDelRespRpc(pVnode->sync, cbMeta.seqNum, &saveRpcMsg);
    if (ret == 1 && cbMeta.state == TAOS_SYNC_STATE_LEADER) {
      applyMsg.info = saveRpcMsg.info;
    } else {
      applyMsg.info.handle = NULL;
      applyMsg.info.ahandle = NULL;
    }

    // put to applyQ
    tmsgPutToQueue(&(pVnode->msgCb), APPLY_QUEUE, &applyMsg);

  } else {
    char logBuf[256];
    snprintf(logBuf, sizeof(logBuf),
             "==callback== ==CommitCb== do not execute, pFsm:%p, index:%ld, isWeak:%d, code:%d, state:%d %s, "
             "beginIndex :%ld\n",
             pFsm, cbMeta.index, cbMeta.isWeak, cbMeta.code, cbMeta.state, syncUtilState2String(cbMeta.state),
             beginIndex);
    syncRpcMsgLog2(logBuf, (SRpcMsg *)pMsg);
  }
}

void vnodeSyncPreCommitCb(struct SSyncFSM *pFsm, const SRpcMsg *pMsg, SFsmCbMeta cbMeta) {
  char logBuf[256];
  snprintf(logBuf, sizeof(logBuf),
           "==callback== ==PreCommitCb== pFsm:%p, index:%ld, isWeak:%d, code:%d, state:%d %s \n", pFsm, cbMeta.index,
           cbMeta.isWeak, cbMeta.code, cbMeta.state, syncUtilState2String(cbMeta.state));
  syncRpcMsgLog2(logBuf, (SRpcMsg *)pMsg);
}

void vnodeSyncRollBackCb(struct SSyncFSM *pFsm, const SRpcMsg *pMsg, SFsmCbMeta cbMeta) {
  char logBuf[256];
  snprintf(logBuf, sizeof(logBuf), "==callback== ==RollBackCb== pFsm:%p, index:%ld, isWeak:%d, code:%d, state:%d %s \n",
           pFsm, cbMeta.index, cbMeta.isWeak, cbMeta.code, cbMeta.state, syncUtilState2String(cbMeta.state));
  syncRpcMsgLog2(logBuf, (SRpcMsg *)pMsg);
}

SSyncFSM *syncVnodeMakeFsm(SVnode *pVnode) {
  SSyncFSM *pFsm = (SSyncFSM *)taosMemoryMalloc(sizeof(SSyncFSM));
  pFsm->data = pVnode;
  pFsm->FpCommitCb = vnodeSyncCommitCb;
  pFsm->FpPreCommitCb = vnodeSyncPreCommitCb;
  pFsm->FpRollBackCb = vnodeSyncRollBackCb;
  pFsm->FpGetSnapshot = vnodeSyncGetSnapshotCb;
  return pFsm;
}
