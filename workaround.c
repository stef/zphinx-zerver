#include "tp-dkg.h"
#include "toprf.h"
#include <stdlib.h>
#include <string.h>

TP_DKG_PeerState* new_peerstate(void) {
  return aligned_alloc(64,sizeof(TP_DKG_PeerState));
}

void extract_share(const TP_DKG_PeerState *ctx, uint8_t share[TOPRF_Share_BYTES]) {
  memcpy(share, &ctx->share, TOPRF_Share_BYTES);
}

void del_peerstate(TP_DKG_PeerState **peer) {
  if(*peer!=NULL) free(*peer);
  *peer = NULL;
}
