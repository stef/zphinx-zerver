#include "oprf/tp-dkg.h"
#include "oprf/toprf.h"
#include <stdlib.h>
#include <string.h>

// zig cannot align data at 64Byte (or anything beyond 16 bytes really)
// see https://github.com/ziglang/zig/issues/8452

// thus we have to workaround this by allocating/freeing and accessing
// the data in c which the zig cc backend (clang) handles correctly.
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
