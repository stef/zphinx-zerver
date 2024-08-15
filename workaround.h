#ifndef workaround_h
#define workaround_h
#include "tp-dkg.h"
#include "toprf.h"
#include <stdint.h>

TP_DKG_PeerState* new_peerstate(void);
void extract_share(const TP_DKG_PeerState *ctx, uint8_t share[TOPRF_Share_BYTES]);
void del_peerstate(TP_DKG_PeerState **peer);
#endif // workaround_h
