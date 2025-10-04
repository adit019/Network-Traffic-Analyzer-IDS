#pragma once
#include <stdint.h>
#include <stddef.h>
#include <pcap/pcap.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  const uint8_t* data;
  uint32_t len;
  uint64_t ts_nsec;
} nta_packet_t;

typedef enum { NTA_OK=0, NTA_DROP=1, NTA_ALERT=2 } nta_action_t;

typedef struct {
  // Simple extracted fields for rules to match on (extendable)
  const char* l4_proto;   // "TCP","UDP","ICMP",...
  uint16_t src_port, dst_port;
  const char* http_host;  // if parsed
  const char* http_path;  // if parsed
} nta_flow_features_t;

// ---- Capture ----
typedef struct nta_capture nta_capture_t;
nta_capture_t* nta_capture_open_live(const char* ifname, int snaplen, int promisc, int timeout_ms, char* errbuf);
nta_capture_t* nta_capture_open_offline(const char* pcap_path, char* errbuf);
int  nta_capture_next(nta_capture_t* cap, nta_packet_t* out);
void nta_capture_close(nta_capture_t* cap);

// ---- DPI (very light HTTP/TCP parser/demo) ----
void nta_dpi_extract(const nta_packet_t* pkt, nta_flow_features_t* out);

// ---- Rules Engine ----
typedef struct nta_rules nta_rules_t;
nta_rules_t* nta_rules_load(const char* path);     // simple DSL
void         nta_rules_free(nta_rules_t*);
nta_action_t nta_rules_eval(const nta_rules_t*, const nta_flow_features_t*);

// ---- Pipeline (multithreaded) ----
int nta_pipeline_run_offline(const char* pcap_path, const char* rules_path, int worker_threads);

#ifdef __cplusplus
}
#endif
