#include \"nta.h\"
#include <stdlib.h>
#include <string.h>

struct nta_capture {
  pcap_t* handle;
  struct pcap_pkthdr* hdr;
  const u_char* data;
};

nta_capture_t* nta_capture_open_live(const char* ifname, int snaplen, int promisc, int timeout_ms, char* errbuf) {
  pcap_t* h = pcap_open_live(ifname, snaplen, promisc, timeout_ms, errbuf);
  if (!h) return NULL;
  nta_capture_t* cap = (nta_capture_t*)calloc(1, sizeof(*cap));
  cap->handle = h;
  return cap;
}

nta_capture_t* nta_capture_open_offline(const char* pcap_path, char* errbuf) {
  pcap_t* h = pcap_open_offline(pcap_path, errbuf);
  if (!h) return NULL;
  nta_capture_t* cap = (nta_capture_t*)calloc(1, sizeof(*cap));
  cap->handle = h;
  return cap;
}

int nta_capture_next(nta_capture_t* cap, nta_packet_t* out) {
  int rc = pcap_next_ex(cap->handle, &cap->hdr, &cap->data);
  if (rc <= 0) return rc; // 0: timeout, -1: err, -2: EOF
  out->data = cap->data;
  out->len  = (uint32_t)cap->hdr->caplen;
  out->ts_nsec = ((uint64_t)cap->hdr->ts.tv_sec * 1000000000ull) + ((uint64_t)cap->hdr->ts.tv_usec * 1000ull);
  return 1;
}

void nta_capture_close(nta_capture_t* cap) {
  if (!cap) return;
  if (cap->handle) pcap_close(cap->handle);
  free(cap);
}
