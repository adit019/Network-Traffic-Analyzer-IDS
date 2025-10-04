#include \"nta.h\"
#include <string.h>
#include <arpa/inet.h>

typedef struct {
  uint8_t  ver_ihl, tos;
  uint16_t tot_len, id, frag_off;
  uint8_t  ttl, proto;
  uint16_t check;
  uint32_t saddr, daddr;
} __attribute__((packed)) ipv4_hdr;

typedef struct {
  uint16_t src, dst;
  uint32_t seq, ack;
  uint8_t  off_reserved;
  uint8_t  flags;
  uint16_t win, sum, urp;
} __attribute__((packed)) tcp_hdr;

static const char* starts_with(const char* s, const char* p) {
  return (s && p && strncmp(s, p, strlen(p))==0) ? s : NULL;
}

void nta_dpi_extract(const nta_packet_t* pkt, nta_flow_features_t* out) {
  memset(out, 0, sizeof(*out));
  if (!pkt || pkt->len < 54) return; // L2 + IP + TCP (rough)
  const uint8_t* p = pkt->data;
  // Assume Ethernet + IPv4
  if (p[12] != 0x08 || p[13] != 0x00) return; // not IPv4
  const ipv4_hdr* ip = (const ipv4_hdr*)(p + 14);
  size_t ihl = (ip->ver_ihl & 0x0F) * 4;
  if (ihl < 20) return;
  if (ip->proto == 6) out->l4_proto = "TCP";
  else if (ip->proto == 17) out->l4_proto = "UDP";
  else if (ip->proto == 1) out->l4_proto = "ICMP";
  else out->l4_proto = "OTHER";
  if (ip->proto != 6) return;

  const tcp_hdr* tcp = (const tcp_hdr*)((const uint8_t*)ip + ihl);
  size_t doff = ((tcp->off_reserved >> 4) & 0xF) * 4;
  out->src_port = ntohs(tcp->src);
  out->dst_port = ntohs(tcp->dst);
  const char* payload = (const char*)(((const uint8_t*)tcp) + doff);
  size_t plen = pkt->len - (payload - (const char*)pkt->data);
  if (plen < 4) return;

  // Very light HTTP detection (GET/POST/Host:)
  if (starts_with(payload, "GET ") || starts_with(payload, "POST ")) {
    const char* host = strstr(payload, "\r\nHost: ");
    if (host) {
      host += 8;
      const char* e = strstr(host, "\r\n");
      static __thread char hostbuf[128];
      size_t n = e ? (size_t)(e - host) : (size_t)0;
      if (n > sizeof(hostbuf)-1) n = sizeof(hostbuf)-1;
      memcpy(hostbuf, host, n); hostbuf[n] = 0;
      out->http_host = hostbuf;
    }
    // Extract path after method
    const char* path = payload + 4; // after "GET "
    const char* sp = strchr(path, ' ');
    static __thread char pathbuf[128];
    if (sp) {
      size_t n = (size_t)(sp - path);
      if (n > sizeof(pathbuf)-1) n = sizeof(pathbuf)-1;
      memcpy(pathbuf, path, n); pathbuf[n] = 0;
      out->http_path = pathbuf;
    }
  }
}
