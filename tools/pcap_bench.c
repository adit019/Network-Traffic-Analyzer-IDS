#include <stdio.h>
#include <time.h>
#include \"nta.h\"

static double now_s(void){
  struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec + ts.tv_nsec/1e9;
}

int main(int argc, char** argv){
  if (argc < 2){ fprintf(stderr, "usage: pcap_bench <file.pcap>\\n"); return 2; }
  const char* p = argv[1];
  char err[PCAP_ERRBUF_SIZE];
  nta_capture_t* cap = nta_capture_open_offline(p, err);
  if (!cap){ fprintf(stderr, "pcap open: %s\\n", err); return 2; }
  nta_packet_t pkt;
  int count = 0;
  double t0 = now_s();
  while (nta_capture_next(cap, &pkt) > 0) count++;
  double t1 = now_s();
  double dt = t1 - t0;
  printf("packets=%d time=%.3fs rate=%.0f pkt/s\\n", count, dt, count/(dt>0?dt:1e-9));
  nta_capture_close(cap);
  return 0;
}
