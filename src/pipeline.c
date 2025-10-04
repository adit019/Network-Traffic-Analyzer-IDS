#include \"nta.h\"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  nta_packet_t pkt;
  int in_use;
} pkt_slot_t;

#define QUEUE_SIZE 1024

typedef struct {
  pkt_slot_t q[QUEUE_SIZE];
  int head, tail;
  pthread_mutex_t mtx;
  pthread_cond_t  cv;
  int done;
} ring_t;

static void ring_init(ring_t* r) {
  memset(r,0,sizeof(*r));
  pthread_mutex_init(&r->mtx,NULL);
  pthread_cond_init(&r->cv,NULL);
}
static void ring_push(ring_t* r, const nta_packet_t* p) {
  pthread_mutex_lock(&r->mtx);
  int next = (r->head+1) % QUEUE_SIZE;
  while (next == r->tail) pthread_cond_wait(&r->cv,&r->mtx); // full
  r->q[r->head].pkt = *p; r->q[r->head].in_use = 1; r->head = next;
  pthread_cond_broadcast(&r->cv);
  pthread_mutex_unlock(&r->mtx);
}
static int ring_pop(ring_t* r, nta_packet_t* out) {
  pthread_mutex_lock(&r->mtx);
  while (r->head == r->tail && !r->done) pthread_cond_wait(&r->cv,&r->mtx);
  if (r->head == r->tail && r->done) { pthread_mutex_unlock(&r->mtx); return 0; }
  *out = r->q[r->tail].pkt; r->q[r->tail].in_use = 0; r->tail = (r->tail+1)%QUEUE_SIZE;
  pthread_cond_broadcast(&r->cv);
  pthread_mutex_unlock(&r->mtx);
  return 1;
}

typedef struct {
  ring_t* ring;
  const nta_rules_t* rules;
  volatile unsigned long alerts;
} worker_ctx_t;

static void* worker(void* arg) {
  worker_ctx_t* ctx = (worker_ctx_t*)arg;
  nta_packet_t pkt;
  nta_flow_features_t f;
  while (ring_pop(ctx->ring, &pkt)) {
    nta_dpi_extract(&pkt, &f);
    if (nta_rules_eval(ctx->rules, &f) == NTA_ALERT) ctx->alerts++;
  }
  return NULL;
}

int nta_pipeline_run_offline(const char* pcap_path, const char* rules_path, int worker_threads) {
  char err[PCAP_ERRBUF_SIZE];
  nta_capture_t* cap = nta_capture_open_offline(pcap_path, err);
  if (!cap) { fprintf(stderr, "pcap open error: %s\n", err); return 2; }
  nta_rules_t* rules = nta_rules_load(rules_path);
  if (!rules) { fprintf(stderr, "failed to load rules\n"); nta_capture_close(cap); return 2; }

  ring_t ring; ring_init(&ring);
  pthread_t* th = (pthread_t*)calloc(worker_threads, sizeof(pthread_t));
  worker_ctx_t ctx = { .ring = &ring, .rules = rules, .alerts = 0 };

  for (int i=0;i<worker_threads;++i) pthread_create(&th[i], NULL, worker, &ctx);

  nta_packet_t pkt;
  int rc;
  while ((rc = nta_capture_next(cap, &pkt)) > 0) {
    ring_push(&ring, &pkt);
  }

  pthread_mutex_lock(&ring.mtx); ring.done = 1; pthread_cond_broadcast(&ring.cv); pthread_mutex_unlock(&ring.mtx);
  for (int i=0;i<worker_threads;++i) pthread_join(th[i], NULL);

  printf("alerts=%lu\n", ctx.alerts);

  free(th);
  nta_rules_free(rules);
  nta_capture_close(cap);
  return rc < 0 ? 1 : 0;
}
