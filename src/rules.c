#include \"nta.h\"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct rule {
  char key[32];
  char op[8];
  char val[128];
  struct rule* next;
} rule_t;

struct nta_rules {
  rule_t* head;
};

static int match_kv(const char* actual, const char* op, const char* expected) {
  if (!actual) return 0;
  if (strcmp(op, \"==\") == 0) return strcmp(actual, expected) == 0;
  if (strcmp(op, \"contains\") == 0) return strstr(actual, expected) != NULL;
  return 0;
}

nta_rules_t* nta_rules_load(const char* path) {
  FILE* f = fopen(path, \"r\");
  if (!f) return NULL;
  nta_rules_t* R = (nta_rules_t*)calloc(1, sizeof(*R));
  char line[256];
  while (fgets(line, sizeof(line), f)) {
    if (line[0]=='#' || line[0]=='\\n') continue;
    rule_t* r = (rule_t*)calloc(1, sizeof(*r));
    if (sscanf(line, \"%31s %7s %127[^\\n]\", r->key, r->op, r->val) != 3) { free(r); continue; }
    r->next = R->head; R->head = r;
  }
  fclose(f);
  return R;
}

void nta_rules_free(nta_rules_t* R) {
  rule_t* r = R ? R->head : NULL;
  while (r) { rule_t* n = r->next; free(r); r = n; }
  free(R);
}

nta_action_t nta_rules_eval(const nta_rules_t* R, const nta_flow_features_t* f) {
  if (!R || !f) return NTA_OK;
  for (const rule_t* r=R->head; r; r=r->next) {
    if (strcmp(r->key, \"proto\")==0 && match_kv(f->l4_proto, r->op, r->val)) return NTA_ALERT;
    if (strcmp(r->key, \"dst_port\")==0 && strcmp(r->op,\"==\")==0 && f->dst_port == (uint16_t)atoi(r->val)) return NTA_ALERT;
    if (strcmp(r->key, \"http_host\")==0 && match_kv(f->http_host, r->op, r->val)) return NTA_ALERT;
    if (strcmp(r->key, \"http_path\")==0 && match_kv(f->http_path, r->op, r->val)) return NTA_ALERT;
  }
  return NTA_OK;
}
