#include <assert.h>
#include <string.h>
#include \"nta.h\"

int main(){
  nta_flow_features_t f = {0};
  f.l4_proto = \"TCP\"; f.dst_port=80; f.http_host=\"example.com\"; f.http_path=\"/\";

  nta_rules_t* R = nta_rules_load(\"rules/demo.rules\");
  assert(R && \"rules load\");
  assert(nta_rules_eval(R,&f) == NTA_ALERT); // proto==TCP rule triggers
  nta_rules_free(R);
  return 0;
}
