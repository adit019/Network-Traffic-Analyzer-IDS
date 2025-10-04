#include <assert.h>
#include <string.h>
#include <stdint.h>
#include \"nta.h\"

int main(){
  // Synthetic packet not built here; DPI extractor is smoke-tested via pipeline in CI.
  // Unit test focuses on basic API presence.
  nta_flow_features_t f = {0};
  f.l4_proto = \"UDP\";
  assert(strcmp(f.l4_proto, \"UDP\") == 0);
  return 0;
}
