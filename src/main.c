#include \"nta.h\"
#include <stdio.h>
#include <stdlib.h>

static void usage(void){
  fprintf(stderr, "Usage: nta --pcap <file.pcap> --rules <rules.txt> [--threads N]\\n");
}

int main(int argc, char** argv){
  const char* pcap = NULL;
  const char* rules = \"rules/demo.rules\";
  int threads = 4;
  for (int i=1;i<argc;i++){
    if (!strcmp(argv[i],\"--pcap\") && i+1<argc) pcap=argv[++i];
    else if (!strcmp(argv[i],\"--rules\") && i+1<argc) rules=argv[++i];
    else if (!strcmp(argv[i],\"--threads\") && i+1<argc) threads=atoi(argv[++i]);
  }
  if (!pcap){ usage(); return 2; }
  return nta_pipeline_run_offline(pcap, rules, threads);
}
