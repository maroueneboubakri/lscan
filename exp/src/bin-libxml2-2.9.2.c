#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

int
main(int argc, char **argv) {

  char         *docname;
  xmlDocPtr    doc;
  xmlNodePtr   cur;
  xmlChar      *uri;

  printf("lscan test binary file statically linked with libxml2-2.9.2\n");
  
  if (argc <= 1) {
    printf("Usage: %s docname\n", argv[0]);
    return(0);
  }

  docname = argv[1];

  doc = xmlParseFile(docname);
  cur = xmlDocGetRootElement(doc);

  cur = cur->xmlChildrenNode;
  while (cur != NULL) {
      if ((!xmlStrcmp(cur->name, (const xmlChar *)"reference"))) {
        uri = xmlGetProp(cur, "uri");
        printf("uri: %s\n", uri);
        xmlFree(uri);
      }
      cur = cur->next;
  }
  xmlFreeDoc(doc);
  return (1);
}
