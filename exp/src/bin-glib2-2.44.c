#include<stdio.h>
#include <glib.h>
int main(int argc, char** argv) {
 GList* list = NULL;
 printf("lscan binary test file statically compiled with glib2-2.44\n");
 list = g_list_append(list, "Hello world!");
 printf("The first item is '%s'\n", g_list_first(list)->data);
 return 0;
}
