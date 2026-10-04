#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdarg.h>
static int should_fail(int fd) {
 char path[4096];
 const char *marker=getenv("OURO_READER_FSYNC_MARKER");
 if (marker && access(marker,F_OK)==0 && fcntl(fd,F_GETPATH,path)==0) {
  size_t n=strlen(path); const char *scope=getenv("OURO_READER_SYNC_SCOPE"); const char *suffix=(scope && strcmp(scope,"parent")==0) ? "/ledger" : "/ledger/readers";
  if(n>=strlen(suffix) && strcmp(path+n-strlen(suffix),suffix)==0) {
   fprintf(stderr,"INJECTED EIO on reader directory sync(%s)\n",path); return 1;
  }
 }
 return 0;
}
static int fail_reader_fsync(int fd) {
 if(should_fail(fd)){errno=EIO;return -1;} return fsync(fd);
}
static int fail_reader_fcntl(int fd,int cmd,...) {
 if(cmd==F_FULLFSYNC) {if(should_fail(fd)){errno=EIO;return -1;}return fcntl(fd,cmd);}
 va_list args;va_start(args,cmd);void *arg=va_arg(args,void*);va_end(args);return fcntl(fd,cmd,arg);
}
__attribute__((used)) static struct {const void *replacement; const void *replacee;} interpose[] __attribute__((section("__DATA,__interpose")))={{(const void*)fail_reader_fsync,(const void*)fsync},{(const void*)fail_reader_fcntl,(const void*)fcntl}};
