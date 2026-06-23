# define _GNU_SOURCE

# include "crypto-algorithms/base64.h"
# include "crypto-algorithms/sha256.h"
# include <ctype.h>
# include <dirent.h>
# include <errno.h>
# include <limits.h>
# include <linux/sched.h>
# include "lua/lua.h"
# include "lua/lauxlib.h"
# include "lua/lualib.h"
# include <pthread.h>
# include <sched.h>
# include "stb_ds.h"
# include <stdarg.h>
# include <stdlib.h>
# include <stdio.h>
# include <stdint.h>
# include <string.h>
# include <sys/epoll.h>
# include <sys/eventfd.h>
# include <sys/mman.h>
# include <sys/mount.h>
# include <sys/sendfile.h>
# include <sys/socket.h>
# include <sys/stat.h>
# include <sys/syscall.h>
# include <sys/wait.h>
# include <unistd.h>

#define STB_DS_IMPLEMENTATION
# include "stb_ds.h"
#include "crypto-algorithms/base64.h"
#include "crypto-algorithms/sha256.h"

#define STR_HELPER(x) #x
#define TOSTRING(x) STR_HELPER(x)
#define AT __FILE__ ":" TOSTRING(__LINE__)
#define errif(x) if(x) { \
  perror(AT); \
  exit(errno); \
}
#define errife(x, errnum) if(x) { \
  errno = errnum; \
  perror(AT); \
  exit(errno); \
}

#define CMNT_MAX 256
#define CREATTOOL_FILE 0x1
#define CREATTOOL_DIR 0x2
#define CREATTOOL_UPDIRS 0x4
#define CREATTOOL_UPDIRMODE 0x8
#define CREATTOOL_EXCL 0x10
#define ENDPOINT_MAX 64
#define FDI_SUPERVISOR 3
#define FDI_SRC 4
#define FDI_DESTPATH 5
#define FDI_CODE 6
#define FDI_LASTI 6
#define hexdec "abcdefABCDEF0123456789"
#define LUAWSPACES " \f\n\r\t\v"
#define PARAM_MAX 1024
#define PE_KSZ 64
#define RMR_KEEPCONTAINER 0x1
#define RMR_IFEXISTS 0x2
#define SREQ_NEWSCK 0
#define SREQ_CACHEGET 1
#define SREQ_CACHEPUT 2
#define SREQ_ISTHERE 0x1
#define SREQ_MOUNTFD 0x2
#define SREQ_SHUTDOWN 0x4
#define SREQ_REGFILE 0x8
#define SREQ_DIR 0x10
#define SUPVSRFDI_EPOLL 0
#define SUPVSRFDI_LAST 0

typedef struct build_args build_args;
typedef struct caccent caccent;
typedef struct svsr_msg;

void build(build_args *ba);
void buildpath(char *buf, const char *first, ...);
void cachehstr(char buf[NAME_MAX], const char *sha256, const char *name);
size_t checkltblstr(const char *ts, int flags);
void copytool(int srcdir, const char *src, int destdir, const char *dest, int flags);
void cpyntillptr(const char *ogstr, const char *ptr, const char *buf, size_t bsz);
void creattool(int dir, const char *path, uint64_t flags, mode_t mode, ...);
void *lnullunwrp(void *value);
const void *lnullwrp(void *value);
int luaapi_fslib_register(lua_State *luast);
int luaapi_init(lua_State *ls);
void luadumpfd(int fd, lua_State *L);
void lualoadfd(int fd, char *chunkname, lua_State *L);
uint32_t main(uint32_t argc, char* argv[]);
int rmr(const char *path, int flags);
void startasbuilder();
int startassupervisor();
void svsr(svsr_msg *req, svsr_msg *res);
int xiolib_init(lua_State *st);

bdr_data *bdata;
int buildn = 0;
char fd_luareader_buf[2048];
const luaL_Reg luaapi_fslib[] = {
  {"direntries", &fslib_direntries},
  {"copy", &fs_copy},
  {"rename", &fs_rename},
  {"mkdir", &fs_mkdir},
  {NULL, NULL}
};
void *luanull = "luanull";
const char sha256zero[32] = {0};
svsr_data *sdata;
const luaL_Reg xiolib_functions[] = {
  {"writefile", &xio_writefile},
  {NULL, NULL}
};

// int errnotostring(lua_State *ls);
// int pusherrno(lua_State *ls, int givenerrno);

#include "crypto-algorithms/base64.c"
#include "crypto-algorithms/sha256.c"

struct bdr_data {
  char chunkname[512];
  int script;
  char params[PARMAX];
  fdent srcs[10];
  pathent dests[10];
};

struct build_args {
  pathorfd script;
  char params[PARMAX];
  pathent srcs[10];
  pathent dests[10];
  char ws[PATH_MAX];
};

struct cmnt {
  uint64_t mntid;
  char sha256[32];
  chra name[ENDPOINT_MAX];
};

typedef struct fdent {
  char k[PE_KSZ];
  int fd;
} fdent;

struct pathent {
  char k[PE_KSZ];
  pathent v;
}


struct pathorfd {
  int fd;
  char path[PATH_MAX];
};

struct supvsr_msg {
  int type;
  char sha256[32];
};

typedef struct svsr_data {
  char cache[PATH_MAX];
  int *fds;
  pthread_t thread;
  cmnt cmnt_tbl[CMNT_MAX];
} svsr_data;

struct svsr_msg {
  int type;
  char hash[32];
  int fd;
  char name[ENDPOINTMAX];
  uint64_t flags;
};

void build(build_args *ba) {
  pid_t pid;
  int newsupfd;
  int returned_destpathfd;
  char *returned_destpath;
  char dest_internalpath[PATH_MAX];
  int thisexefd;
  char chunknamebuf[256];
  char *argv[4];
  int status;
  struct timespec starttime, finishtime, duration;

  buildn++;
  clock_gettime(CLOCK_MONOTONIC, &starttime);
  fprintf(stderr, "Begun the build #%d. Time: %ds %dms %dys %dns\n", buildn, starttime.tv_sec, starttime.tv_nsec / 1000000, (starttime.tv_nsec / 1000) % 1000, starttime.tv_nsec % 1000);

  calchash(ba, ba->hash);
  if (cache_query(ba->hash)) {
    if (ba->destpath != NULL) {
      errif(cache_get(ba->destpath, ba->hash));
    }
    clock_gettime(CLOCK_MONOTONIC, &finishtime);
    duration = calculate_duration(starttime, finishtime);
    fprintf(stderr, "Finished the build #%d (cached). Time: %ds %dms %dys %dns. Duration: %ds %dms %dys %dns.\n", buildn, finishtime.tv_sec, finishtime.tv_nsec / 1000000, (finishtime.tv_nsec / 1000) % 1000, finishtime.tv_nsec % 1000, duration.tv_sec, duration.tv_nsec / 1000000, (duration.tv_nsec / 1000) % 1000, duration.tv_nsec % 1000);
    return;
  }

  newsupfd = newsupervisorfd();
  thisexefd = openthisexe();

  returned_destpathfd = memfd_create("returned_destpath", MFD_ALLOW_SEALING);
  errif(returned_destpathfd == -1);
  errif(ftruncate(returned_destpathfd, PATH_MAX));
  errif(fcntl(returned_destpathfd, F_ADD_SEALS, F_SEAL_SHRINK | F_SEAL_GROW));
  returned_destpath = mmap(NULL, PATH_MAX, PROT_READ, MAP_SHARED, returned_destpathfd, 0);
  errif(returned_destpath == MAP_FAILED);

  pid = fork();
  errif(pid == -1);
  if (pid != 0) {
    errif(waitpid(pid, &status, 0) == -1);
    errif(!WIFEXITED(status));
    errif(WEXITSTATUS(status) != 0);

    buildpath(dest_internalpath, ba->workspace, "/", returned_destpath, NULL);
    cache_put(dest_internalpath, ba->hash);
    if (ba->destpath != NULL) {
      errif(cache_get(ba->destpath, ba->hash));
    } else {
      strcpy(ba->destpathbuf, dest_internalpath);
      ba->destpath = ba->destpathbuf;
    }

    close(newsupfd);
    close(thisexefd);
    close(returned_destpathfd);
    clock_gettime(CLOCK_MONOTONIC, &finishtime);
    duration = calculate_duration(starttime, finishtime);
    fprintf(stderr, "Finished the build #%d (uncached). Time: %ds %dms %dys %dns. Duration: %ds %dms %dys %dns.\n", buildn, finishtime.tv_sec, finishtime.tv_nsec / 1000000, (finishtime.tv_nsec / 1000) % 1000, finishtime.tv_nsec % 1000, duration.tv_sec, duration.tv_nsec / 1000000, (duration.tv_nsec / 1000) % 1000, duration.tv_nsec % 1000);
    return;
  }

  

  unshare(CLONE_NEWUSER | CLONE_NEWNS);

  creattool(AT_FDCWD, ba->workspace, CREATTOOL_DIR, 0777);
  rmr(ba->workspace, RMR_KEEPCONTAINER);

  chdir(ba->workspace);
  chroot(".");

  errif(dup2(newsupfd, FDI_SUPERVISOR) == -1);
  if (ba->srcfd != -2) errif(dup2(ba->srcfd, FDI_SRC) == -1);
  errif(dup2(returned_destpathfd, FDI_DESTPATH) == -1);
  errif(dup2(ba->code, FDI_CODE) == -1);
  
  destpath = mmap(NULL, PATH_MAX, PROT_READ | PROT_WRITE, MAP_SHARED, FDI_DESTPATH, 0);
  strcpy(destpath, "/dest");
  syscall(SYS_close_range, FDI_LASTI + 1, ~0U, 0);
  
  lua_State *L = luaL_newstate();
  luaL_openlibs(L);
  luaapi_fslib_register(L);
  xiolib_init(L);
  luaapi_init(L);

  lualoadfd(FDI_CODE, chunkname, L);
  lua_call(L, 0, 0);
  exit(0);
}

void buildpath(char buf[PATH_MAX], const char *first, ...) {
  va_list ap;
  const char *currentarg;

  checkpathlen(first);
  strcpy(buf, first);

  va_start(ap, first);
  while (1) {
    currentarg = va_arg(ap, char *);
    if (currentarg == NULL) break;
    errif(strlen(buf) + strlen(currentarg) >= PATH_MAX);
    strcat(buf, currentarg);
  }
  va_end(ap);
}

int cache_get(const char *path, const char hash[32]) {
  int fd;
  supvsr_msg req;
  supvsr_msg res;

  creattool(AT_FDCWD, path, CREATTOOL_DIR, 0766);
  fd = open(path, O_RDONLY);
  if (fd == -1) {
    fprintf(stderr, "Could not access '%s': %s.\n", path, strerror(errno));
    exit(errno);
  }

  req.type = SUPVSRREQ_GET;
  memcpy(req.sha256, hash, 32);
  supvsr_sendmsg(FDI_SUPERVISOR, &req, fd);
  close(fd);

  supvsr_recvmsg(FDI_SUPERVISOR, &res, NULL, 0);
  errif(!(res.sha256[0] == 0 || res.sha256[0] == 1));
  return res.sha256[0];
}

int cache_handleget(supvsr_server *srv, const char hash[32], int obj) {
  char path[PATH_MAX];
  int treeopenedobj;

  cache_mkpath(hash, path);

  treeopenedobj = open_tree(AT_FDCWD, path, OPEN_TREE_CLONE);
  if (treeopenedobj == -1) {
    if (errno == ENOENT) {
      return 1;
    }
    fprintf(stderr, "Could not access '%s': %s.\n", path, strerror(errno));
    exit(errno);
  }
  errif(move_mount(treeopenedobj, "", obj, "", MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH) != 0);
  return 0;
}

int cache_handlequery(supvsr_server *srv, const char hash[32]) {
  struct stat statbuf;
  char path[PATH_MAX];

  cache_mkpath(hash, path);
  errif(stat(cli->cache, &statbuf));
  if (stat(path, &statbuf) == -1) {
    errif(errno != ENOENT);
    return 0;
  }
  return 1;
}

void cachehstr(char buf[NAME_MAX], const char *sha256, const char *name) {
  char *pos = buf;

  strcpy(pos, "sha256_");
  pos += strlen("sha256_");
  pos += base64_encode(hash, pos, 32, 0);
  if (*name == '\0') *pos = '\0';
  else {
    *pos = '_';
    pos++;
    strcpy(pos, name);
  }

  for (char *cpos = buf; ; cpos++) {
    if (*cpos == '\0') break;
    if (*cpos == '/') {
      *cpos = '_';
    }
  }
}

int cache_put(const char *path, const char hash[32]) {
  int fd;
  supvsr_msg req;
  supvsr_msg res;

  fd = open(path, O_RDONLY);
  if (fd == -1) {
    fprintf(stderr, "Could not access '%s': %s.\n", path, strerror(errno));
    exit(errno);
  }

  req.type = SUPVSRREQ_PUT;
  memcpy(req.sha256, hash, 32);
  supvsr_sendmsg(FDI_SUPERVISOR, &req, fd);
  close(fd);

  supvsr_recvmsg(FDI_SUPERVISOR, &res, NULL, 0);
  return 0;
}

int cache_query(const char hash[32]) {
  supvsr_msg req;
  supvsr_msg res;

  req.type = SUPVSRREQ_QUERY;
  memcpy(req.sha256, hash, 32);
  supvsr_sendmsg(FDI_SUPERVISOR, &req, -1);
  
  supvsr_recvmsg(FDI_SUPERVISOR, &res, NULL, 0);
  return res.sha256[0];
}

void calchash(build_args *ba, char hash[32]) {
  SHA256_CTX ctx;
  off_t foffset;
  ssize_t bytesread;
  char rdbuf[1024];

  sha256_init(&ctx);
  sha256_update(&ctx, ba->chunkname, strlen(ba->chunkname));
  
  foffset = lseek(ba->code, 0, SEEK_CUR);
  while (1) {
    bytesread = read(ba->code, rdbuf, 1024);
    assert(bytesread != -1);
    if (bytesread == 0) break;
    sha256_update(&ctx, rdbuf, bytesread);
  }
  lseek(ba->code, foffset, SEEK_SET);

  sha256_final(&ctx, hash);
}

struct timespec calculate_duration(struct timespec start, struct timespec stop) {
    struct timespec result;

    if ((stop.tv_nsec - start.tv_nsec) < 0) {
        // Borrow 1 second from the seconds field
        result.tv_sec = stop.tv_sec - start.tv_sec - 1;
        result.tv_nsec = stop.tv_nsec - start.tv_nsec + 1000000000L;
    } else {
        result.tv_sec = stop.tv_sec - start.tv_sec;
        result.tv_nsec = stop.tv_nsec - start.tv_nsec;
    }

    return result;
}

void copytool(int srcdir, const char *src, int destdir, const char *dest, int flags) {
  struct stat statbuf;
  int srcfd;
  int destfd;
  int dirfd;

  errif(fstatat(srcdir, src, &statbuf, AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH));
  if (S_ISREG(statbuf.st_mode)) {
    if (strcmp(src, "")) {
      srcfd = openat(srcdir, src, O_RDONLY);
    } else {
      srcfd = srcdir;
    }
    errif(srcfd == -1);
    if (strcmp(dest, "")) {
      destfd = openat(destdir, dest, O_WRONLY | O_CREAT, 0666);
    } else {
      destfd = destdir;
    }
    errif(destfd == -1);
    off_t bytesleft = statbuf.st_size;
    while (1) {
      ssize_t bytestransferred = sendfile(destfd, srcfd, NULL, bytesleft);
      errif(bytestransferred == -1);
      if (bytesleft == bytestransferred) {
        break;
      }
      bytesleft -= bytestransferred;
    }
    if (strcmp(src, "")) {
      errif(close(srcfd));
    }
    if (strcmp(dest, "")) {
      errif(close(destfd));
    }
  } else if (S_ISDIR(statbuf.st_mode)) {
    if (!strcmp(src, "")) {
      dirfd = srcdir;
    } else {
      dirfd = openat(srcdir, src, O_RDONLY);
      errif(dirfd == -1);
    }
    DIR *dirstream = fdopendir(dirfd);
    errif(dirstream == NULL);
    if (mkdirat(destdir, dest, 0777) == -1) {
      errif(errno != EEXIST);
    }

    while (1) {
      errno = 0;
      struct dirent *dent = readdir(dirstream);
      if (dent == NULL) {
        if (errno == 0) {
          break;
        }
        errif(1);
      }
      if (strcmp(dent->d_name, ".") == 0) {
        continue;
      }
      if (strcmp(dent->d_name, "..") == 0) {
        continue;
      }
      char newsrc[PATH_MAX];
      char newdest[PATH_MAX];
      if (strlen(src) + 1 + strlen(dent->d_name) > PATH_MAX) {
        errno = ENAMETOOLONG;
        if (closedir(dirstream) == -1) {
          close(dirfd);
          errif(1);
        }
        close(dirfd);
        errif(1);
      }
      if (strlen(dest) + 1 + strlen(dent->d_name) > PATH_MAX) {
        errno = ENAMETOOLONG;
        if (closedir(dirstream) == -1) {
          close(dirfd);
          errif(1);
        }
        close(dirfd);
        errif(1);
      }
      strcpy(newsrc, src);
      if (strcmp(src, "")) {
        strcat(newsrc, "/");
      }
      strcat(newsrc, dent->d_name);
      strcpy(newdest, dest);
      if (strcmp(dest, "")) {
        strcat(newdest, "/");
      }
      strcat(newdest, dent->d_name);
      copytool(srcdir, newsrc, destdir, newdest, flags);
    }
    if (closedir(dirstream) == -1) {
      close(dirfd);
      errif(1);
    }
  } else if (S_ISLNK(statbuf.st_mode)) {
    char tgtpath[PATH_MAX + 1];
    ssize_t bytesplaced = readlinkat(srcdir, src, tgtpath, PATH_MAX + 1);
    if (bytesplaced == -1) {
      errif(1);
    }
    if (bytesplaced == PATH_MAX + 1) {
      errno = ENAMETOOLONG;
      errif(1);
    }
    errif(!strcmp(dest, ""));
    if (symlinkat(tgtpath, destdir, dest) == -1) {
      errif(1);
    }
  } else {
    errno = EINVAL;
    errif(1);
  }
}

void cpyntillptr(const char *ogstr, const char *ptr, const char *buf, size_t bsz) {
  size_t reslen;
  if ((size_t) ptr - ogstr < bsz) {
    strncpy(buf, ogstr, (size_t) ptr - ogstr);
  } else {
    strncpy(buf, ptr - bsz + 1, bsz - 1);
    buf[9] = '\0';
  }
}

void creattool(int dir, const char *path, uint64_t flags, mode_t mode, ...) {
  struct stat sb;
  const char *lastslash;
  char pathbuf[PATH_MAX];
  mode_t updirmode;
  va_list ap;
  int fd;

  errif(!(flags & CREATTOOL_FILE && !(flags & CREATTOOL_DIR) ||
      !(flags & CREATTOOL_FILE) && flags & CREATTOOL_DIR));
  errif(sizeof(pathbuf) <= strlen(path));

  updirmode = mode;
  if (updirmode & S_IRUSR) updirmode |= S_IXUSR;
  if (updirmode & S_IRGRP) updirmode |= S_IXGRP;
  if (updirmode & S_IROTH) updirmode |= S_IXOTH;
  if (flags & CREATTOOL_UPDIRMODE) {
    va_start(ap, mode);
    updirmode = va_arg(ap, mode_t);
    va_end(ap);
  }

  if (flags & CREATTOOL_UPDIRS) {
    lastslash = path;
    while (1) {
      lastslash = strchr(lastslash, '/') + 1;
      if (lastslash == NULL) break;
      if (lastslash == path + 1) continue;
      memcpy(pathbuf, path, (size_t) lastslash - (size_t) path - 2);
      pathbuf[(size_t) lastslash - (size_t) path - 1] = '\0';

      if (fstatat(dir, pathbuf, &sb, 0) == -1) {
        errif(errno != ENOENT);
        errif(mkdirat(dir, pathbuf, updirmode) != 0);
      }
    }
  }

  if (flags & CREATTOOL_FILE) {
    fd = openat(dir, path, O_WRONLY | O_CREAT | (flags & CREATTOOL_EXCL)? O_EXCL : 0, mode);
    errif(fd == -1);
    errif(close(fd) != 0);
  }

  if (flags & CREATTOOL_DIR) {
    if (mkdirat(dir, path, mode) == -1) {
      errif(errno != EEXIST);
      errif(flags & CREATTOOL_EXCL);
    }
  }
}

int errnotostring(lua_State *ls) {
  int givenerrno = luaL_checkinteger(ls, 1);
  lua_pushstring(ls, strerror(givenerrno));
  return 1;
}

const char * fd_luareader(lua_State *L, void *data, size_t *size) {
  ssize_t bytesread = read((size_t) data, fd_luareader_buf, 2048);
  errif(bytesread == -1);
  *size = bytesread;
  return fd_luareader_buf;
}

int fd_luawriter(lua_State *L, const void* p, size_t sz, void *ud) {
  const void *pos = p;
  ssize_t bytes_written;

  if (sz == 0) return 0;

  while (1) {
    bytes_written = write((size_t) ud, pos, sz - (size_t) (pos - p));
    errif(bytes_written == -1);
    pos += bytes_written;
    if (sz - (size_t) (pos - p) == 0) break;
  }
  return 0;
}

int fs_copy(lua_State *L) {
  const char *src = luaL_checkstring(L, 1);
  const char *dest = luaL_checkstring(L, 2);

  copytool(AT_FDCWD, src, AT_FDCWD, dest, 0);

  return 0;
}

int fslib_direntries(lua_State *luast) {
  const char *path = luaL_checkstring(luast, 1);

  lua_newtable(luast);
  luaL_setmetatable(luast, "stdtable");
  DIR *dir = opendir(path);
  if (dir == NULL) {
    luaL_error(luast, "Could not opendir '%s': %s", path, strerror(errno));
  }

  int entord = 0;
  while(1) {
    errno = 0;
    struct dirent* dent = readdir(dir);
    if (dent == NULL) {
      if (errno != 0) {
        luaL_error(luast, "Could not readdir: %s", strerror(errno));
      }
      break;
    }
    entord++;
    lua_pushstring(luast, dent->d_name);
    lua_seti(luast, -2, entord);
  }

  return 1;
}

int fs_mkdir(lua_State *L) {
  const char *path = luaL_checkstring(L, 1);
  mode_t mode = 0777;
  if (lua_gettop(L) > 1) {
    mode = luaL_checkinteger(L, 2);
  }

  if (mkdir(path, mode) == -1) {
    pusherrno(L, errno);
    lua_error(L);
  }

  return 0;
}

int fs_rename(lua_State *L) {
  const char *oldpath = luaL_checkstring(L, 1);
  const char *newpath = luaL_checkstring(L, 2);

  if (rename(oldpath, newpath) == -1) {
    pusherrno(L, errno);
    lua_error(L);
  }

  return 0;
}

#define putindent for (int i = 0; i < indent; i++) pos[i] = ' '; \
                               pos += indent;
size_t getltblstr(lua_State *L, char *buf, int flags) {
  const char *key;
  const char *valstr;
  size_t valstrlen;
  char *pos = buf;
  int indent;
  double fpnum;
  int isfirst = 1;

  if (flags >= 0) indent = 0;
  else indent = -flags;

  pos[0] = '{';
  pos[1] = '\n';
  indent += 2;
  pos += 2;
  lua_pushnil(L);
  while (lua_next(L, -2) != 0) {
    if (!isfirst) {
      *pos = ',';
      pos++;
    } else {
      isfirst = 0;
    }
    
    key = lua_tostring(-2);
    errif(key == NULL);
    errif(key[0] == '\0');
    errif(lnamespn(key) != strlen(key));
    putindent
    strcpy(pos, key);
    pos += strlen(key);
    pos[0] = ' ';
    pos[1] = '=';
    pos[2] = ' ';
    pos += 3;
    switch (lua_type(L, -1)) {
      case LUA_TNIL:
        pos[0] = 'n';
        pos[1] = 'i';
        pos[2] = 'l';
        pos += 3;
        break;
      case LUA_TBOOLEAN:
        if (lua_toboolean(L, -1)) {
          pos[0] = 't';
          pos[1] = 'r';
          pos[2] = 'u';
          pos[3] = 'e';
          pos += 4;
        } else {
          pos[0] = 'f';
          pos[1] = 'a';
          pos[2] = 'l';
          pos[3] = 's';
          pos[4] = 'e';
          pos += 5;
        }
        break;
      case LUA_TSTRING:
        valstr = lua_tostring(L, -1);
        valstrlen = strlen(valstr);
        *pos = '\'';
        pos++;
        for (char *ptr = valstr; ptr < valstr + valstrlen; ptr++) {
          if (*ptr == '\'') {
            pos[0] = '\\';
            pos[1] = '\'';
            pos += 2;
          } else if (*ptr == '\\) {
            pos[0] = '\\';
            pos[1] = '\\';
            pos += 2;
          } else if (*ptr == '\n') {
            pos[0] = '\\';
            pos[1] = 'n';
            pos += 2;
          } else if (*ptr == '\r') {
            pos[0] = '\\';
            pos[1] = 'r';
            pos += 2;
          } else if (*ptr == '\t') {
            pos[0] = '\\';
            pos[1] = 't';
            pos += 2;
          } else if (*ptr >= 0x01 && *ptr <= 0x1f) {
            pos[0] = '\\';
            pos[1] = 'x';
            if (*ptr % 16 > 9) pos[2] = 'a' + *ptr % 16 - 10;
            else pos[2] = '0' + *ptr % 16;
            if (*ptr / 16 > 9) pos[3] = 'a' + *ptr / 16 - 10;
            else pos[3] = '0' + *ptr / 16;
            pos += 3;
          } else {
            *pos = *ptr
          }
        }
        *pos = '\'';
        pos++;
        break;
      case LUA_TNUMBER:
        fpnum = lua_tonumber(L, -1);
        pos += sprintf(pos, "%g", fpnum);
        break;
      case LUA_TTABLE:
        pos += getltblstr(L, pos, -indent);
        break;
      default:
        errno = EINVAL;
        errif(1);
    }
    *pos = '\n';
    pos++;
    lua_pop(L, 1);
  }
  *pos = '}';
  pos++;
  return (size_t) (pos - buf);
}

int lapi_bindsrc(lua_State *L) {
  const char *target;
  struct stat st;
  mode_t file_type;
  mode_t permissions;
  int opentgt;

  target = luaL_checkstring(L, 1);

  errif(fstat(FDI_SRC, &st) == -1);
  file_type = st.st_mode & S_IFMT;
  permissions = 0644;
  if (S_ISDIR(st.st_mode)) {
    errif(mkdir(target, 0755) == -1);
  } else {
    errif(mknod(target, file_type | permissions, st.st_rdev) == -1);
  }

  opentgt = open(target, O_RDONLY);

  errif(move_mount(FDI_SRC, "", opentgt, "", MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH) == -1);
  return 0;
}

int lapi_build(lua_State *L) {
  build_args bargs;
  lua_Debug ar;

  if (lua_getfield(L, 1, "src") == LUA_TNIL) {
    bargs.srcfd = -2;
  } else {
    fprintf(stderr, "Type: %s", lua_type(L, -1));
    errif(!lua_isstring(L, -1));
    bargs.srcfd = open_tree(AT_FDCWD, luaL_checkstring(L, -1), OPEN_TREE_CLONE);
  }
  lua_getfield(L, 1, "dest");
  errif(!lua_isstring(L, -1));
  bargs.destpath = luaL_checkstring(L, -1);
  lua_getfield(L, 1, "ws");
  errif(!lua_isstring(L, -1));
  bargs.workspace = luaL_checkstring(L, -1);
  luaL_checktype(L, 2, LUA_TFUNCTION);
  lua_pushvalue(L, 2);
  errif(lua_getinfo(L, ">S", &ar) == 0);
  bargs.chunkname = ar.short_src;

  lua_pushvalue(L, 2);
  bargs.code = memfd_create("bargscode", 0);
  errif(bargs.code == -1);
  luadumpfd(bargs.code, L);
  errif(lseek(bargs.code, 0, SEEK_SET) == -1);

  build(&bargs);

  if (bargs.srcfd != -2) errif(close(bargs.srcfd) != 0);
  errif(close(bargs.code) != 0);
  return 0;
}

int lapi_setdest(lua_State *L) {
  const char *dest;

  dest = luaL_checkstring(L, 1);
  strcpy(destpath, dest);
  return 0;
}

size_t lnamespn(const char *str) {
  const char *pos = str;
  if (!(isalpha(*pos) || *pos == '_')) return 0;
  if (
      !strcmp(pos, "and") ||
      !strcmp(pos, "false") ||
      !strcmp(pos, "in") ||
      !strcmp(pos, "return") ||
      !strcmp(pos, "break") ||
      !strcmp(pos, "for") ||
      !strcmp(pos, "local") ||
      !strcmp(pos, "then") ||
      !strcmp(pos, "do") ||
      !strcmp(pos, "function") ||
      !strcmp(pos, "nil") ||
      !strcmp(pos, "true") ||
      !strcmp(pos, "else") ||
      !strcmp(pos, "global") ||
      !strcmp(pos, "not") ||
      !strcmp(pos, "until") ||
      !strcmp(pos, "elseif") ||
      !strcmp(pos, "goto") ||
      !strcmp(pos, "or") ||
      !strcmp(pos, "while") ||
      !strcmp(pos, "end") ||
      !strcmp(pos, "if") ||
      !strcmp(pos, "repeat")
  ) return 0;
  pos++;
  while (isalnum(*pos) || *pos == '_') pos++;
  return (size_t) (pos - str);
}

void *lnullunwrp(void *value) {
  if (value == luanull) {
    return NULL;
  }
  return value;
}

const void *lnullwrp(void *value) {
  if (value == NULL) {
    return luanull;
  }
  return value;
}

int luaapi_fslib_register(lua_State *luast) {
  luaL_newlib(luast, luaapi_fslib);
  lua_setglobal(luast, "fs");
}

int luaapi_init(lua_State *ls) {
  luaL_newmetatable(ls, "stdtable");
  lua_pushcfunction(ls, &stdtbltostring);
  lua_setfield(ls, -2, "__tostring");
  lua_pop(ls, 1);

  luaL_newmetatable(ls, "errno");
  lua_pushcfunction(ls, &errnotostring);
  lua_setfield(ls, -2, "__tostring");
  lua_pop(ls, 1);

  lua_pushcfunction(ls, &lapi_build);
  lua_setglobal(ls, "build");

  lua_pushcfunction(ls, &lapi_bindsrc);
  lua_setglobal(ls, "bindsrc");

  lua_pushcfunction(ls, &lapi_setdest);
  lua_setglobal(ls, "setdest");
}

void luadumpfd(int fd, lua_State *L) {
  lua_dump(L, fd_luawriter, (void *) (size_t) fd, 0);
}

void lualoadfd(int fd, char *chunkname, lua_State *L) {
  int status = lua_load(L, &fd_luareader, (void *) (size_t) fd, chunkname, NULL);
  if (status != LUA_OK) {
    fprintf(stderr, "%s\n", lua_tostring(L, -1));
    exit(-1);
  }
}

int newsupervisorfd(void) {
  int newsck;
  supvsr_msg req;
  supvsr_msg res;

  req.type = SUPVSRREQ_NEWSCK;
  supvsr_sendmsg(FDI_SUPERVISOR, &req, -1);

  supvsr_recvmsg(FDI_SUPERVISOR, &res, &newsck, 0);

  return newsck;
}

uint32_t main(uint32_t argc, char* argv[]) {
  int32_t opt;
  int stderr_fd;
  build_args bargs;

  stderr_fd = STDERR_FILENO;
  errif(fcntl(stderr_fd, F_GETFL) == -1);
  for (int fd = 3; fd <= FDI_LASTI; fd++) {
    if (fd == stderr_fd) continue;
    errif(dup2(stderr_fd, fd) == -1);
  }

  sdata = malloc(sizeof(svsr_data));
  errif(sdata == NULL);
  strcpy(sdata.cache, "plcache");

  bargs.srcs[0] = { k = "\0" };
  bargs.dests[0] = { k = "\0" };
  bargs.ws = "plws";

  while(1){
    opt = getopt(argc, argv, "s:d:w:c:x:");
    if (opt == 's') {
      parse_pents(bargs.srcs, 10, optarg);
      continue;
    }
    if (opt == 'd') {
      parse_pents(bargs.dests, 10, optarg);
      continue;
    }
    if (opt == 'w') {
      checkpathlen(optarg);
      strcpy(bargs.ws, optarg);
      continue;
    }
    if (opt == 'c') {
      checkpathlen(optarg);
      strcpy(sdata->cache, optarg);
      continue;
    }
    break;
  }

  if (optind - argc < 1) {
    fprintf(stderr, "Missing argument <build_script>\n");
    exit(-1);
  }
  if (optind - argc > 1) {
    fprintf(stderr, "Too many arguments.\n");
    exit(-1);
  }
  strcpy(bargs.script, argv[optind]);

  errif(unshare(CLONE_NEWUSER | CLONE_NEWNS) != 0);

  startsupervisorserver();

  for (int i = 0; i < 10; i++) bargs.dests[i].v.fd = DSTMD_COPY;
  build(&bargs);

  exit(0);
}

uint32_t mkdirs(const char *path, mode_t mode) {
  const char *lastslashpos = path;
  char currentpath[PATH_MAX];
  while (1) {
    lastslashpos = strchr(lastslashpos, '/');
    if (lastslashpos == NULL) {
      strcpy(currentpath, path);
    } else {
      strncpy(currentpath, path, (int32_t) (lastslashpos - path));
      currentpath[(int32_t) (lastslashpos - path)] = '\0';
    }

    if (strcmp(currentpath, "") != 0) {
      struct stat finfo;
      if (stat(currentpath, &finfo) == -1) {
        if (errno != ENOENT) {
          return -1;
        } else {
          if (mkdir(currentpath, mode) == -1) {
            return -1;
          }
        }
      } else {
        if (!S_ISDIR(finfo.st_mode)) {
          errno = ENOTDIR;
          return -1;
        }
      }
    }
    
    if (lastslashpos == NULL) {
      break;
    }
    lastslashpos++;
  }
  return 0;
}

int openthisexe() {
  int exefd;
  supvsr_msg req;
  supvsr_msg res;

  req.type = SUPVSRREQ_OPENEXE;
  supvsr_sendmsg(FDI_SUPERVISOR, &req, -1);

  supvsr_recvmsg(FDI_SUPERVISOR, &res, &exefd, 0);
  return exefd;
}

ssize_t parseluanum(const char *str, double *rsl) {
  const char *pos = str;
  char buf[128];
  char *endptr;
  //size_t nskip;
  //int64_t intpart = 0;
  //int64_t fracpart = 0;
  //int64_t expo = 0;

  if (*pos != '\0' && *pos == '0' && pos[1] == 'x') {
    pos += 2;
    nskip = strspn(pos, hexdec);
    //for (size_t off = 0; off < nskip; off++) {
      //if (pos[off] >= '0' && pos[off] <= '9') intpart += pos[off] - '0';
      //else if (pos[off] >= 'a' && pos[off] <= 'f') intpart += pos[off] - 'a' + 10;
      //else if (pos[off] >= 'A' && pos[off] <= 'F') intpart += pos[off] - 'A' + 10;
      //intpart *= 16;
    //}
    pos += nskip;
    if (*pos == '.') {
      pos++;
      nskip = strspn(pos, hexdec);
      //for (size_t off = 0; off < nskip; off++) {
        //if (pos[off] >= '0' && pos[off] <= '9') fracpart += pos[off] - '0';
        //if (pos[off] >= 'a' && pos[off] <= 'f') fracpart += pos[off] - 'a' + 10;
        //if (pos[off] >= 'A' && pos[off] <= 'F') fracpart += pos[off] - 'A' + 10;
        //fracpart *= 16;
      //}
      pos += nskip;
    }
    if (*pos == 'p' || *pos == 'P') {
      pos++;
      if (*pos == '+' || *pos == '-') pos++;
      nskip = strspn(pos, hexdec);
      //for (size_t off = 0; off < nskip; off++) {
        //if (pos[off] >= '0' && pos[off] <= '9') expo += pos[off] - '0';
        //if (pos[off] >= 'a' && pos[off] <= 'f') expo += pos[off] - 'a' + 10;
        //if (pos[off] >= 'A' && pos[off] <= 'F') expo += pos[off] - 'A' + 10;
        //expo *= 16;
      //}
      //if (*(pos - 1) == '-') expo = -expo;
      pos += nskip;
    }
  } else {
    nskip = strspn(pos, "0123456789");
    //for (size_t off = 0; off < nskip; off++) {
      //intpart += pos[off] - '0';
      //intpart *= 10;
    //}
    pos += nskip;
    if (*pos == '.') {
      pos++;
      nskip = strspn(pos, "0123456789");
      //for (size_t off = 0; off < nskip; off++) {
        //fracpart += pos[off] - '0';
        //fracpart *= 10;
      //}
      pos += nskip;
    }
    if (*pos == 'e' || *pos == 'E') {
      pos++;
      if (*pos == '+' || *pos == '-') pos++;
      nskip = strspn(pos, "0123456789");
      //for (size_t off = 0; off < nskip; off++) {
        //expo += pos[off] - '0';
        //expo *= 10;
      //}
      //if (*(pos - 1) == '-') expo = -expo;
      pos += nskip;
    }
  }

  if (rsl != NULL) {
    if ((size_t) (str - pos) > 127) {
      errno = ERANGE;
      return -1;
    }
    errno = 0;
    *rsl = strtod(str, &endptr);
    if (errno != 0) return -1;
  }

  return (ssize_t) (str - pos);
}

size_t parselstr(const char *str, char *dest, size_t *nwrt, size_t destsz) {
  const char *pos = str;
  char *dpos = dest;
  size_t nskip;
  size_t nskip2;
  
  if (!(*pos == '\'' || *pos == '\"')) return 0;
  if (dest != NULL) {
    errife(dpos == dest + destsz, ERANGE);
    *dpos = *pos;
    dpos++;
  }
  pos++;
  while (*pos != str[0]) {
    if (*pos == '\n') goto ret;
    if (*pos != '\\') {
      if (dest != NULL) {
        errife(dpos == dest + destsz, ERANGE);
        *dpos = *pos;
        dpos++;
      }
      pos++;
      continue;
    }
    pos++;
    if (
        *pos == 'a' ||
        *pos == 'b' ||
        *pos == 'f' ||
        *pos == 'n' ||
        *pos == 'r' ||
        *pos == 't' ||
        *pos == 'v' ||
        *pos == '\\' ||
        *pos == '\"' ||
        *pos == '\'' ||
        *pos == '\n'
    ) {
      if (dest != NULL) {
        errife(dpos == dest + destsz, ERANGE);
        switch (*pos) {
          case 'a':
           *pos = '\a';
           break;
          case 'b':
           *pos = '\b';
           break;
          case 'f':
           *pos = '\f';
           break;
          case 'n':
           *pos = '\n';
           break;
          case 'r':
           *pos = '\r';
           break;
          case 't':
           *pos = '\t';
           break;
          case 'v':
           *pos = 'v';
           break;
          case '\\':
           *pos = '\\';
           break;
          case '\"':
           *pos = '\"';
           break;
          case '\'':
           *pos = '\'';
           break;
          case '\n':
           *pos = '\n';
           break;
        }
        dpos++;
      }
      pos++;
      continue;
    }
    if (*pos == '\r') {
      pos++;
      if (*pos == '\n') pos++;
      if (dest != NULL) {
        errife(dpos >= dest + destsz - 2, ERANGE);
        *dpos = '\r';
        dpos[1] = '\n';
        dpos += 2;
      }
      continue;
    }
    if (*pos == 'z') {
      pos += strspn(pos, LUAWSPACES);
      continue;
    }
    if (*pos == 'x') {
      pos++;
      if (strspn(pos, hexdec) < 2) goto ret;
      if (dest != NULL) {
        errife(dpos == dest + destsz, ERANGE);
        strbuf[0] = pos[0];
        strbuf[1] = pos[1];
        strbuf[2] = '\0';
        *dpos = (char) strtol(strbuf, 16);
        dpos++;
      }
      pos += 2;
      continue;
    }
    if ((nskip = strspn(pos, "0123456789")) >= 1) {
      nskip = nskip > 3? 3 : nskip;
      if (dest != NULL) {
        errife(dpos == dest + destsz, ERANGE);
        memcpy(strbuf, pos, nskip);
        strbuf[nskip] = '\0';
        *dpos = (char) strtol(strbuf, 10);
        dpos++;
      }
      pos += nskip;
      continue;
    }
    if (*pos == 'u') {
      pos++;
      if (*pos != '{') goto ret;
      pos++;
      if ((nskip = strspn(pos, hexdec)) == 0) goto ret;
      if (dest != NULL) {
        errife(dpos >= dest + destsz - 4, ERANGE);
        memcpy(strbuf, pos, nskip);
        strbuf[nskip] = '\0';
        nskip2 = write_utf8_codepoint(dpos, strtol(strbuf, 16));
        errife(nskip2 == 0, EINVAL);
        dpos += nskip2;
      }
      pos += nskip;
      if (*pos != '}') goto ret;
      continue;
    }
    goto ret;
  }
ret:
  if (nwrt != NULL) *nwrt = (size_t) (dpos - dest);
  return (size_t) (pos - str);
}

int parse_pents(pathent *ents, int bufsz, const char *str) {
  int n = 0;
  const char *ptr = str;
  char strbuf[10];
  pathent *pent = ents;
  size_t nsz;
  char *pathpos;

  while (1) {
    if (*ptr == '\0') break;
    n++;
    errife(n >= bufsz, ERANGE);
    nsz = lnamespn(ptr);
    if (nsz == 0 && n != 1) {
      cpyntillptr(str, ptr, strbuf, 10);
      fprintf(stderr, "'%s' <-- expected lua name ([a-zA-Z_][a-zA-Z0-9_]*).\n", strbuf);
      exit(-1);
    }
    strnpcy(pent->k, ptr, nsz);
    pos += nsz;
    if (nsz != 0) {
      if (*ptr != '=') {
        cpyntillptr(str, ptr, strbuf, 10);
        fprintf(stderr, "'%s' <-- expected '='.\n", strbuf);
        exit(-1);
      }
      ptr++;
    }
    pathpos = pent->v->path;
    while (1) {
      if (*ptr != ';') {
        errife(pathpos - pent->v->path >= sizeof(pent->v->path), ERANGE);
        *pathpos = *ptr;
        pathpos++;
        ptr++;
      } else {
        ptr++;
        if (*ptr == ';') {
          errife(pathpos - pent->v->path >= sizeof(pent->v->path), ERANGE);
          *pathpos = ';';
          pathpos++;
          ptr++;
        } else if (*ptr == ':') {
          ptr++;
        }
        *pathpos = '\0';
        break;
      }
    }
    pent->v->fd = -1;
    if (nsz == 0) {
      if (*ptr != '\0') {
        cpyntillptr(str, ptr, strbuf, 10);
        fprintf(stderr, "'%s' <-- expected the end there.\n", strbuf);
        exit(-1);
      }
      pent[1].k = "\0a";
      break;
    }
    pent = &pent[1];
  }
  return n;
}

ssize_t parsetblstr(const char *ts, char *binrep, size_t binrepsz, size_t *nwrt, char *emsg) {
  const char *pos = ts;
  char *binpos = binrep;
  size_t nws;
  const char *lastwspos = NULL;
  const char *lastnonwspos = NULL;
  size_t nskip;
  size_t nskip2;
  char strbuf[10];
  double fpnum;

  pos += strspn(pos, LUAWSPACES);
  if (*pos != '{') {
    cpyntillptr(str, ptr, strbuf, 10);
    if (emsg != NULL) sprintf(emsg, "'%s' <-- expected '{'.");
    return -1;
  }
  pos++;
field:
  pos += strspn(pos, LUAWSPACES);
  nskip = lnamespn(pos);
  if (nskip == 0) {
    pos += strspn(pos, LUAWSPACES);
    if (*pos != '}') {
      cpyntillptr(str, ptr, strbuf, 10);
      if (emsg != NULL) sprintf(emsg, "'%s' <-- expected '}'.");
      return -1;
    }
    goto ret;
  }
  errife(binpos + nskip + 1> binrep + binrepsz, ERANGE);
  *binpos = 'K';
  binpos++;
  strncpy(binpos, pos, nskip);
  binpos += nskip;
  pos += nskip;
  pos += strspn(pos, LUAWSPACES);
  if (*pos != '=') {
    cpyntillptr(str, ptr, strbuf, 10);
    if (emsg != NULL) sprintf(emsg, "'%s' <-- expected '='.");
    return -1;
  }
  pos += strspn(pos, LUAWSPACES);
  errife((size_t) (binpos - binrep) == binrepsz, ERANGE);
  *binpos = 'V';
  binpos++;
  if (!strcmp(pos, "nil")) {
    pos += 3;
    errife((size_t) (binpos - binrep) == binrepsz, ERANGE);
    *binpos = '-';
    binpos++;
  } else if (!strcmp(pos, "false")) {
    pos += 5;
    errife((size_t) (binpos - binrep) == binrepsz, ERANGE);
    *binpos = '0';
    binpos++;
  } else if (!strcmp(pos, "true")) {
    pos += 4;
    errife((size_t) (binpos - binrep) == binrepsz, ERANGE);
    *binpos = '1';
    binpos++;
  } else if (isdigit(*pos)) {
    nskip = parseluanum(pos, &fpnum);
    if (nskip == -1) {
      if (fpnum == HUGE_VAL || fpnum == -HUGE_VAL) {
        cpyntillptr(str, ptr, strbuf, 10);
        if (emsg != NULL) sprintf(emsg, "'%s' <-- that floating-point overflows in 64bit.");
        return -1;
      } else {
        cpyntillptr(str, ptr, strbuf, 10);
        if (emsg != NULL) sprintf(emsg, "'%s' <-- that floating-point underflows in 64bit.");
        return -1;
      }
    }
    errife(binpos + 9 > binrep + binrepsz, ERANGE);
    *binpos = 'n';
    binpos++;
    memcpy(binpos, &fpnum, 8);
    binpos += 8;
    pos += nskip;
    binpos++;
  } else if (*pos == '\'' || *pos = '\"') {
    errife(binpos + 9 > binrep + binrepsz, ERANGE);
    *binpos = 's';
    binpos++;
    nskip = parselstr(pos, &binpos, &nskip2, binrep + binrepsz - binpos);
    pos += nskip;
    binpos += nskip2;
  } else if (*pos == '{') {
    errife(binpos + 9 > binrep + binrepsz, ERANGE);
    *binpos = 't';
    binpos++;
    nskip = checkltblstr(pos, binpos, binrep + binrepsz - binpos, &nskip2, emsg);
    if (nskip2 == -1) return -1;
    binpos += nskip2;
    pos += nskip;
  } else return -1;
  pos += strspn(pos, LUAWSPACES);
  if (!(*pos == ',' || *pos == ';')) {
    pos += strspn(pos, LUAWSPACES);
    if (*pos != '}') return 0;
    goto ret;
  }
  goto field;
ret:
  errife((size_t) (binpos - binrep) == binrepsz, ERANGE);
  *binpos = 'R';
  binpos++;
  *nwrt = (size_t) (binpos - binrep);
  return (ssize_t) (pos - ts);
}

int pusherrno(lua_State *ls, int givenerrno) {
  lua_pushinteger(ls, givenerrno);
  luaL_setmetatable(ls, "errno");
}

int rmr(const char *path, int flags) {
  struct stat statbuf;
  if (lstat(path, &statbuf) == -1 && !(flags & RMR_IFEXISTS && errno = ENOENT)) {
    return -1;
  }
  if (S_ISREG(statbuf.st_mode) || S_ISLNK(statbuf.st_mode)) {
    if (unlink(path) == -1) {
      return -1;
    }
  } else if (S_ISDIR(statbuf.st_mode)) {
    DIR *dstream = opendir(path);
    if (dstream == NULL) {
      return -1;
    }
    while (1) {
      errno = 0;
      struct dirent *dent = readdir(dstream);
      if (dent == NULL) {
        if (errno == 0) {
          break;
        }
        if (closedir(dstream) == -1) {
          return -1;
        }
        return -1;
      }

      if (strcmp(dent->d_name, ".") == 0 ||
          strcmp(dent->d_name, "..") == 0) {
        continue;
      }

      char newpath[PATH_MAX];
      if (strlen(path) + 1 + strlen(dent->d_name) >= PATH_MAX) {
        errno = ENAMETOOLONG;
        if (closedir(dstream) == -1) {
          return -1;
        }
        return -1;
      }
      strcpy(newpath, path);
      strcat(newpath, "/");
      strcat(newpath, dent->d_name);

      if (rmr(newpath, flags & ~RMR_KEEPCONTAINER & ~RMR_IFEXISTS) == -1) {
        if (closedir(dstream) == -1) {
          return -1;
        }
        return -1;
      }
    }
    if (!(flags & RMR_KEEPCONTAINER) && rmdir(path) == -1) {
      if (closedir(dstream) == -1) {
        return -1;
      }
      return -1;
    }
    if (closedir(dstream) == -1) {
      return -1;
    }
  } else {
    errno = ENOTSUP;
    return -1;
  }
  return 0;
}

int startassupervisor() {
  char dpathbuf[PATH_MAX];
  build_args bargs;
  char cachepath[PATH_MAX];

  errif(unshare(CLONE_NEWUSER | CLONE_NEWNS) != 0);

  startsupervisorserver();

  if (strcmp(cli->src, "")) {
    bargs.srcfd = open_tree(AT_FDCWD, cli->src, OPEN_TREE_CLONE);
    errif(bargs.srcfd == -1);
  } else {
    bargs.srcfd = -2;
  }
  bargs.destpath = NULL;
  bargs.code = open(cli->script, O_RDONLY);
  errif(bargs.code == -1);
  bargs.workspace = cli->workspace;
  bargs.chunkname = cli->script;
  build(&bargs);

  cache_mkpath(bargs.hash, cachepath);
  copytool(AT_FDCWD, cachepath, AT_FDCWD, cli->dest, 0);
  exit(0);
}

int startsupervisorserver() {
  struct epoll_event event;
  int sckpair[2];
  supvsr_server *srv = malloc(sizeof(supvsr_server));

  creattool(AT_FDCWD, cli->cache, CREATTOOL_DIR, 0777);

  srv->fds = NULL;
  arraddnptr(srv->fds, SUPVSRFDI_LAST + 1);
  srv->fds[SUPVSRFDI_EPOLL] = epoll_create(1);
  errif(srv->fds[SUPVSRFDI_EPOLL] == -1);

  errif(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sckpair) != 0);
  arrput(srv->fds, sckpair[0]);
  errif(dup2(sckpair[1], FDI_SUPERVISOR) == -1);
  errif(close(sckpair[1]) != 0);
  event.data.u32 = arrlen(srv->fds) - 1;
  event.events = EPOLLIN | EPOLLRDHUP;
  errif(epoll_ctl(srv->fds[SUPVSRFDI_EPOLL], EPOLL_CTL_ADD, sckpair[0], &event) != 0);

  errno = pthread_create(&srv->thread, NULL, &supervisor_handler, srv);
  errif(errno != 0);
  return 0;
}

int stdtbltostring(lua_State *ls) {
  luaL_checktype(ls, 1, LUA_TTABLE);
  luaL_Buffer b;
  luaL_buffinit(ls, &b);
  luaL_addstring(&b, "{");
  int index = 1;
  while (1) {
    int valtype = lua_geti(ls, 1, index);
    if (valtype == LUA_TNIL) {
      break;
    }
    const char *hmnrdbl = lua_tolstring(ls, -1, NULL);
    if (index > 1) {
      luaL_addstring(&b, ", ");
    }
    luaL_addstring(&b, hmnrdbl);
    lua_pop(ls, 1);
    index++;
  }
  luaL_addstring(&b, "}");
  luaL_pushresult(&b);
  return 1;
}

void* supervisor_handler(void *arg) {
  struct epoll_event event;
  struct epoll_event eventtoregister;
  int fdnum;
  svsr_msg req;
  svsr_msg res;
  int sckpair[2];
  char path[PATH_MAX];
  int openfile;
  int dtchmnt;
  char name[NAME_MAX];
  struct statx statxbuf;
  size_t index;
  struct mount_attr mattr;

  memset(&req, 0, sizeof(req));
  memset(&res, 0, sizeof(res));

  while (1) {
    fdnum = epoll_wait(srv->fds[SUPVSRFDI_EPOLL], &event, 1, -1);
    if (fdnum == -1 && errno == EINTR) continue;
    errif(fdnum == -1);
    errif(fdnum != 1);

    svsrmsg_recv(srv->fds[event.data.u32], &req);
    if (req.flags & SREQ_SHUTDOWN) {
      errif(epoll_ctl(srv->fds[SUPVSRFDI_EPOLL], EPOLL_CTL_DEL, srv->fds[event.data.u32], NULL) != 0);
      errif(close(srv->fds[event.data.u32]) != 0);
      arrdel(srv->fds, event.data.u32);
      continue;
    }

    switch (req.type) {
      case SREQ_NEWSCK:
        errif(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sckpair) != 0);
        arrput(srv->fds, sckpair[0]);
        eventtoregister.data.u32 = arrlen(srv->fds) - 1;
        eventtoregister.events = EPOLLIN | EPOLLRDHUP;
        errif(epoll_ctl(srv->fds[SUPVSRFDI_EPOLL], EPOLL_CTL_ADD, sckpair[0], &eventtoregister) != 0);

        res.type = SREQ_NEWSCK;
        res.fd = sckpair[1];
        supvsr_sendmsg(srv->fds[event.data.u32], &res);
        errif(close(sckpair[1]) != 0);
      case SREQ_PUT:
        if (req.flags & SREQ_MOUNTFD && !(req.flags & SREQ_ISTHERE)) {
          errife(req.flags & SREQ_REGFILE && req.flags & SREQ_DIR, EINVAL);
          errife(!(req.flags & SREQ_REGFILE) && !(req.flags & SREQ_DIR, EINVAL));
          cachehstr(name, req.hash, req.name);
          buildpath(path, sdata->cache, "/", name, ".lock", NULL);
          openfile = open(path, O_WRONLY | O_CREAT | O_EXCL);
          errif(openfile == -1);
          errif(close(openfile) == -1);
          buildpath(path, sdata->cache, "/", name, NULL);
          errif(rmr(path, RMR_IFEXISTS) == -1);
          if (req.flags & SREQ_DIR) {
            errif(mkdir(path, 0755) == -1);
          } else {
            openfile = open(path, O_WRONLY | O_CREAT | O_EXCL, 0644);
            errif(openfile == -1);
            errif(close(openfile));
          }
          dtchmnt = open_tree(AT_FDCWD, path, OPEN_TREE_CLONE);
          errif(dtchmnt == -1);
          errife(sdata->cmnt_tbl[CMNT_MAX - 2].mntid == 0, ERANGE);
          errif(statx(dtchmnt, "", AT_EMPTY_PATH, STATX_MNT_ID_UNIQUE, &statxbuf) == -1);
          sdata->cmnt_tbl[CMNT_MAX - 2].mntid = staxbuf.stx_mnt_id;
          memcpy(sdata->cmnt_tbl[CMNT_MAX - 2].hash, req.hash, 32);
          strcpy(sdata->cmnt_tbl[CMNT_MAX - 2].name, req.name);
          sdata->cmnt_tbl[CMNT_MAX - 1].mntid = 0;
          res.type = SVSRREQ_PUT;
          res.fd = dtchmnt;
          supvsrmsg_send(srv->fds[event.data.u32], &res);
          errif(close(dtchmnt) == -1);
        } else if (req.flags & SREQ_MOUNTFD && req.flags & SREQ_ISTHERE) {
          errif(statx(req.fd, "", at_empty_path, statx_ino | statx_mnt_id_unique | statx_mode, &statxbuf) == -1);
          for (index = 0; index < cmnt_max; index++) {
            if (sdata->cmnt_tbl[index].mntid == 0) {
              index = cmnt_max;
              break;
            }
            if (statxbuf.stx_mnt_id == sdata->cmnt_tbl[index].mntid) {
              break;
            }
          }
          errife(index == CMNT_MAX, ENODATA);
          memset(&mattr, 0, sizeof(mattr));
          mattr.attr_set = mount_attr_rdonly;
          errif(mount_setattr(req.fd, "", at_empty_path, &mattr, sizeof(mattr)) == -1);
          errif(close(req.fd) == -1);
          cachehstr(name, sdata->cmnt_tbl[index].sha256, sadata->cmnt_tbl[index].name);
          buildpath(path, sdata->cache, "/", name, ".lock", NULL);
          errif(unlink(path) == -1);
          for (; index < cmnt_max; index++) {
            if (sdata->cmnt_tbl[index].lock == -1) break;
            memcpy(&sdata->cmnt_tbl[index], &sdata->cmnt_tbl[index + 1], sizeof(sdata->cmnt_tbl[index]));
          }
          res.type = SVSRREQ_PUT;
          res.fd = -1;
          supvsrmsg_send(srv->fds[event.data.u32], &res);
        } else {
          cachehstr(req.hash, name);
          buildpath(path, sdata->cache, "/", name, ".lock", NULL);
          openfile = open(path, O_WRONLY | O_CREAT | O_EXCL, 0644);
          errif(openfile == -1);
          errif(close(openfile) == -1);
          buildpath(path, sdata->cache, "/", name, NULL);
          errif(rmr(path, RMR_IFEXISTS) == -1);
          copytool(req.fd, "", AT_FDCWD, path, 0);
          errif(close(req.fd) == -1);
          buildpath(path, sdata->cache, "/", name, ".lock", NULL);
          errif(unlink(path) == -1);
          res.type = SVSRREQ_PUT;
          res.fd = -1;
          supvsrmsg_send(srv->fds[event.data.u32], &res);
        }
      case SUPVSRREQ_GET:

      supvsr_sendmsg(srv->fds[event.data.u32], &res, -1);
    } else if (req.type == SUPVSRREQ_OPENEXE) {
      thisexefd = open(cli->thisexecutable, O_RDONLY);
      errif(thisexefd == -1);

      res.type = SUPVSRREQ_OPENEXE;
      supvsr_sendmsg(srv->fds[event.data.u32], &res, thisexefd);
      errif(close(thisexefd) != 0);
    } else if (req.type == SUPVSRREQ_QUERY) {
      int rslt = cache_handlequery(srv, req.sha256);

      res.type = SUPVSRREQ_QUERY;
      memset(res.sha256, (char) rslt, 32);
      supvsr_sendmsg(srv->fds[event.data.u32], &res, -1);
    }
  }
}

void svsr(svsr_msg *req, svsr_msg *res) {
  svsrmsg_send(FDI_SUPERVISOR, req);
  svsrmsg_recv(FDI_SUPERVISOR, res);
}

void svsrmsg_recv(int sck, svsr_msg *payload) {
  struct cmsghdr *chdr_p;
  struct msghdr hdr;
  struct iovec pl_iov;
  union {
    struct cmsghdr align;
    char buf[CMSG_SPACE(sizeof(int))];
  } cmsg_holder;

  memset(&hdr, 0, sizeof(struct msghdr));
  pl_iov.iov_base = payload;
  pl_iov.iov_len = sizeof(svsr_msg);
  hdr.msg_iov = &pl_iov;
  hdr.msg_iovlen = 1;
  hdr.msg_control = cmsg_holder.buf;
  hdr.msg_controllen = sizeof(cmsg_holder.buf);

  int r = recvmsg(sck, &hdr, 0);
  if (r == 0) payload->flags |= SMSG_SHUTDOWN;
  errife(r != sizeof(supvsr_msg), EMSGSZ);

  chdr_p = CMSG_FIRSTHDR(&hdr);
  if (chdr_p != NULL) memcpy(payload->fd, CMSG_DATA(chdr_p), sizeof(int));
  else payload->fd = -1;
}

void svsrmsg_send(int sck, svsr_msg *payload) {
  union {
    char buf[CMSG_SPACE(sizeof(int))];
    struct cmsghdr align_to_me;
  } chdr_holder;
  struct cmsghdr *chdr_p;
  struct msghdr hdr;
  struct iovec pl_iov;

  memset(&hdr, 0, sizeof(struct msghdr));

  pl_iov.iov_base = payload;
  pl_iov.iov_len = sizeof(svsr_msg);
  hdr.msg_iov = &pl_iov;
  hdr.msg_iovlen = 1;

  if (payload->fd >= 0) {
    payload->fd = -2;
    hdr.msg_control = chdr_holder.buf;
    hdr.msg_controllen = sizeof(chdr_holder.buf);
    chdr_p = CMSG_FIRSTHDR(&hdr);
    chdr_p->cmsg_level = SOL_SOCKET;
    chdr_p->cmsg_type = SCM_RIGHTS;
    chdr_p->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(chdr_p), &payload->fd, sizeof(int));
  }

  int r = sendmsg(sck, &hdr, 0);
  errife(r != sizeof(svsr_msg), EMSGSZ);
}

int write_utf8_codepoint(uint8_t *dst, uint32_t cp) {
    if (cp <= 0x7F) {
        dst[0] = (uint8_t)cp;
        return 1;
    } 
    if (cp <= 0x7FF) {
        dst[0] = (uint8_t)(0xC0 | (cp >> 6));
        dst[1] = (uint8_t)(0x80 | (cp & 0x3F));
        return 2;
    } 
    if (cp <= 0xFFFF) {
        // Guard against UTF-16 surrogates (invalid raw Unicode scalar values)
        if (cp >= 0xD800 && cp <= 0xDFFF) return 0; 
        dst[0] = (uint8_t)(0xE0 | (cp >> 12));
        dst[1] = (uint8_t)(0x80 | ((cp >> 6) & 0x3F));
        dst[2] = (uint8_t)(0x80 | (cp & 0x3F));
        return 3;
    } 
    if (cp <= 0x10FFFF) {
        dst[0] = (uint8_t)(0xF0 | (cp >> 18));
        dst[1] = (uint8_t)(0x80 | ((cp >> 12) & 0x3F));
        dst[2] = (uint8_t)(0x80 | ((cp >> 6) & 0x3F));
        dst[3] = (uint8_t)(0x80 | (cp & 0x3F));
        return 4;
    }
    return 0; // Out of Unicode range
}

int xiolib_init(lua_State *st) {
  luaL_newlib(st, xiolib_functions);
  lua_setglobal(st, "xio");
}

int xio_writefile(lua_State *st) {
  const char *pathname = luaL_checkstring(st, 1);
  const char *mode = "w";
  const char *content;
  if (lua_gettop(st) > 2) {
    mode = luaL_checkstring(st, 2);
    content = luaL_checkstring(st, 3);
  } else {
    content = luaL_checkstring(st, 2);
  }

  FILE *f = fopen(pathname, mode);
  if (f == NULL) {
    pusherrno(st, errno);
    lua_error(st);
  }

  if (fprintf(f, "%s", content) < 0) {
    pusherrno(st, errno);
    lua_error(st);
  }
  if (fclose(f) == EOF) {
    pusherrno(st, errno);
    lua_error(st);
  }
}
