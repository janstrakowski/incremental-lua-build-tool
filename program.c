# define _GNU_SOURCE

# include "crypto-algorithms/base64.h"
# include "crypto-algorithms/sha256.h"
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

#define CREATTOOL_FILE 0x1
#define CREATTOOL_DIR 0x2
#define CREATTOOL_UPDIRS 0x4
#define CREATTOOL_UPDIRMODE 0x8
#define CREATTOOL_EXCL 0x10

void creattool(int dir, const char *path, uint64_t flags, mode_t mode, ...);

void copytool(int srcdir, const char *src, int destdir, const char *dest, int flags);

#define BUILD_DISCACHE

typedef struct build_args build_args;

void build(build_args *ba);

void startasbuilder();

void lualoadfd(int fd, char *chunkname, lua_State *L);

void luadumpfd(int fd, lua_State *L);

#define checkpathlen(x) assert(strlen(x) < PATH_MAX);

void buildpath(char *buf, const char *first, ...);

#define FDI_SUPERVISOR 3
#define FDI_SRC 4
#define FDI_DESTPATH 5
#define FDI_CODE 6
#define FDI_LASTI 6

char *destpath;

char *chunkname;

typedef struct cli_args cli_args;

cli_args *cli;

void cli_defaults(cli_args *a, const char *thisexecutable);

int startassupervisor();

int newsupervisorfd(void);

int cache_get(const char *path, const char hash[32]);

int cache_put(const char *path, const char hash[32]);

int cache_query(const char hash[32]);

int openthisexe();

void cache_mkpath(const char hash[32], char path[PATH_MAX]);

int luaapi_fslib_register(lua_State *luast);

int xiolib_init(lua_State *st);

void *luanull;

int luaapi_init(lua_State *ls);

void *lnullunwrp(void *value);

const void *lnullwrp(void *value);

// int errnotostring(lua_State *ls);

// int pusherrno(lua_State *ls, int givenerrno);

# define RMR_KEEPCONTAINER 0x1

int rmr(const char *path, int flags);

#include "crypto-algorithms/base64.c"
#include "crypto-algorithms/sha256.c"

struct build_args {
  int srcfd;
  const char *workspace;
  int code;
  const char *chunkname;
  uint64_t flags;
  char hash[32];
  const char *destpath;
  char destpathbuf[PATH_MAX];
};

char * const emptyenvp[1] = {
  NULL
};

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

int buildn = 0;

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
  if (ba->destpath != NULL) checkpathlen(ba->destpath);
  checkpathlen(ba->workspace);

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

void *luanull = "luanull";

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

int rmr(const char *path, int flags) {
  struct stat statbuf;
  if (lstat(path, &statbuf) == -1) {
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

      if (rmr(newpath, flags & ~RMR_KEEPCONTAINER) == -1) {
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

int errnotostring(lua_State *ls) {
  int givenerrno = luaL_checkinteger(ls, 1);
  lua_pushstring(ls, strerror(givenerrno));
  return 1;
}

int pusherrno(lua_State *ls, int givenerrno) {
  lua_pushinteger(ls, givenerrno);
  luaL_setmetatable(ls, "errno");
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
        
int fs_copy(lua_State *L) {
  const char *src = luaL_checkstring(L, 1);
  const char *dest = luaL_checkstring(L, 2);

  copytool(AT_FDCWD, src, AT_FDCWD, dest, 0);

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

const luaL_Reg luaapi_fslib[] = {
  {"direntries", &fslib_direntries},
  {"copy", &fs_copy},
  {"rename", &fs_rename},
  {"mkdir", &fs_mkdir},
  {NULL, NULL}
};

int luaapi_fslib_register(lua_State *luast) {
  luaL_newlib(luast, luaapi_fslib);
  lua_setglobal(luast, "fs");
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

int lapi_setdest(lua_State *L) {
  const char *dest;

  dest = luaL_checkstring(L, 1);
  strcpy(destpath, dest);
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

char fd_luareader_buf[2048];

const char * fd_luareader(lua_State *L, void *data, size_t *size) {
  ssize_t bytesread = read((size_t) data, fd_luareader_buf, 2048);
  errif(bytesread == -1);
  *size = bytesread;
  return fd_luareader_buf;
}

void lualoadfd(int fd, char *chunkname, lua_State *L) {
  int status = lua_load(L, &fd_luareader, (void *) (size_t) fd, chunkname, NULL);
  if (status != LUA_OK) {
    fprintf(stderr, "%s\n", lua_tostring(L, -1));
    exit(-1);
  }
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

void luadumpfd(int fd, lua_State *L) {
  lua_dump(L, fd_luawriter, (void *) (size_t) fd, 0);
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

const luaL_Reg xiolib_functions[] = {
  {"writefile", &xio_writefile},
  {NULL, NULL}
};

int xiolib_init(lua_State *st) {
  luaL_newlib(st, xiolib_functions);
  lua_setglobal(st, "xio");
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

#define SUPVSRFDI_EPOLL 0
#define SUPVSRFDI_LAST 0

typedef struct supvsr_server {
  int *fds;
  pthread_t thread;
} supvsr_server;

# define SUPVSRREQ_NEWSCK 0
# define SUPVSRREQ_PUT 1
# define SUPVSRREQ_QUERY 2
# define SUPVSRREQ_GET 3
# define SUPVSRREQ_OPENEXE 4

typedef struct {
  int type;
  char sha256[32];
} supvsr_msg;

struct cli_args {
  char src[PATH_MAX];
  char dest[PATH_MAX];
  char workspace[PATH_MAX];
  char cache[PATH_MAX];
  char thisexecutable[PATH_MAX];
  char script[PATH_MAX];
};

void cli_defaults(cli_args *a, const char *thisexecutable) {
  strcpy(a->src, "");
  strcpy(a->dest, "pldest");
  strcpy(a->workspace, "plworkspace");
  strcpy(a->cache, "plcache");
  strcpy(a->thisexecutable, thisexecutable);
  strcpy(a->script, "build.lua");
}

int supvsr_sendmsg(int sck, supvsr_msg *payload, int fd) {
  union {
    char buf[CMSG_SPACE(sizeof(int))];
    struct cmsghdr align_to_me;
  } chdr_holder;
  struct cmsghdr *chdr_p;
  struct msghdr hdr;
  struct iovec pl_iov;

  memset(&hdr, 0, sizeof(struct msghdr));

  pl_iov.iov_base = payload;
  pl_iov.iov_len = sizeof(supvsr_msg);
  hdr.msg_iov = &pl_iov;
  hdr.msg_iovlen = 1;

  if (fd >= 0) {
    hdr.msg_control = chdr_holder.buf;
    hdr.msg_controllen = sizeof(chdr_holder.buf);
    chdr_p = CMSG_FIRSTHDR(&hdr);
    chdr_p->cmsg_level = SOL_SOCKET;
    chdr_p->cmsg_type = SCM_RIGHTS;
    chdr_p->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(chdr_p), &fd, sizeof(int));
  }

  int r = sendmsg(sck, &hdr, 0);
  errif(r != sizeof(supvsr_msg));
  return 0;
}

#define SUPVSRRECV_MAYSHUTDOWN 1
int supvsr_recvmsg(int sck, supvsr_msg *payload, int *fd, int flags) {
  struct cmsghdr *chdr_p;
  struct msghdr hdr;
  struct iovec pl_iov;
  union {
    struct cmsghdr align;
    char buf[CMSG_SPACE(sizeof(int))];
  } cmsg_holder;

  memset(&hdr, 0, sizeof(struct msghdr));
  pl_iov.iov_base = payload;
  pl_iov.iov_len = sizeof(supvsr_msg);
  hdr.msg_iov = &pl_iov;
  hdr.msg_iovlen = 1;
  hdr.msg_control = cmsg_holder.buf;
  hdr.msg_controllen = sizeof(cmsg_holder.buf);

  int r = recvmsg(sck, &hdr, 0);
  if (flags & SUPVSRRECV_MAYSHUTDOWN && r == 0) {
    return 1;
  }
  errif(r != sizeof(supvsr_msg));

  if (fd != NULL) {
    chdr_p = CMSG_FIRSTHDR(&hdr);
    if (chdr_p != NULL) {
      memcpy(fd, CMSG_DATA(chdr_p), sizeof(int));
    }
  }

  return 0;
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

int openthisexe() {
  int exefd;
  supvsr_msg req;
  supvsr_msg res;

  req.type = SUPVSRREQ_OPENEXE;
  supvsr_sendmsg(FDI_SUPERVISOR, &req, -1);

  supvsr_recvmsg(FDI_SUPERVISOR, &res, &exefd, 0);
  return exefd;
}

void cache_mkpath(const char hash[32], char path[PATH_MAX]) {
  char *pos = path;
  char *endpos;

  strcpy(path, cli->cache);
  pos += strlen(cli->cache);
  strcpy(pos, "/sha256_");
  pos += strlen("/sha256_");
  endpos = pos + base64_encode(hash, pos, 32, 0);
  *endpos = '\0';
  for (char *cpos = pos; cpos != endpos; cpos++) {
    if (*cpos == '/') {
      *cpos = '_';
    }
  }
}

int cache_handleput(supvsr_server *srv, const char hash[32], int obj) {
  char path[PATH_MAX];

  cache_mkpath(hash, path);
  copytool(obj, "", AT_FDCWD, path, 0);
  return 0;
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

void* supervisor_handler(void *arg) {
  struct epoll_event event;
  struct epoll_event eventtoregister;
  int fdnum;
  supvsr_msg req;
  int reqfd = -1;
  supvsr_msg res;
  int thisexefd;
  int sckpair[2];
  supvsr_server *srv;

  srv = (supvsr_server *) arg;

  while (1) {
    fdnum = epoll_wait(srv->fds[SUPVSRFDI_EPOLL], &event, 1, -1);
    if (fdnum == -1 && errno == EINTR) continue;
    errif(fdnum == -1);
    errif(fdnum != 1);

    if (supvsr_recvmsg(srv->fds[event.data.u32], &req, &reqfd, SUPVSRRECV_MAYSHUTDOWN) == 1) {
      errif(epoll_ctl(srv->fds[SUPVSRFDI_EPOLL], EPOLL_CTL_DEL, srv->fds[event.data.u32], NULL) != 0);
      errif(close(srv->fds[event.data.u32]) != 0);
      arrdel(srv->fds, event.data.u32);
      continue;
    }

    if (req.type == SUPVSRREQ_NEWSCK) {
      errif(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sckpair) != 0);
      arrput(srv->fds, sckpair[0]);
      eventtoregister.data.u32 = arrlen(srv->fds) - 1;
      eventtoregister.events = EPOLLIN | EPOLLRDHUP;
      errif(epoll_ctl(srv->fds[SUPVSRFDI_EPOLL], EPOLL_CTL_ADD, sckpair[0], &eventtoregister) != 0);

      res.type = SUPVSRREQ_NEWSCK;
      supvsr_sendmsg(srv->fds[event.data.u32], &res, sckpair[1]);
      errif(close(sckpair[1]) != 0);
    } else if (req.type == SUPVSRREQ_PUT) {
      cache_handleput(srv, req.sha256, reqfd);

      res.type = SUPVSRREQ_PUT;
      supvsr_sendmsg(srv->fds[event.data.u32], &res, -1);
    } else if (req.type == SUPVSRREQ_GET) {
      int rslt = cache_handleget(srv, req.sha256, reqfd);

      res.type = SUPVSRREQ_GET;
      memset(res.sha256, (char) rslt, 32);
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

#define intsrcpath "/src"
#define intdestpath "/dest"

uint32_t main(uint32_t argc, char* argv[]) {
  int32_t opt;
  int stderr_fd;

  stderr_fd = STDERR_FILENO;
  errif(fcntl(stderr_fd, F_GETFL) == -1);
  for (int fd = 3; fd <= FDI_LASTI; fd++) {
    if (fd == stderr_fd) continue;
    errif(dup2(stderr_fd, fd) == -1);
  }

  cli = malloc(sizeof(cli_args));
  cli_defaults(cli, argv[0]);

  while(1){
    opt = getopt(argc, argv, "s:d:w:c:x:");
    if (opt == 's') {
      checkpathlen(optarg);
      strcpy(cli->src, optarg);
      continue;
    }
    if (opt == 'd') {
      checkpathlen(optarg);
      strcpy(cli->dest, optarg);
      continue;
    }
    if (opt == 'w') {
      checkpathlen(optarg);
      strcpy(cli->workspace, optarg);
      continue;
    }
    if (opt == 'c') {
      checkpathlen(optarg);
      strcpy(cli->cache, optarg);
      continue;
    }
    if (opt == 'x') {
      checkpathlen(optarg);
      strcpy(cli->script, optarg);
      continue;
    }
    break;
  }

  startassupervisor();
  return 0;
}
