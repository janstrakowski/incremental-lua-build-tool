#include "crypto-algorithms/base64.h"
#include "crypto-algorithms/sha256.h"

#include "api.h"

#define ERREXIT(fmt, ...)                                                      \
  do {                                                                         \
    fprintf(stderr, fmt, ##__VA_ARGS__);                                       \
    fprintf(stderr, "Error code: %d (%s).\n", errno, strerror(errno));         \
    exit(errno);                                                               \
  } while (0)
#define ERREXITE(errn, fmt, ...)                                               \
  do {                                                                         \
    errno = errn;                                                              \
    ERREXIT(fmt, ##__VA_ARGS__);                                               \
  } while (0)

static thread_local char iobuf1[4096];

static int cachedir;
static int workspace;
static int buildn;

struct active_build {
  int comsck;
  pid_t pid;
  pid_t callerpid;
  int idincaller;
  struct time_spec starttime;
  struct time_spec finishtime;
  pthread_t handlerthread;
  int *ios;
  uint64_t *ioflags;
  char sha256[32];
  char incacheid[51];
  int buildn;
};
#define ACBUILDS_LAST 1024
static struct active_build acbuilds[ACBUILDS_LAST];
pthread_mutex_t acbuilds_mutex = PTHREAD_MUTEX_INITIALISER;

int hash(int io, SHA256_CTX *hashctx) {
  struct statx statxbuf;
  ssize_t nbytes;
  DIR *dirstream;
  struct dirent *dirent;
  int openfile;

  if (statx(io, "", AT_EMPTY_PATH,
            STATX_TYPE | STATX_MODE | STATX_UID | STATX_GUID | STATX_SIZE,
            &statxbuf) == -1)
    return -1;
  sha256_update(hashctx, &statxbuf.stx_mode, sizeof(uint16_t));
  sha256_update(hashctx, &statxbuf.stx_uid, sizeof(uint32_t));
  sha256_update(hashctx, &statxbuf.stx_gid, sizeof(uint32_t));
  sha256_update(hashctx, &statxbuf.stx_size, sizeof(uint32_t));
  if (S_ISREG(statxbuf.stx_mode)) {
    while (1) {
      nbytes = read(io, iobuf1, sizeof(iobuf1));
      if (nbytes == -1)
        return -1;
      if (nbytes == 0)
        break;
      sha256_update(hashctx, iobuf1, nbytes);
    }
  } else if (S_ISDIR(statxbuf.stx_mode)) {
    dirstream = fopendir(io);
    if (dirstream == NULL)
      return -1;
    while (1) {
      errno = 0;
      dirent = readdir(dirstream);
      if (errno != 0)
        return -1;
      if (dirent == NULL)
        break;
      openfile = openat(io, dirent->d_name, O_RDONLY | O_NOFOLLOW);
      if (openfile == -1) {
        closedir(dirstream);
        return -1;
      }
      if (hash(openfile, hashctx) == -1) {
        closedir(dirstream);
        close(openfile);
        return -1;
      }
      if (close(openfile) == -1) {
        closedir(dirstream);
        return -1;
      }
    }
    if (closedir(dirstream) == -1)
      return -1;
  } else if (S_ISLNK(statxbuf.stx_mode)) {
    nbytes = readlinkat(io, "", iobuf1, sizeof(iobuf1));
    if (nbytes == sizeof(iobuf1)) {
      errno = ENOBUFS;
      return -1;
    }
    if (nbytes == -1)
      return -1;
    sha256_update(hashctx, iobuf1, nbytes);
  } else {
    errno = ENOTSUP;
    return -1;
  }
  return 0;
}

int cacheid(const char sha256[32], char buf[51]) {
  strcpy(buf, "sha256-");
  base64_encode(sha256, buf + 7, 32, 0);
  buf[50] = '\0';
}

#define RECCPY_REPLACE 0x1
#define RECCPY_CPYMODE 0x2
int recdircpy(int destfd, int srcfd, uint64_t flags) {
  struct stat statbuf;
  ssize_t nbytes;
  size_t bytesleft;
  int openfile;
  int openfile2;
  DIR *dirstream;
  struct dirent dirent;

  dirstream = fopendir(srcfd);
  if (dirstream == NULL)
    return -1;

  while (1) {
    errno = 0;
    dirent = readdir(dirstream);
    if (errno != 0) {
      closedir(dirstream);
      return -1;
    }
    if (dirent == NULL)
      break;
    if (fstatat(srcfd, dirent->name, &statbuf, AT_SYMLINK_NOFOLLOW) == -1) {
      closedir(dirstream);
      return -1;
    }
    if (S_ISLNK(statbuf->st_mode)) {
      if (flags & RECCPY_REPLACE && unlinkat(destfd, dirent->name, 0) == -1) {
        closedir(dirstream);
        return -1;
      }
      nbytes = readlinkat(srcfd, dirent->name, iobuf1, sizeof(iobuf1));
      if (nbytes == sizeof(iobuf1)) {
        errno = ENOBUFS;
        closedir(dirstream);
        return -1;
      }
      if (nbytes == -1) {
        closedir(dirstream);
        return -1;
      }
      if (symlinkat(iobuf1, destfd, dirent->name) == -1) {
        closedir(dirstream);
        return -1;
      }
    } else if (S_ISREG(statbuf->st_mode)) {
      if (flags & RECCPY_REPLACE && unlinkat(destfd, dirent->name, 0) == -1) {
        closedir(dirstream);
        return -1;
      }
      openfile = openat(srcfd, dirent->name, O_RDONLY);
      if (openfile == -1) {
        closedir(dirstream);
        return -1;
      }
      openfile2 =
          openat(destfd, dirent->name, O_WRONLY | O_CREAT | O_EXCL, 0644);
      if (openfile2 == -1) {
        closedir(dirstream);
        close(openfile);
        return -1;
      }
      bytesleft = statbuf->st_size;
      while (bytesleft != 0) {
        nbytes = sendfile(openfile2, openfile, NULL, bytesleft);
        if (nbytes == -1) {
          closedir(dirstream);
          close(openfile);
          close(openfile2);
          return -1;
        }
        if (nbytes == 0) {
          errno = EPIPE;
          closedir(dirstream);
          close(openfile);
          close(openfile2);
          return -1;
        }
        bytesleft -= nbytes;
      }
      if (close(openfile) == -1) {
        closedir(dirstream);
        close(openfile2);
        return -1;
      }
      if (close(openfile2) == -1) {
        closedir(dirstream);
        return -1;
      }
    } else if (S_ISDIR(statbuf->st_mode)) {
      openfile = openat(srcfd, dirent->name, O_RDONLY);
      if (openfile == -1) {
        closedir(dirstream);
        return -1;
      }
      openfile2 = openat(destfd, dirent->name, O_RDONLY);
      if (openfile2 == -1) {
        if (errno != ENOENT) {
          close(openfile);
          closedir(dirstream);
          return -1;
        }
        if (mkdirat(destfd, dirent->name, 0755) == -1) {
          close(openfile);
          closedir(dirstream);
          return -1;
        }
        openfile2 = openat(destfd, dirent->name, O_RDONLY);
        if (openfile2 == -1) {
          close(openfile);
          closedir(dirstream);
          return -1;
        }
      }
      if (recdircpy(openfile2, openfile, flags) == -1) {
        close(openfile);
        close(openfile2);
        closedir(dirstream);
        return -1;
      }
      if (close(openfile2) == -1) {
        close(openfile);
        closedir(dirstream);
        return -1;
      }
      if (close(openfile) == -1) {
        closedir(dirstream);
        return -1;
      }
    } else {
      errno = EOPNOTSUP;
      return -1;
    }
    if (flags & RECCPY_CPYMODE &&
        fchmodat(destfd, dirent->name, statbuf->st_mode, AT_SYMLINK_NOFOLLOW) ==
            -1) {
      closedir(dirstream);
      return -1;
    }
  }
  if (closedir(dirstream) == -1)
    return -1;
  return 0;
}

int build(int ios[], uint64_t ioflags[]) {
  fprintf(stderr, "NOT IMPLEMENTED FUNCTION\n");
  exit(-1);
}

void *startbuildroutine(void *arg) {
  struct active_build *thisbuild = (struct active_build *)arg;

  SHA256_CTX shactx;
  sha256_init(&shactx);
  size_t nios;
  for (nios = 0; ios[nios] != -1; nios++) {
    if (hash(ios[nios], &shactx) == -1)
      ERREXIT("Build #%d hashing error: %s\n", thisbuild->buildn,
              strerror(errno));
  }
  sha256_update(&shactx, &nios, sizeof(nios));
  sha256_final(&shactx, thisbuild->sha256);
  cacheid(sha256, thisbuild->incacheid);

  int builddirincache = openat(cachedir, cacheid, O_RDONLY);
  if (builddirincache == -1 && errno != ENOENT)
    ERREXIT("Build #%d (%s) buildirincache open: %s\n", thisbuild->buildn,
            thisbuild->incacheid, strerror(errno));
  if (builddirincache != -1) {
    for (size_t i = 0; i < nios; i++) {
      char ion_str[64];
      sprintf(ion_str, "%d", i);
      iofile = openat(builddirincache, ion_str, O_RDONLY);
      if (iofile == -1) {
        close(builddirincache);
        return -1;
      }
      if (statx(ios[i], "", AT_EMPTY_PATH, STATX_BASIC_STATS, &statxbuf) ==
          -1) {
        close(iofile);
        close(builddirincache);
        return -1;
      }
      if (statx(iofile, "", AT_EMPTY_PATH, STATX_BASIC_STATS, &statxbuf2) ==
          -1) {
        close(iofile);
        close(builddirincache);
        return -1;
      }
      if (statxbuf & S_IFMT != statxbuf2 & S_IFMT) {
        errno = EFTYPE;
        close(iofile);
        close(builddirincache);
        return -1;
      }
      if (S_ISREG(statxbuf)) {
        if (ftruncate(ios[i], 0) == -1) {
          close(iofile);
          close(builddirincache);
          return -1;
        }

        bytesleft = statxbuf2;
        while (bytesleft != 0) {
          nbytes = sendfile(ios[i], iofile, NULL, bytesleft);
          if (nbytes == -1) {
            close(iofile);
            close(builddirincache);
            return -1;
          }
          if (nbytes == 0) {
            errno = EPIPE;
            close(iofile);
            close(builddirincache);
            return -1;
          }
        }
      } else if (reccpydir(ios[i], iofile, RECCPY_REPLACE | RECCPY_CPYMODE) ==
                 -1) {
        close(iofile);
        close(builddirincache);
        return -1;
      }
      if (close(iofile) == -1) {
        close(builddirincache);
        return -1;
      }

      if (fchmod(ios[i], statxbuf2.stx_mode) == -1) {
        close(builddirincache);
        return -1;
      }
    }
    sprintf(ion_str, "%d", i);
    if (statx(builddirincache, ion_str, 0, 0, &statxbuf) != -1) {
      errno = EEXIST;
      close(builddirincache);
      return -1;
    }
    if (errno != ENOENT) {
      close(builddirincache);
      return -1;
    }
  } else {
    if (close_range(3, ~0U, 0) == -1)
      exit(errno);
  }
}

struct active_build *startbuild(int ios[], uint64_t ioflags[],
                                struct active_build *caller) {
  char ion_str[NAME_MAX];
  size_t nios = 0;
  int cbuilddir;
  int iofile;
  struct statx statxbuf;
  struct statx statxbuf2;
  ssize_t nbytes;
  size_t bytesleft;
  pid_t rpid;

  for (size_t i = 0; ios[i] != -1; i++) {
    nios++;
    if (statx(ios[i], "", AT_EMPTY_PATH, STATX_BASIC_STATS, &statxbuf) == -1) {
      return NULL;
    }

    if (!(S_ISREG(statxbuf.stx_mode) || S_ISDIR(statxbuf.stx_mode))) {
      errno = EOPNOTSUP;
      return NULL;
    }

    if (ioflags[i] & IO_READONLY) {
      if (S_ISREG(statxbuf.stx_mode)) {
        int seals = fcntl(ios[i], F_GET_SEALS);
        if (seals == -1 && errno != EINVAL)
          ERREXIT("IO#%d seal getting error", i);
        if (seals != -1 && !seals & F_SEAL_WRITE)
          ERREXITE(EINVAL,
                   "IO#%d is flagged read-only but it is sealable and has not "
                   "write seal",
                   i);
        if (seals != -1)
          goto ok;
      }
    }

    errno = pthread_mutex_lock(&acbuilds_mutex);
    if (errno != NULL)
      ERREXIT("Acbuilds mutex lock failure");
    struct active_build *thisbuild;
    for (thisbuild = acbuilds;; thisbuild = &thisbuild[1]) {
      if (thisbuild == &acbuilds[ACBUILDS_LAST + 1])
        ERREXIT("Active builds table overflow.\n");
      if (thisbuild->comsck == -1)
        break;
    }
    thisbuild->comsck = -2;
    if (clock_gettime(CLOCK_MONOTONIC, &thisbuild->starttime) == -1)
      ERREXIT("Clock_gettime starttime failure");
    memcpy(&thisbuild->finishtime, &thisbuild->starttime,
           sizeof(thisbuild->starttime));
    thisbuild->callerid = caller;
    int incallerid = -1;
    for (struct active_build *currentbuild = acbuilds;
         currentbuild != &acbuilds[ACBUILDS_LAST + 1];
         currentbuild = &acbuild[1]) {
      if (currentbuild->comsck == -1)
        continue;
      if (currentbuild->callerid == caller &&
          currentbuild->incallerid > incallerid)
        incallerid = currentbuild->incallerid;
    }
    thisbuild->ios = ios;
    thisbuild->ioflags = ioflags;
    buildn++;
    thisbuild->buildn = buildn;

    errno = pthread_mutex_unlock(&acbuilds_mutex);
    if (errno != NULL)
      ERREXIT("Acbuilds mutex unlock failure");
    errno = phread_create(&acbuild->handlingthread, NULL, &startbuildroutine,
                          acbuild);
    if (errno != 0)
      ERREXIT("Buildhandling thread setup failure");
    return acbuild;

    rpid = fork();
    if (rpid == -1)
      return -1;
    if (rpid != 0)
      return rpid;
  }

  int waitbuild(int buildid, uint64_t flags) {
    fprintf(stderr, "UNIMPLEMENTED FUNCTION\n");
    exit(-1);
  }

  int waitforbuild(struct active_build * acbuild) {}

  int main(int argc, char *argv[]) {
    char *cachepath = getenv("CB_CACHE");
    if (cachepath == NULL)
      cachepath = "./cb_cache/";
    char *cachedirfdstr = getenv("CB_CACHEDIRFD");
    int cachedirfd;
    if (cachedirfdstr == NULL)
      cachedirfd = AT_FDCWD;
    else {
      char *cachedirfdstrendp;
      errno = 0;
      cachedirfd = (int)strtol(cachedirfdstr, cachedirfdstrendp, 0);
      if (errno != 0) {
        perror("Cachedirfd string-to-int conversion error");
        return errno;
      }
      if (*cachedirfdstrendp != '\0') {
        errno = EINVAL;
        perror("Cachedirfd is not a valid integer");
        return errno;
      }
    }
    cachedir = openat(cachedirfd, cachepath, O_PATH);

    char *workspacepath = getenv("CB_WORKSPACE");
    if (workspacepath == NULL)
      workspacepath = "./cb_workspace/";
    char *workspacefdstr = getenv("CB_WORKSPACEDIRFD");
    int workspacedirfd;
    if (workspacefdstr == NULL)
      workspacedirfd = AT_FDCWD;
    else {
      char *workspacedirfdstrendp;
      errno = 0;
      workspacefd = strtol(workspacedirfdstr, workspacedirfdstrendp, 0);
      if (errno != 0) {
        perror("Worspacedirfd string-to-int conversion error");
        return errno;
      }
      if (workspacedirfdstrendp != '\0') {
        errno = ENIVAL;
        perror("Workspacedirfd is not a valid integer");
        return errno;
      }
    }
    workspace = openat(workspacedirfd, workspacepath, O_PATH);

    int *ios = malloc(sizeof(int) * (argc - 1));
    for (size_t i = 0; i < argc - 1; i++) {
      size_t c = 0;
      for (char ptr = argv[i]; *ptr != '\0'; ptr++)
        if (*ptr == ':')
          c++;
      char * 1ptr = argv[i];
      while (*1ptr != '\0' && *1ptr != ':')
        1ptr ++;
      char * 2ptr = *1ptr == ':' ? 1ptr + 1 : 1ptr;
      while (*2ptr != '\0' && *2ptr != ':')
        2ptr ++;
      *1ptr = '\0';
      *2ptr = '\0';
      char *flagsstr;
      char *dirfdstr;
      char *pathstr;
      if (c >= 2) {
        dirfdstr = argv[i];
        flagsstr = 1ptr + 1;
        pathstr = 2ptr + 1;
      } else if (c == 1) {
        dirfdstr = argv[i];
        pathstr = 1ptr + 1;
        flagsstr = 1ptr;
      } else {
        pathstr = argv[i];
        dirfdstr = 1ptr;
        flagsstr = 1ptr;
      }
      int dirfd;
      if (*dirfd == '\0')
        dirfd = AT_FDCWD;
      else {
        char *endp;
        errno = 0;
        dirfd = (int)strtol(dirfdstr, endp, 0);
        if (errno != 0) {
          fprintf(stderr,
                  "Failed string-to-int conversion for dirfd of arg#%d: %s.\n",
                  i, strerror(errno));
          return errno;
        }
        if (*endp != '\0') {
          fprintf(stderr,
                  "Arg#%d: the value before the first colon should be an "
                  "integer.\n",
                  i);
          return EINVAL;
        }
      }
      int read = 0;
      int write = 0;
      for (char *ptr = flagsstr; *ptr != '\0'; ptr++)
        switch
          *ptr {
          case 'r':
            read = 1;
            break;
          case 'w':
            write = 1;
            break;
          default:
            fprintf(stderr,
                    "Arg#%d has bad flags: only 'r' and 'w' characters are "
                    "allowed.\n",
                    i);
            return EINVAL;
          }
      int flags;
      if (read && write)
        flags = O_RDWR;
      else if (read)
        flags = O_RDONLY;
      else if (write)
        flags = O_WRONLY;
      else {
        fprintf(stderr,
                "Arg#%d has bad flags: at least one 'r' or 'w' character is "
                "expected.\n",
                i);
        return EINVAL;
      }
      if (*pathstr == '\0' && dirfd == AT_FDCWD) {
        fprintf(stderr, "Arg#%d has an empty path and no dirfd.\n", i);
        return EINVAL;
      }
      if (*pathstr == '\0')
        ios[i] = dirfd;
      else {
        ios[i] = openat(dirfd, pathstr, flags);
        if (ios[i] == -1) {
          fprintf(stderr, "Could not open io#%d: %s\n", i, strerr(errno));
          return errno;
        }
      }
    }

    struct active_build *acbuild = startbuild(ios, NULL, NULL);
    if (acbuild == NULL) {
      perror("Could not start the main build");
      return errno;
    }
    if (waitforbuild(acbuild) == -1) {
      perror("The main build failed");
      return errno;
    }
    return 0;
  }
