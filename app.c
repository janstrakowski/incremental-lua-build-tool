#define VERSIONSTR "0.1.0"
#define IO_CANWRITE 0x1

typedef uint64_t ioflags_t;
struct ioent {
  const char *ioname;
  const char *iopath;
  ioflags_t ioflags;
  int iofd;
};

#define CRASHE(msg, errn) \
    do { \
        errno = errn; \
        fprintf(stderr, "CRASHED: %s\n", (msg)); \
        exit(errno); \
    } while(0)

#define CRASH(msg) \
    do { \
        fprintf(stderr, "CRASHED: %s\n", (msg)); \
        exit(errno); \
    } while(0)

#define IOTBL_CAP 512
uint32_t main(uint32_t argc, char *argv[]) {
  if (argc > 2 && strcmp(argv[1], "--help") == 0) {
    printf("DETERMINISTIC LUA BUILD v%s\n"
        "%s --help  - displays this message.\n"
        "%s --version  - displays the current using version message.\n"
        "%s [<ioname> <iopath> [ioflags]]...\n", VERSIONSTR, argv[0], argv[0]);
    exit(0);
  }
  if (argc > 2 && strcmp(argv[1], "--version") == 0) {
    printf("Deterministic Lua Build v%s\n", VERSIONSTR);
    exit(0);
  }
  struct ioent iotbl[IOTBL_CAP];
  ssize_t lastioi = -1;
  uint64_t stage = 0;
  for (size_t argi = 1; argi < argc; ) {
    if (stage == 0) {
      if (*argv[argi] != '=') {
        fprintf(stderr, "CLI arguments error: argument #%d is invalid: now expected '=<name of the io>' but received '%s'.\n", argi, argv[argi]);
        exit(EINVAL);
      }
      if (argv[argi][1] == '\0') {
        fprintf(stderr, "CLI arguments error: argument #%d is invalid: expected '=<name of the io>' but received just '='.\n", argi, argv[argi]);
        exit(EINVAL);
      }
      uint32_t ifregexrequirement = 1;
      if (!isalpha(ch)) ifregeqrequirement = 0;
      for (char *currentcharp = argv[argi] + 2; currentcharp != '\0'; currentcharp++)
        if (!isalnum(*currentcharp) && *currentcharp != '_') ifregexrequirement = 0;
      if (!ifregexrequirement) {
        fprintf(stderr, "CLI arguments error: argument #%d is invalid: expected '=<name of the io>' and <name of the io>=[A-Za-z][A-Za-z0-9_]* but '%s' does not meet that.\n", argi, argv[argi]);
        exit(EINVAL);
      }
      lastioi++;
      if (lastioi == IOTBL_CAP) CRASHE("IOTBL overflow", ENOBUFS);
      iotbl[lastioi].ioname = argv[argi] + 1;
      stage++;
      argi++;
      continue;
    }
    if (stage == 1) {
      iotbl[lastioi].iopath = argv[argi];
      stage++;
      argi++;
      continue;
    }
    if (stage == 2) {
      if (*argv[argi] == '=') {
        stage = 0;
        continue;
      }
      ioflags_t ioflags = 0;
      for (char *currentcharp = argv[argi]; *currentcharp != '\0'; currentcharp++) {
        if (*currentcharp != 'w') {
          fprintf(stderr, "CLI arguments error: argument #%d is invalid: expected '<ioflags=[w]+>' or '=<name of the io>' but received '%s'\n", argi, argv[argi]);
          exit(EINVAL);
        }
        if (*currentcharp == 'w') ioflags |= IO_CANWRITE;
      }
      ios[lastioi].ioflags = ioflags;
      stage = 0;
      argi++;
      continue;
    }
  }

  for (ssize_t ioi = -1; ioi < lastioi; ioi++) {
    iotbl[i].io = open(iotbl[i].iopath, iotbl[i].ioflags & IO_CANWRITE? O_RDWR : O_RDONLY);
    if (iotbl[i].io == -1) {
      fprintf(stderr, "IO =%s: could not open CLI-given path '%s': %s\n", 
          iotbl[i].ioname, iotbl[i].iopath, strerror(errno));
      exit(errno);
    }
  }
}
