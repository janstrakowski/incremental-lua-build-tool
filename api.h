#ifndef PROGRAMMATICLINUX_H
#define PROGRAMMATICLINUX_H

#define SUPMSG_BUILD ((uint64_t) 0)
#define SUPMSG_WAITBUILD ((uint64_t) 1)

#define IO_READONLY 0x1

int build(int ios[], uint64_t ioflags[]);

#define WAITBUILD_NONBLOCK 0x1

int waitbuild(int buildid, uint64_t flags);

#endif
