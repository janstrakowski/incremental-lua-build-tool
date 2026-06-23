#include "api.h"

pthread_mutex_t sup_mutex = PTHREAD_MUTEX_INITIALIZER;

int build(int ios[], uint64_t ioflags[]) {
  struct msghdr reqhdr;
  memset(&reqhdr, 0, sizeof(msghdr));
  struct iovec iov;
  struct cmsghdr *reqchdr;
  ssize_t nbytes;
  uint64_t nios = 0;
  struct ucred cred;
  int buildid;

  while(ios[nios] != -1) nios++;

  errno = pthread_mutex_lock(&sup_mutex);
  if (errno != 0) return -1;

  nbytes = write(3, 8, SUPMSG_BUILD);
  if (nbytes == -1) {
    pthread_mutex_unlock(&sup_mutex);
    return -1;
  }
  if (nbytes != 8) {
    errno = EBADMSG;
    pthread_mutex_unlock(&sup_mutex);
    return -1;
  }
  nbytes = write(3, 8, &nios);
  if (nbytes == -1) {
    pthread_mutex_unlock(&sup_mutex);
    return -1;
  }
  if (nbytes != 8) {
    errno = EBADMSG;
    pthread_mutex_unlock(&sup_mutex);
    return -1;
  }

  iov.iov_base = ioflags;
  iov.iov_len = 8 * nios;
  reqhdr.iov = &iov;
  reqhdr.iovlen = 1;
  reqhdr.msg_control = malloc(CMSG_SPACE(sizeof(int) * nios) + CMSG_SPACE(sizeof(struct ucred)));
  if (reqhdr.msg_control == NULL) return -1;
  reqhdr.msg_controllen = CMSG_SPACE(sizeof(int) * nios) + CMSG_SPACE(sizeof(struct ucred));
  reqchdr = CMSG_FIRSTHDR(&reqhdr);
  reqchdr->cmsg_level = SOL_SOCKET;
  reqchdr->cmsg_type = SCM_RIGHTS;
  reqchdr->cmsg_len = CMSG_LEN(sizeof(int) * nios);
  memcpy(CMSG_DATA(reqchdr), ios, sizeof(int) * nios);
  reqchdr = CMSG_NXTHDR(&reqhdr, reqchdr);
  reqchdr->cmsg_level = SOL_SOCKET;
  reqchdr->cmsg_type = SCM_CREDENTIALS;
  reqchdr->cmsg_len = CMSG_LEN(sizeof(struct ucred));
  cred->pid = getpid();
  cred->uid = getuid();
  cred->gid = getgid();
  memcpy(CMSG_DATA(reqchdr), &cred, sizeof(struct ucred));

  nbytes = sendmsg(3, &reqhdr, 0);
  free(reqhdr->msg_control);
  if (nbytes != sizeof(int) * nios) {
    errno = EMSGSZ;
    pthread_mutex_unlock(&sup_mutex);
    return -1;
  }

  nbytes = read(3, &buildid, sizeof(int));
  if (nbytes == -1) {
    pthread_mutex_unlock(&sup_mutex);
    return -1;
  }
  errno = pthread_mutex_unlock(&sup_mutex);
  if (errno != 0) return -1;
  if (nbytes == 0) {
    errno = ECONNRESET;
    return -1;
  }
  if (nbytes != sizeof(int)) {
    errno = EMSGSZ;
    return -1;
  }
  if (buildid < 0) {
    errno = EBADMSG;
    return -1;
  }
  return buildid;
}

int waitbuild(int buildid, uint64_t flags) {
  struct msghdr reqhdr;
  memset(&reqhdr, 0, sizeof(msghdr));
  struct iovec iov;
  struct cmsghdr *reqchdr;
  struct ucred cred;
  ssize_t nbytes;
  char ack;

  iov.iov_base = &buildid;
  iov.iov_len = sizeof(int);
  reqhdr.msg_iov = &iov;
  reqhdr.msg_iovlen = 1;
  reqhdr.msg_control = malloc(CMSG_SPACE(sizeof(struct ucred)));
  if (reqhdr.msg_control == NULL) return -1;
  reqhdr.msg_controllen = CMSG_SPACE(sizeof(struct ucred));
  reqchdr = CMSG_FIRSTHDR(&reqhdr);
  reqchdr->cmsg_level = SOL_SOCKET;
  reqchdr->cmsg_type = SCM_CREDENTIALS;
  reqchdr->cmsg_len = CMSG_LEN(sizeof(struct ucred));
  cred->pid = getpid();
  cred->uid = getuid();
  cred->gid = getgid();
  memcpy(CMSG_DATA(reqchdr), &cred, sizeof(struct ucred));

  errno = pthread_mutex_lock(&sup_mutex);
  if (errno != 0) {
    free(reqhdr->msg_control);
    return -1;
  }
  nbytes = sendmsg(3, &reqhdr, 0);
  if (nbytes != sizeof(int)) {
    errno = EMSGSZ;
    pthread_mutex_unlock(&sup_mutex);
    free(reqhdr->msg_control);
    return -1;
  }
  free(reqhdr->msg_control);

  nbytes = read(3, &ack, 1);
  if (nbytes == -1) {
    pthread_mutex_unlock(&sup_mutex);
    return -1;
  }
  errno = pthread_mutex_unlock(&sup_mutex);
  if (errno != 0) return -1;
  if (nbytes == 0) {
    errno = ECONNRESET;
    return -1;
  }
  if (nbytes != 1) {
    errno = EMSGSZ;
    return -1;
  }
  if (ack != 1) {
    errno = EBADMSG;
    return -1;
  }
  return 0;
}

