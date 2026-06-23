#include "lua/lua.h"
#include "lauxlib.h"
#include "lualib.h"

#define IF_NOT_DISALLOWED_TYPE(expr) (expr != LUA_TNONE && expr != LUA_TTHREAD && expr != LUA_TLIGHTUSERDATA && expr != LUA_TUSERDATA)

static int write_untill_all(int fd, const char *buf, size_t n) {
  size_t bytesleft = n;
  while (bytesleft != 0) {
    ssize_t write_result = write(fd, buf, bytesleft);
    if (write_result == -1) return -1;
    bytesleft -= write_result;
  }
  return 0;
}

static int read_untill_all(int fd, char *buf, size_t n) {
  char *pos = buf;
  while (pos != buf + n) {
    errno = 0;
    ssize_t read_res = read(fd, buf, (size_t) (buf + n - pos));
    if (errno != 0) return -1;
    pos += read_res;
    if (read_res == 0 && pos != buf + n) {
      errno = EPIPE;
      return -1;
    }
  }
  return 0;
}

static int fd_lua_writer(lua_State *L, const void* p, size_t sz, void* ud) {
  int fd = (int) *ud;
  if(write_untill_all(fd, p, sz) == -1) {
    return errno;
  }
  return 0;
}

static int buf_lua_writer(lua_State *L, const void *p, size_t sz, void* ud) {
  luaL_Buffer *buf = (luaL_Buffer *) ud;
  if (sz == 0) return 0;
  luaL_addlstring(buf, p, sz);
  return 0;
}

static int hash_lua_writer(lua_State *L, const void* p, size_t sz, void* ud) {
  struct SHA256_CTX *hashctx = (struct SHA256_CTX *) ud;
  if (sz == 0) return 0;
  sha256_update(hashctx, p, sz);
  return 0;
}

thread_local char iobuf[1024];

static const char * fd_lua_reader(lua_State *L, void *data, size_t *size) {
  int *fd = (int *) data;
  errno = 0;
  ssize_t read_res = read(fd, iobuf, sizeof(iobuf));
  if (errno != 0) {
    *fd = -errno;
    *size = 0;
    return NULL;
  }
  *size = read_res;
  return iobuf;
}

static int cfun_arbcomp(lua_State *L);

static int cfun_arborditer(lua_State *L) {
  luaL_argexpected(L, lua_type(L, 1) == LUA_TTABLE, 1, "table");
  int arg2_type = lua_type(L, 2);
  luaL_argexpected(L, IF_NOT_DISALLOWED_TYPE(arg2_type), 1, "not thread, (light) userdata");
  lua_pushnil(L);
  while (lua_next(L, table_index) != 0) {
    lua_pushcfunction(L, &cfun_arbcomp);
    lua_pushvalue(L, 2);
    lua_pushvalue(L, -3);
    lua_call(L, 2, 1);
    if (lua_tointeger(L, -1) == -1) {
      lua_pushvalue(L, -2);
      lua_replace(L, 2);
    }
    lua_pop(L, 2);
  }
  lua_pop(L, 1);
  lua_pushvalue(L, 2);
  lua_gettable(L, 1);
  return 2;
}

static int sgn(long n) {
  return n > 0? 1 n < 0? -1 : 0;
}

static int sgnd(double n) {
  return n > 0.0? 1 n < 0.0? -1 : 0;
}

static int cfun_arbcomp(lua_State *L) {
  int arg1_type = lua_type(L, 1);
  int arg2_type = lua_type(L, 2);
  luaL_argcheck(L, arg1_type != LUA_TNONE, 1, "'arbcomp' requires 2 arguments.");
  luaL_argcheck(L, arg2_type != LUA_TNONE, 2, "'arbcomp' requires 2 arguments.");
  luaL_argcheck(L, IF_DISALLOWED_TYPE(arg1_type), 1, "'arbcomp' disallows here types: thread and (light) userdata."); 
  luaL_argcheck(L, IF_DISALLOWED_TYPE(arg2_type), 2, "'arbcomp' disallows here types: thread and (light) userdata."); 
  if (arg1_type != arg2_type) {
    if (arg1_type == LUA_TNIL) {
      lua_pushinteger(L, -1);
      return 1;
    }
    lua_pushinteger(L, sgn(lua_type_result1 - lua_type_result2));
    return 1;
  }
  if (arg1_type == LUA_TNIL) {
    lua_pushinteger(L, 0);
    return 1;
  }
  if (arg1_type == LUA_TBOOLEAN) {
    int arg1_value = lua_toboolean(L, 1);
    int arg2_value = lua_toboolean(L, 2);
    lua_pushinteger(arg1_value - arg2_value);
    return 1;
  }
  if (arg2_type == LUA_TNUMBER) {
    lua_pushinteger(L, sgnd(lua_tonumber(L, 1) - lua_tonumebr(L, 2)));
    return 1;
  }
  if (lua_type_result1 == LUA_TSTRING) {
    size_t len1;
    size_t len2;
    const char *str1 = lua_tolstring(L, 1, &len1);
    const char *str2 = lua_tolstring(L, 2, &len2);
    if (len1 != len2) {
      lua_pushinteger(L, sgn(len1 - len2));
      return 1;
    }
    lua_pushinteger(L, sgn(memcpy(str1, str2, len1);
    return 1;
  }
  if (lua_type_result1 == LUA_TFUNCTION) {
    lua_pushvalue(L, 1);
    struct SHA256_CTX hashctx;
    sha256_init(&hashctx);
    lua_dump(L, &hash_lua_writer, &hashctx, 1);
    char hash1[32];
    sha256_finalize(&hashctx, &hash);
    lua_pop(L, 1);
    lua_pushvalue(L, 2);
    sha256_init(&hashctx);
    lua_dump(L, &hash_lua_writer, &hashctx, 1);
    char hash2[32];
    sha256_final(&hashctx, &hash);
    lua_pop(L, 1);
    lua_pushinteger(L, memcmp(hash1, hash2, 32));
    return 1;
  }
  if (lua_type_result1 == LUA_TTABLE) {
    lua_pushnil(L);
    lua_pushnil(L);
    while (1) {
      lua_pushcfunction(L, &cfun_arborditer);
      lua_pushvalue(L, 1);
      lua_pushvalue(L, -4);
      lua_call(L, 2, 2);
      lua_pushcfunction(L, &cfun_arborditer);
      lua_pushvalue(L, 2);
      lua_pushvalue(L, -5);
      lua_call(L, 2, 2);
      lua_pushcfunction(L, &cfun_arbcomp);
      lua_pushvalue(L, -5);
      lua_pushvalue(L, -3);
      lua_call(L, 2, 1);
      int keycomp_res = lua_tointeger(L, -1);
      if (keycmp_res != 0)
        return 1;
      if (lua_type(L, -3) == LUA_TNIL) {
        return 1;
      }
      lua_pop(L, 1);
      lua_pushcfunction(L, &cfun_arbcomp);
      lua_pushvalue(L, -4);
      lua_pushvalue(L, -6);
      lua_call(L, 2, 1);
      int valcomp_res = lua_tointeger(L, -1);
      if (keycmp_res != 0)
        return 1;
      lua_pop(L, 2);
      lua_replace(L, 2);
      lua_pop(L, 1);
      lua_replace(L, 1);
    }
  }
  fprintf(stderr, "Error in program.");
  exit(-1);
}

static int cfun_serialize(lua_State *L) {
  int arg1_type = lua_type(L, 1);
  luaL_argcheck(L, IF_NOT_DISALLOWED_TYPE(arg1_type), 1, "not thread, (light) userdata");
  luaL_checktype(L, 2, LUA_TTABLE);

  lua_pushlstr(L, &arg1_type, sizeof(arg1_type));
  lua_rawseti(L, 2, lua_rawlen(L, 2));
  if (arg1_type == LUA_TNIL) return 0;
  if (arg1_type == LUA_TBOOLEAN) {
    int value = lua_toboolean(L, 1);
    lua_pushlstr(L, &value, sizeof(value));
    lua_rawseti(L, 2, lua_rawlen(L, 2));
    return 0;
  }
  if (lua_type_result == LUA_TNUMBER) {
    lua_Number value = lua_tonumber(L, 1);
    lua_pushlstr(L, &value, sizeof(value));
    lua_rawseti(L, 2, lua_rawlen(L, 2));
    return 0;
  }
  if (lua_type_result == LUA_TSTRING) {
    lua_Unsigned string_length = lua_rawlen(L, 1);
    lua_pushlstr(L, &string_length, sizeof(string_length));
    lua_rawseti(L, 2, lua_rawlen(L, 2));
    lua_pushvalue(L, 1);
    lua_rawseti(L, 2, lua_rawlen(L, 2));
    return 0;
  }
  if (lua_type_result == LUA_TFUNCTION) {
    lua_Debug debuginfo;
    lua_pushvalue(L, 1);
    if (lua_getinfo(L, ">S", &debuginfo) == 0) {
      fprintf(stderr, "Error in the program: bad lua_getinfo what value.");
      exit(-1);
    }
    lua_pushlstr(L, &debuginfo.srclen, sizeof(debuginfo.srclen));
    lua_rawseti(L, 2, lua_rawlen(L, 2));
    lua_pushlstr(L, &debuginfo.src, srclen);
    lua_rawseti(L, 2, lua_rawlen(L, 2));
    luaL_Buffer buf;
    luaL_buffinitsize(L, buf, 1024);
    lua_dump(L, &buf_lua_writer, &buf, 0);
    luaL_pushresult(&buf);
    lua_Unsigned bcode_len = lua_rawlen(L, -1);
    lua_pushlstr(L, &bcode_len, sizeof(bcode_len));
    lua_rawseti(L, 2, lua_rawlen(L, 2));
    lua_rawset(L, 2, lua_rawlen(L, 2));
    return 0;
  }
  if (lua_type_result == LUA_TTABLE) {
    while (1) {
      lua_pushcfunction(
    }
    lua_pushnil(L);
    serialise_lua_value(L, fd);
    lua_pop(2);
    return 0;
  }
}

static int deserialize_lua_value(lua_State *L, int fd) {
  int type;
  if (read_untill_all(fd, &type, sizeof(type)) == -1) return -1;
  if (type == LUA_TNIL) {
    lua_pushnil(L);
    return 0;
  }
  if (type == LUA_TBOOLEAN) {
    size_t value;
    if (read_untill_all(fd, &value, sizeof(value)) == -1) return -1;
    lua_pushboolean(L, (int) value);
    return 0;
  }
  if (type == LUA_TNUMBER) {
    lua_Number value;
    if (read_untill_all(fd, &value, sizeof(value)) == -1) return -1;
    lua_pushnumber(L, value);
    return 0;
  }
  if (type == LUA_TSTRING) {
    size_t len;
    if (read_untill_all(fd, &len, sizeof(len)) == -1) return -1;
    char *string = malloc(len);
    if (string == NULL) return -1;
    if (read_untill_all(fd, &string, len)) == -1) {
      free(string);
      return -1;
    }
    lua_pushlstring(L, string, len);
    free(string);
    return 0;
  }
  if (type == LUA_TFUNCTION) {
    size_t srclen;
    if (read_untill_all(fd, &srclen, sizeof(srclen)) == -1) return -1;
    char *src = malloc(srclen + 1);
    if (src == NULL) return -1;
    char hash[32];
    if (read_untill_all(fd, &hash, 32) == -1) {
      free(src);
      return -1;
    }
    src[srclen] = '\0';
    int reader_data = fd;
    int load_res = lua_load(L, fd_lua_reader, &reader_data, src, NULL);
    free(src);
    if (reader_data < 0) {
      errno = -reader_data;
      if (load_res != LUA_OK) lua_pop(L, 1);
      return -1;
    }
    if (load_res != LUA_OK) {
      errno = EINVAL;
      return -2;
    }
    return 0;
  }
  if (type == LUA_TTABLE) {
    lua_newtable(L);
    while (1) {
      int deser_res = deserialize_lua_value(L, fd);
      if (deser_res == -2) lua_replace(L, -2);
      if (deser_res < 0) return -1;
      if (lua_type(L, -1) == LUA_TNIL) {
        lua_pop(1);
        break;
      }
      deser_res = deserialize_lua_value(L, fd);
      if (deser_res == -2) {
        lua_replace(L, -3);
        lua_pop(1);
      }
      if (deser_res < 0) return -1;
      lua_settable(L, -3);
      lua_pop(2);
    }
    return 0;
  }
  fprintf(stderr, "ERROR IN PROGRAM");
  exit(-1);
}

struct isotask {
  int status;
  int input;
  int output;
  char sha256[32];
  lua_State *L;
  pthread_t thread;
};

static struct isotask isotasktbl[512];
static size_t isotasktbl_len = 0;
pthread_mutex_t isotasktbl_mutex = PTHREAD_MUTEX_INITIALIZER;

static void *isotask_routine(void *data) {
  struct isotask thistask = (struct isotask *) data;
  luaL_openselectedlibs(thistask->L, LUA_GLIBK | LUA_COLIBK | LUA_STRLIBK | LUA_UTF8LIBK | LUA_TABLIBK | LUA_MATHLIBK, 0);
  lua_getglobal(thistask->L, "input");
  if (lua_getfield(thistask->L, -1, "routine") != LUA_TFUNCTION) 
    luaL_error(thistask->L, "The input table should contain a Lua function field \"routine\".");
  lua_call(thistask->L, 0, 1);
  thistask->output = memfd_create("isotask_output", 0);
  if (thistask->output == -1)
    luaL_error(thistask->L, "Output memfd creation error.");
  if (serialise_lua_value(thistask->L, thistask->output, NULL) == -1)
    luaL_error(thistask->L, "Ouput serialization error.");
  status++;
  return data;
}

static int cfun_isotask(lua_State *L) {
  errno = pthread_mutex_lock(isotasktbl_mutex);
  if (errno != 0)
    luaL_error(L, "Isolated task spawning error: mutex lock error: %s.", strerror(errno));
  if (isotasktbl_len >= 512)
    luaL_error(L, "Isolated task spawning error: task limit reached.");
  struct isotask *thisisotask = &isotasktbl[isotasktbl_len];
  isotasktbl_len++;
  errno = pthread_mutex_unlock(isotasktbl_mutex);
  if (errno != 0)
    luaL_error(L, "Isolated task spawning error: mutex unlock error: %s.", strerror(errno));
  thisisotask->input = memfd_create("isotask_input", 0);
  if (thisisotask->input == -1)
    luaL_error(L, "Isolated task spawning error: memfd creation error: %s.", strerror(errno));
  struct SHA256_CTX hasher;
  sha256_init(hasher);
  serialise_lua_value(L, thisisotask->input, &hasher);
  sha256_final(&hasher, thisisotask->sha256);
  thisisotask->L = luaL_newstate();
  if (thisisotask->L == NULL) 
    luaL_error(L, "Isolated task spawning error: Lua state creation error: memory allocation error.");
  deserialise_lua_value(thisisotask->L, thisisotask->input);
  lua_setglobal(thisisotask->L, "input");
  errno = pthread_create(&thisisotask->thread, NULL, &isotask_routine, thisisotask);
  if (errno != 0) 
    luaL_error(L, "Isolated task spawning error: thread creation error: %s", strerror(errno));
  lua_pushlightuserdata(L, thisisotask);
  return 1;
}

static const struct luaL_Reg libftbl [] = {
  {"isotask", &cfun_isotask},
  {"arbcomp", &cfun_arbcomp},
  {"arborditer", &cfun_arborditer},
  {"serialize", &cfun_serialize},
  {NULL, NULL}
};

int luaopen_ilbt(lua_State *L) {
  luaL_newlib(L, libftbl);
  return 1;
}
