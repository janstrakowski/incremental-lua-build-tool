const std = @import("std");
const zlua = @import("zlua");

pub fn register(lua: *zlua.Lua) !void {
    lua.pushFunction(zlua.wrap(lua_stat));
    lua.setGlobal("stat");
    _ = try lua.newMetatable("HandleMT");
    // newMetatable creates the table if it doesn't exist and pushes it (+1)
    // Push the garbage collection metamethod (+1)
    lua.pushFunction(zlua.wrap(HandleWrapper.gc));
    // Pop the metamethod and assign it to the metatable __gc field (-1)
    lua.setField(-2, "__gc");
    // Pop the metatable and assign it to the userdata underneath it (-1)
    lua.pop(1);
}

pub const HandleWrapper = struct {
    tag: enum { file, dir },
    io: std.Io,
    inner_file: ?std.Io.File = null,
    inner_dir: ?std.Io.Dir = null,

    pub fn gc(lua: *zlua.Lua) i32 {
        var wrapper = lua.toUserdata(HandleWrapper, 1) catch return 0;
        if (wrapper.tag == .file and wrapper.inner_file != null) {
            wrapper.inner_file.?.close(wrapper.io);
            wrapper.inner_file = null;
        } else if (wrapper.tag == .dir and wrapper.inner_dir != null) {
            wrapper.inner_dir.?.close(wrapper.io);
            wrapper.inner_dir = null;
        }
        return 0;
    }
};

pub fn pushHandle(lua: *zlua.Lua) !*HandleWrapper {
    // Allocate the userdata block inside Lua's garbage collector.
    // It pushes the userdata to the top of the stack (+1)
    const userdata = lua.newUserdata(HandleWrapper, 0);
    _ = lua.getMetatableRegistry("HandleMT");
    lua.setMetatable(-2);
    // The stack resolves cleanly, leaving only the populated userdata on top.
    return userdata;
}

pub fn lua_stat(lua: *zlua.Lua) !i32 {
    // 1. Get and validate the userdata
    const wrapper = lua.toUserdata(HandleWrapper, 1) catch {
        lua.argCheck(false, 1, "expected directory handle userdata");
        return 0;
    };

    // 2. Ensure it is a valid, open directory handle
    lua.argCheck(wrapper.tag == .dir, 1, "handle must be a directory");
    const dir = wrapper.inner_dir orelse {
        lua.argCheck(false, 1, "directory handle is closed");
        return 0;
    };

    // 3. Get the path string
    const path = try lua.toString(2);

    // 4. Perform stat.
    // In Zig, `statFile` transparently works on both files and directories 
    // without actually opening them, calling `fstatat` or `GetFileAttributesExW` underneath.
    const stat = try dir.statFile(wrapper.io, path, .{});

    // 5. Create a new table on the stack and populate it
    lua.newTable();

    // Field: kind
    const kind_str = switch (stat.kind) {
        .file => "file",
        .directory => "directory",
        .sym_link => "sym_link",
        else => "unknown",
    };
    _ = lua.pushString(kind_str);
    lua.setField(-2, "kind");

    // Field: size
    lua.pushNumber(@floatFromInt(stat.size));
    lua.setField(-2, "size");

    // Field: atime (now optional in Zig 0.16.0)
    if (stat.atime) |atime| {
        const atime_sec = @as(f64, @floatFromInt(atime.toNanoseconds())) / 1_000_000_000.0;
        lua.pushNumber(atime_sec);
        lua.setField(-2, "atime");
    }

    // Field: mtime (now an Io.Timestamp object)
    const mtime_sec = @as(f64, @floatFromInt(stat.mtime.toNanoseconds())) / 1_000_000_000.0;
    lua.pushNumber(mtime_sec);
    lua.setField(-2, "mtime");
    // The constructed table is now left at the top of the stack
    return 1;
}
