const std = @import("std");
const Io = std.Io;
const zlua = @import("zlua");
const Lua = zlua.Lua;

const incremental_lua_build_tool = @import("incremental_lua_build_tool");
const luabase = @import("luabase.zig");
const fs = @import("fs.zig"); // Import our new fs module

var allocator: std.mem.Allocator = undefined;

pub fn main(init: std.process.Init) !void {
    allocator = init.gpa;
    const io = init.io;

    // 1. Properly fetch command line arguments before iterating
    const args = try init.minimal.args.toSlice(allocator);
    defer allocator.free(args);

    // Provide the allocator to the luabase module
    luabase.allocator = allocator;

    var lua = try Lua.init(allocator);
    defer lua.deinit();
    _ = lua.atPanic(zlua.wrap(luaPanicHandler));

    // Register our modular global functions
    luabase.register(lua);
    try fs.register(lua);
    lua.openLibs();

    // 2. Create the table in Lua for our handles.
    // Because openLibs() leaves the stack empty, this table is at index 1.
    lua.newTable();

    lua.pushValue(-1);
    lua.setGlobal("files");

    // 3. Parse Environment Variables (e.g., FILE_my_log=path/to/log.txt)
    var env_it = init.environ_map.iterator();
    while (env_it.next()) |entry| {
        if (std.mem.startsWith(u8, entry.key_ptr.*, "FILE_")) {
            const name = entry.key_ptr.*[5..];
            // Strip "FILE_"
            const path = entry.value_ptr.*;
            try openAndPushFile(io, lua, name, path);
        } else if (std.mem.startsWith(u8, entry.key_ptr.*, "DIR_")) {
            const name = entry.key_ptr.*[4..];
            // Strip "DIR_"
            const path = entry.value_ptr.*;
            try openAndPushDir(io, lua, name, path);
        }
    }

    // 4. Parse CLI Options
    var script_path: ?[:0]const u8 = null;
    var ordinal: u64 = 0;
    for (args[1..]) |arg| {
        ordinal += 1;
        if (std.mem.startsWith(u8, arg, "--file=")) {
            // Parse `--file=my_handle_name=path/to/file.txt`
            const kv = arg[7..];
            if (std.mem.indexOfScalar(u8, kv, '=')) |eq_idx| {
                const name = kv[0..eq_idx];
                const path = kv[eq_idx + 1 ..];
                try openAndPushFile(io, lua, name, path);
            } else {
                std.debug.print("Invalid --file format. Expected --file=name=path\n", .{});
            }
        } else if (std.mem.startsWith(u8, arg, "--dir=")) {
            // Parse `--dir=my_dir_name=path/to/dir`
            const kv = arg[6..];
            if (std.mem.indexOfScalar(u8, kv, '=')) |eq_idx| {
                const name = kv[0..eq_idx];
                const path = kv[eq_idx + 1 ..];
                try openAndPushDir(io, lua, name, path);
            } else {
                std.debug.print("Invalid --dir format. Expected --dir=name=path\n", .{});
            }
        } else if (std.mem.eql(u8, arg, "--")) {
            break;
        } else if (script_path == null) {
            script_path = arg;
        }
    }

    lua.newTable();
    lua.pushValue(-1);
    lua.setGlobal("args");
    var lua_args_push_ordinal: zlua.Integer = 1;
    for (args[ordinal + 1..]) |arg| {
        _ = lua.pushString(arg);
        lua.setIndexRaw(-2, lua_args_push_ordinal);
        lua_args_push_ordinal += 1;
    }

    if (script_path == null) {
        std.debug.print("Usage: {s} [--file=name=path] [--dir=name=path] <script.lua>\n", .{args[0]});
        return;
    }

    // 5. Execute
    loadFileOrLuaError(lua, script_path.?, .binary_text);
    lua.call(.{.args = 0, .results = 0});
}

fn openAndPushFile(io: std.Io, lua: *Lua, name: []const u8, path: []const u8) !void {
    // Open the file on the Zig side
    const file = std.Io.Dir.cwd().openFile(io, path, .{ .mode = .read_write }) catch |err| {
        std.debug.print("Failed to open file '{s}' at '{s}': {}\n", .{name, path, err});
        return err;
    };
    
    // Inject it into the Lua table at index 1
    _ = lua.pushString(name);
    const wrapper = try fs.pushHandle(lua);
    wrapper.* = .{ .tag = .file, .io = io, .inner_file = file };
    lua.setTable(1);
}

fn openAndPushDir(io: std.Io, lua: *Lua, name: []const u8, path: []const u8) !void {
    // Open the dir on the Zig side
    const dir = std.Io.Dir.cwd().openDir(io, path, .{}) catch |err| {
        std.debug.print("Failed to open dir '{s}' at '{s}': {}\n", .{name, path, err});
        return err;
    };
    
    // Inject it into the Lua table at index 1
    _ = lua.pushString(name);
    const wrapper = try fs.pushHandle(lua);
    wrapper.* = .{ .tag = .dir, .io = io, .inner_dir = dir };
    lua.setTable(1);
}

fn loadFileOrLuaError(lua: *Lua, file_name: [:0]const u8, mode: zlua.Mode) void {
    lua.loadFile(file_name, mode) catch {
        // The error string (e.g., syntax error) is already at the top of the stack.
        // Calling Lua's error function will raise it as a proper Lua error.
        lua.raiseError();
        // lua_error performs a longjmp in C and never returns to this point.
        unreachable; 
    };
}

fn luaPanicHandler(lua: *Lua) !i32 {
    const msg = lua.toString(-1) catch "Unknown Lua panic error";
    std.debug.print("CRITICAL: Lua Panicked: {s}\n", .{msg});
    std.process.exit(1);
}
