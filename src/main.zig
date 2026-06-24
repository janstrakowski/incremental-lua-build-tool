const std = @import("std");
const Io = std.Io;
const zlua = @import("zlua");
const Lua = zlua.Lua;

const incremental_lua_build_tool = @import("incremental_lua_build_tool");

// Import our new module
const luabase = @import("luabase.zig");

var allocator: std.mem.Allocator = undefined;

pub fn main(init: std.process.Init) !void {
    // Accessing command line arguments:
    const args = try init.minimal.args.toSlice(init.gpa);
    defer init.gpa.free(args);
    allocator = init.gpa;
    
    // Provide the allocator to the luabase module
    luabase.allocator = allocator;

    var lua = try Lua.init(allocator);
    defer lua.deinit();
    _ = lua.atPanic(zlua.wrap(luaPanicHandler));

    // Register our modular global functions
    luabase.register(lua);

    lua.openLibs();
    
    if (args.len != 2) {
        std.debug.print("Wrong number of arguments!\n", .{});
        return;
    }
    
    try lua.loadFile(args[1], .binary_text);
    lua.call(.{.args=0, .results=0});
}

fn luaPanicHandler(lua: *Lua) !i32 {
    const msg = lua.toString(-1) catch "Unknown Lua panic error";
    std.debug.print("CRITICAL: Lua Panicked: {s}\n", .{msg});
    std.process.exit(1);
}
