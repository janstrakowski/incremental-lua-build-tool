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
    
    loadFileOrLuaError(lua, args[1], .binary_text);
    lua.call(.{.args=0, .results=0});
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
