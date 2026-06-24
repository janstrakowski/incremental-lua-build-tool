const std = @import("std");
const zlua = @import("zlua");
const Lua = zlua.Lua;
const builtin = @import("builtin");

const Sha256 = std.crypto.hash.sha2.Sha256;

// Module-level allocator to be initialized by main.zig
pub var allocator: std.mem.Allocator = undefined;

/// Registers the base functions to the provided Lua state
pub fn register(lua: *Lua) void {
    lua.pushFunction(zlua.wrap(lua_sha256));
    lua.setGlobal("sha256");

    lua.pushFunction(zlua.wrap(lua_tohex));
    lua.setGlobal("tohex");

    lua.pushFunction(zlua.wrap(lua_serialize));
    lua.setGlobal("serialize");

    lua.pushFunction(zlua.wrap(lua_deserialize));
    lua.setGlobal("deserialize");
}

// --- Internal Helper Methods & Structs ---

fn hashDumpCallback(L: ?*zlua.LuaState, item: ?*const anyopaque, size: usize, ud: ?*anyopaque) callconv(.c) c_int {
    _ = L;
    if (item == null) return 0;
    const hasher = @as(*Sha256, @ptrCast(@alignCast(ud.?)));
    const bytes = @as([*]const u8, @ptrCast(item.?))[0..size];
    hasher.update(bytes);
    return 0;
}

threadlocal var thread_last_error: ?anyerror = null;

fn arraylistDumpCallback(L: ?*zlua.LuaState, item: ?*const anyopaque, size: usize, ud: ?*anyopaque) callconv(.c) c_int {
    _ = L;
    if (item == null) return 0;
    const arraylist = @as(*std.ArrayList(u8), @ptrCast(@alignCast(ud.?)));
    const bytes = @as([*]const u8, @ptrCast(item.?))[0..size];
    arraylist.appendSlice(allocator, bytes) catch |err| {
        thread_last_error = err;
        return -1;
    };
    return 0;
}

const hashkv = struct {
    key: [Sha256.digest_length]u8,
    value: [Sha256.digest_length]u8
};

fn lessThanByKey(context: void, a: hashkv, b: hashkv) bool {
    _ = context;
    return std.mem.order(u8, &a.key, &b.key) == .lt;
}

// --- Lua C-Functions ---

fn lua_tohex(lua: *Lua) !i32 {
    const string = try lua.toString(1);
    const hex_string = try std.fmt.allocPrint(
        allocator,
        "{x}",
        .{string}
    );
    defer allocator.free(hex_string);
    _ = lua.pushString(hex_string);
    return 1;
}

fn lua_sha256(lua: *Lua) !i32 {
    // TODO: sha256 metamethod
    const arg_type = lua.typeOf(1);
    lua.argCheck(arg_type != .thread, 1, "a thread is not hashable");
    lua.argCheck(arg_type != .light_userdata, 1, "a light user data is not supported now");
    lua.argCheck(arg_type != .userdata, 1, "an user data is not supported now");
    
    // Safely cast i5 enum to i8, then bitcast to a u8 byte for hashing
    const raw_arg_type_u8: u8 = @bitCast(@as(i8, @intCast(@intFromEnum(arg_type))));
    
    var hasher = Sha256.init(.{});
    hasher.update(&[_]u8{raw_arg_type_u8});

    switch (arg_type) {
        .nil => {},
        .boolean => {
            hasher.update(&[_]u8{@intFromBool(lua.toBoolean(1))});
        },
        .number => {
            const number = try lua.toNumber(1);
            hasher.update(std.mem.asBytes(&[_]u64{@bitCast(number)}));
        },
        .string => {
            hasher.update(try lua.toString(1));
        },
        .function => {
            try lua.dump(hashDumpCallback, &hasher, true);
        },
        .table => {
            var kvs: std.ArrayList(hashkv) = .empty;
            defer kvs.deinit(allocator);

            lua.pushNil();
            while (lua.next(1)) {
                // Hash the key
                lua.pushFunction(zlua.wrap(lua_sha256));
                lua.pushValue(-3);
                lua.call(.{.args = 1, .results = 1});
                const key = try lua.toString(-1);
                lua.pop(1);
                
                // Hash the value
                lua.pushFunction(zlua.wrap(lua_sha256));
                lua.pushValue(-2);
                lua.call(.{.args = 1, .results = 1});
                const value = try lua.toString(-1);
                lua.pop(1);
                
                try kvs.append(allocator, .{
                    .key = key[0..Sha256.digest_length].*,
                    .value = value[0..Sha256.digest_length].*
                });
                lua.pop(1);
            }

            hasher.update(&std.mem.toBytes(kvs.items.len));

            std.mem.sort(hashkv, kvs.items, {}, lessThanByKey);
            for (kvs.items) |kv| {
                hasher.update(&kv.key);
                hasher.update(&kv.value);
            }
        },
        else => unreachable
    }

    var out_hash: [Sha256.digest_length]u8 = undefined;
    hasher.final(&out_hash);
    _ = lua.pushString(&out_hash);
    return 1;
}

fn lua_serialize(lua: *Lua) !i32 {
    // TODO: serialize metamethod
    const arg_type = lua.typeOf(1);
    lua.argCheck(arg_type != .thread, 1, "a thread is not serializable");
    lua.argCheck(arg_type != .light_userdata, 1, "a light user data is not supported now");
    lua.argCheck(arg_type != .userdata, 1, "an user data is not supported now");

    var buffer : std.ArrayList(u8) = .empty;
    defer buffer.deinit(allocator);

    // Safely cast i5 enum to i8, then bitcast to a u8 byte for writing
    const raw_arg_type_u8: u8 = @bitCast(@as(i8, @intCast(@intFromEnum(arg_type))));
    try buffer.appendSlice(allocator, &[_]u8{raw_arg_type_u8});

    switch (arg_type) {
        .nil => {},
        .boolean => {
            try buffer.appendSlice(allocator, &[_]u8{@intFromBool(lua.toBoolean(1))});
        },
        .number => {
            const number = try lua.toNumber(1);
            try buffer.appendSlice(allocator, std.mem.asBytes(&[_]u64{@bitCast(number)}));
        },
        .string => {
            const string = try lua.toString(1);
            const string_length: u64 = string.len;
            try buffer.appendSlice(allocator, std.mem.asBytes(&[_]u64{string_length}));
            try buffer.appendSlice(allocator, string);
        },
        .function => {
            // 1. Get the source name via Lua debug info
            lua.pushValue(1); 
            var ar: zlua.DebugInfo = undefined; // Note: Use zlua.c.lua_Debug if your wrapper doesn't alias it
            // ">S" pops the function at the top of the stack and populates 'source'
            _ = lua.getInfo(.{.@">" = true, .S = true}, &ar); 
            const source_str = ar.source;

            // 2. Serialize the source name string length and data
            try buffer.appendSlice(allocator, std.mem.asBytes(&[_]u64{source_str.len}));
            try buffer.appendSlice(allocator, source_str);

            // 3. Remember where the bytecode length prefix will live
            const len_index = buffer.items.len;
            
            // 4. Append 8 dummy bytes as a placeholder for bytecode length
            try buffer.appendSlice(allocator, &[_]u8{0} ** 8);
            const start_dump_index = buffer.items.len;

            // 5. Dump directly into the main buffer WITHOUT stripping (strip = false)
            try lua.dump(arraylistDumpCallback, &buffer, false);
            
            // 6. Calculate exactly how many bytes were dumped
            const bytecode_len: u64 = buffer.items.len - start_dump_index;
            
            // 7. Backfill the actual length into our placeholder slot
            std.mem.writeInt(u64, buffer.items[len_index .. len_index + 8][0..8], bytecode_len, builtin.cpu.arch.endian());
        },
        .table => {
            lua.pushNil();
            while (lua.next(1)) {
                // Serialize and append the key
                lua.pushFunction(zlua.wrap(lua_serialize));
                lua.pushValue(-3);
                lua.call(.{.args = 1, .results = 1});
                try buffer.appendSlice(allocator, try lua.toString(-1));
                lua.pop(1);
                
                // Hash the value
                lua.pushFunction(zlua.wrap(lua_serialize));
                lua.pushValue(-2);
                lua.call(.{.args = 1, .results = 1});
                try buffer.appendSlice(allocator, try lua.toString(-1));
                lua.pop(2);
            }

            // Write our explicitly structured nil type byte
            const lua_nil_type_u8: u8 = @bitCast(@as(i8, @intCast(@intFromEnum(zlua.LuaType.nil))));
            try buffer.appendSlice(allocator, &[_]u8{lua_nil_type_u8});
        },
        else => unreachable
    }
    _ = lua.pushString(buffer.items);
    return 1;
}

/// Recursively reads from the buffer, advances the slice pointer, and pushes values to the Lua stack.
fn deserializeInternal(lua: *Lua, buffer: *[]const u8) !void {
    if (buffer.*.len < 1) return error.BufferTooSmall;
    
    const raw_type_u8 = buffer.*[0];
    buffer.* = buffer.*[1..]; // Advance past the type byte

    // Safely truncate to u5 first to preserve bit layout, then bitcast to i5
    const raw_type_i5: i5 = @bitCast(@as(u5, @truncate(raw_type_u8)));
    const lua_type = std.enums.fromInt(zlua.LuaType, raw_type_i5) orelse {
        return error.InvalidLuaType;
    };

    switch (lua_type) {
        .nil => {
            lua.pushNil();
        },
        .boolean => {
            if (buffer.*.len < 1) return error.BufferTooSmall;
            const bool_byte = buffer.*[0];
            buffer.* = buffer.*[1..];
            lua.pushBoolean(bool_byte != 0);
        },
        .number => {
            if (buffer.*.len < 8) return error.BufferTooSmall;
            const num_bytes = buffer.*[0..8];
            buffer.* = buffer.*[8..];
            
            const u64_val = std.mem.readInt(u64, num_bytes[0..8], builtin.cpu.arch.endian());
            lua.pushNumber(@bitCast(u64_val));
        },
        .string => {
            if (buffer.*.len < 8) return error.BufferTooSmall;
            const len_bytes = buffer.*[0..8];
            buffer.* = buffer.*[8..];
            
            const string_len = std.mem.readInt(u64, len_bytes[0..8], builtin.cpu.arch.endian());

            if (buffer.*.len < string_len) return error.BufferTooSmall;
            const string_data = buffer.*[0..string_len];
            buffer.* = buffer.*[string_len..];

            _ = lua.pushString(string_data);
        },
        .function => {
            // 1. Read source string length
            if (buffer.*.len < 8) return error.BufferTooSmall;
            const source_len_bytes = buffer.*[0..8];
            buffer.* = buffer.*[8..];
            const source_len = std.mem.readInt(u64, source_len_bytes[0..8], builtin.cpu.arch.endian());

            // 2. Read source string data
            if (buffer.*.len < source_len) return error.BufferTooSmall;
            const source_data = buffer.*[0..source_len];
            buffer.* = buffer.*[source_len..];

            // 3. Convert to null-terminated string for loadBuffer51 'name' arg
            // We use the module-level allocator to create a sentinel slice
            const source_name_z = try allocator.allocSentinel(u8, source_data.len, 0);
            defer allocator.free(source_name_z);
            @memcpy(source_name_z[0..source_data.len], source_data);

            // 4. Read bytecode length
            if (buffer.*.len < 8) return error.BufferTooSmall;
            const len_bytes = buffer.*[0..8];
            buffer.* = buffer.*[8..];
            const bytecode_len = std.mem.readInt(u64, len_bytes[0..8], builtin.cpu.arch.endian());

            // 5. Read bytecode
            if (buffer.*.len < bytecode_len) return error.BufferTooSmall;
            const bytecode = buffer.*[0..bytecode_len];
            buffer.* = buffer.*[bytecode_len..];

            // 6. Load buffer with the extracted source name
            try lua.loadBuffer(bytecode, source_name_z, .binary);
        }, 
        .table => {
            // Push an empty table to the stack
            lua.newTable();
            while (true) {
                if (buffer.*.len < 1) return error.BufferTooSmall;
                
                // Peek at the next byte to check for the terminator (.nil)
                const next_type_u8 = buffer.*[0];
                const next_type_i5: i5 = @bitCast(@as(u5, @truncate(next_type_u8)));
                const next_type = std.enums.fromInt(zlua.LuaType, next_type_i5) orelse {
                    return error.InvalidLuaType;
                };

                // If we encounter a nil byte, the table is finished
                if (next_type == .nil) {
                    buffer.* = buffer.*[1..];
                    // Consume the nil byte
                    break;
                }

                // 1. Recurse to push the Key
                try deserializeInternal(lua, buffer);
                
                // 2. Recurse to push the Value
                try deserializeInternal(lua, buffer);
                
                // 3. Assign the key-value pair to the table
                // Current Stack: [..., table, key, value]
                // The table is at index -3. setTable pops the key and value.
                lua.setTable(-3);
            }
        },
        else => return error.UnsupportedLuaType,
    }
}

// --- 2. Lua C-Function Wrapper ---

fn lua_deserialize(lua: *Lua) !i32 {
    const buffer_str = try lua.toString(1);
    // We create a mutable slice variable that points to our buffer data
    var buffer_slice: []const u8 = buffer_str;
    // Pass a pointer to the slice so `deserializeInternal` can advance it natively
    try deserializeInternal(lua, &buffer_slice);
    // The root object will be left cleanly at the top of the Lua stack
    return 1;
}
