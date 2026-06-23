const std = @import("std");
const Io = std.Io;
const zlua = @import("zlua");

const Sha256 = std.crypto.hash.sha2.Sha256;

const incremental_lua_build_tool = @import("incremental_lua_build_tool");

const Lua = zlua.Lua;

var allocator: std.mem.Allocator = undefined;

pub fn main(init: std.process.Init) !void {
    // Accessing command line arguments:
    const args = try init.minimal.args.toSlice(init.gpa);
    defer init.gpa.free(args);
    allocator = init.gpa;

    var lua = try Lua.init(allocator);
    defer lua.deinit();
    _ = lua.atPanic(zlua.wrap(luaPanicHandler));

    lua.pushFunction(zlua.wrap(lua_sha256));
    lua.setGlobal("sha256");

    lua.pushFunction(zlua.wrap(lua_tohex));
    lua.setGlobal("tohex");

    lua.openLibs();

    if (args.len != 2) {
        std.debug.print("Wrong number of arguments!\n", .{});
        return;
    }
    try lua.loadFile(args[1], .binary_text);
    lua.call(.{.args=0, .results=0});
}

const nil_sha256 = [_]u8{0} ** Sha256.digest_length;

fn hashDumpCallback(L: ?*zlua.LuaState, item: ?*const anyopaque, size: usize, ud: ?*anyopaque) callconv(.c) c_int {
    _ = L;
    if (item == null) return 0;
    const hasher = @as(*Sha256, @ptrCast(@alignCast(ud.?)));
    const bytes = @as([*]const u8, @ptrCast(item.?))[0..size];
    hasher.update(bytes);
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
    
    const raw_arg_type = @intFromEnum(arg_type);
    const arg_type_bytes = std.mem.asBytes(&raw_arg_type);
    var hasher = Sha256.init(.{});
    hasher.update(arg_type_bytes);

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

fn luaPanicHandler(lua: *Lua) !i32 {
    const msg = lua.toString(-1) catch "Unknown Lua panic error";
    std.debug.print("CRITICAL: Lua Panicked: {s}\n", .{msg});
    std.process.exit(1);
}

test "simple test" {
    const gpa = std.testing.allocator;
    var list: std.ArrayList(i32) = .empty;
    defer list.deinit(gpa); // Try commenting this out and see if zig detects the memory leak!
    try list.append(gpa, 42);
    try std.testing.expectEqual(@as(i32, 42), list.pop());
}

test "fuzz example" {
    try std.testing.fuzz({}, testOne, .{});
}

fn testOne(context: void, smith: *std.testing.Smith) !void {
    _ = context;
    // Try passing `--fuzz` to `zig build test` and see if it manages to fail this test case!

    const gpa = std.testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    while (!smith.eos()) switch (smith.value(enum { add_data, dup_data })) {
        .add_data => {
            const slice = try list.addManyAsSlice(gpa, smith.value(u4));
            smith.bytes(slice);
        },
        .dup_data => {
            if (list.items.len == 0) continue;
            if (list.items.len > std.math.maxInt(u32)) return error.SkipZigTest;
            const len = smith.valueRangeAtMost(u32, 1, @min(32, list.items.len));
            const off = smith.valueRangeAtMost(u32, 0, @intCast(list.items.len - len));
            try list.appendSlice(gpa, list.items[off..][0..len]);
            try std.testing.expectEqualSlices(
                u8,
                list.items[off..][0..len],
                list.items[list.items.len - len ..],
            );
        },
    };
}
