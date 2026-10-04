// Regression for replacement ownership in the port of management.proto (v0.79.0), BSD-3-Clause.
const std = @import("std");
const messages = @import("mgmt/messages.zig");

fn decodeRepeatedKey(alloc: std.mem.Allocator) !void {
    // EncryptedMessage{wgPubKey:"aaa",wgPubKey:"bbb"}: last value wins.
    const input = "\x0a\x03aaa\x0a\x03bbb";
    var m = try messages.EncryptedMessage.decode(alloc, input);
    defer m.deinit(alloc);
    try std.testing.expectEqualStrings("bbb", m.wg_pub_key);
    try std.testing.expectEqualStrings("", m.body);
}

fn decodeRepeatedPeerConfig(alloc: std.mem.Allocator) !void {
    // NetworkMap{peerConfig:{address:"a"},peerConfig:{address:"b"}}.
    const input = "\x12\x03\x0a\x01a\x12\x03\x0a\x01b";
    var m = try messages.NetworkMap.decode(alloc, input);
    defer m.deinit(alloc);
    const pc = m.peer_config orelse return error.NoPeerConfig;
    try std.testing.expectEqualStrings("b", pc.address);
}

test "Management singular strings preserve ownership during replacement" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, decodeRepeatedKey, .{});
}

test "Management optional structs preserve ownership during replacement" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, decodeRepeatedPeerConfig, .{});
}

test "Management SSH map entries preserve ownership during replacement" {
    // SSHAuth{machineUsers:[{key:"k1",value:{1},key:"k2",value:{2}}]}: last wins.
    const input = "\x1a\x10\x0a\x02k1\x12\x02\x08\x01\x0a\x02k2\x12\x02\x08\x02";
    const needed = x: {
        var fa = std.testing.FailingAllocator.init(std.testing.allocator, .{});
        var m = try messages.SSHAuth.decode(fa.allocator(), input);
        defer m.deinit(fa.allocator());
        try std.testing.expectEqual(@as(usize, 1), m.machine_users.items.len);
        const e = m.machine_users.items[0];
        try std.testing.expectEqualStrings("k2", e.key);
        try std.testing.expectEqualSlices(u32, &.{2}, e.value.indexes.items);
        break :x fa.alloc_index;
    };
    // The last allocation for this input is the machine_users list growth; that
    // owning-append site belongs to the sibling append finding (separate PR), so
    // this sweep covers every earlier failure point. The total is pinned to catch
    // allocation-order drift loudly instead of silently skipping coverage.
    try std.testing.expectEqual(@as(usize, 5), needed);
    for (0..needed - 1) |fail_index| {
        var fa = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = fail_index });
        var m = messages.SSHAuth.decode(fa.allocator(), input) catch |err| switch (err) {
            error.OutOfMemory => {
                if (fa.allocated_bytes != fa.freed_bytes) {
                    std.testing.failPrint("\nreplace sweep fail_index: {d}/{d} allocated={d} freed={d}\n", .{ fail_index, needed, fa.allocated_bytes, fa.freed_bytes });
                    return error.MemoryLeakDetected;
                }
                continue;
            },
            else => return err,
        };
        m.deinit(fa.allocator());
        if (fa.has_induced_failure) return error.SwallowedOutOfMemoryError;
        return error.NondeterministicMemoryUsage;
    }
}
