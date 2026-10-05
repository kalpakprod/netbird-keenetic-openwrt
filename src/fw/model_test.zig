// Tests for the model SpecBuilder ownership contract: every arg buffer
// is freed exactly once on success, after build(), and on any
// allocation failure. Regression for xreview #60: a list-growth
// allocation failure inside arg/argf used to free the new buffer twice
// (once in the append catch, once in the errdefer) and panicked the
// testing allocator; the full sweep below now covers every allocation
// index, including the list growth steps.
const std = @import("std");
const model = @import("model.zig");

test "build transfers ownership; deinit after build frees nothing" {
    const alloc = std.testing.allocator;
    var b = model.SpecBuilder.init(alloc);
    try b.arg("-p");
    try b.argf("tcp:{d}", .{443});
    const spec = try b.build();
    defer model.freeSpec(alloc, spec);
    try std.testing.expectEqual(@as(usize, 2), spec.len);
    try std.testing.expectEqualStrings("-p", spec[0]);
    try std.testing.expectEqualStrings("tcp:443", spec[1]);
    // After toOwnedSlice the builder holds nothing; a double free or a
    // leftover buffer fails the leak check on test exit.
    b.deinit();
}

// 24 appends force several ArrayListUnmanaged growth reallocations, so
// the sweep fails both the arg dupe/allocPrint allocations and the
// list-growth allocations at every index.
fn buildGrownArgs(alloc: std.mem.Allocator) anyerror!void {
    var b = model.SpecBuilder.init(alloc);
    defer b.deinit();
    var i: usize = 0;
    while (i < 24) : (i += 1) try b.arg("--arg");
    const spec = try b.build();
    model.freeSpec(alloc, spec);
}

fn buildGrownArgf(alloc: std.mem.Allocator) anyerror!void {
    var b = model.SpecBuilder.init(alloc);
    defer b.deinit();
    var i: usize = 0;
    while (i < 24) : (i += 1) try b.argf("--port={d}", .{4000 + i});
    const spec = try b.build();
    model.freeSpec(alloc, spec);
}

test "arg frees each buffer once at every allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, buildGrownArgs, .{});
}

test "argf frees each buffer once at every allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, buildGrownArgf, .{});
}
