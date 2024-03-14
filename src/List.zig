const g = @import("g.zig");
const std = @import("std");
const testing = std.testing;
const assert = std.debug.assert;

const Node = @This();

prev: *Node,
next: *Node,

// =================== `list` ===================

/// empty list
pub fn init(list: *Node) void {
    list.prev = list;
    list.next = list;
}

/// first node
pub inline fn head(list: *const Node) *Node {
    return list.next;
}

/// last node
pub inline fn tail(list: *const Node) *Node {
    return list.prev;
}

/// `unlink(node)` and/or `free(node)` is safe
pub fn iterator(list: *const Node) Iterator {
    return .{
        .sentinel = list,
        .node = list.head(),
    };
}

/// `unlink(node)` and/or `free(node)` is safe
pub fn reverse_iterator(list: *const Node) ReverseIterator {
    return .{
        .sentinel = list,
        .node = list.tail(),
    };
}

pub const Iterator = struct {
    sentinel: *const Node,
    node: *Node,

    pub fn next(it: *Iterator) ?*Node {
        const node = it.node;
        if (node == it.sentinel) return null;
        defer it.node = node.next;
        return node;
    }
};

pub const ReverseIterator = struct {
    sentinel: *const Node,
    node: *Node,

    pub fn next(it: *ReverseIterator) ?*Node {
        const node = it.node;
        if (node == it.sentinel) return null;
        defer it.node = node.prev;
        return node;
    }
};

// =================== `node` ===================

pub fn link_head(list: *Node, node: *Node) void {
    return node.link(list, list.head());
}

pub fn link_tail(list: *Node, node: *Node) void {
    return node.link(list.tail(), list);
}

fn link(node: *Node, prev: *Node, next: *Node) void {
    prev.next = node;
    node.prev = prev;
    node.next = next;
    next.prev = node;
}

/// `node` is in undefined state
pub fn unlink(node: *Node) void {
    node.prev.next = node.next;
    node.next.prev = node.prev;
}

// =========================================================

const Object = struct {
    id: u32,
    node: Node,

    pub fn from_node(node: *Node) *Object {
        return @fieldParentPtr(Object, "node", node);
    }
};

pub fn @"test: List"() !void {
    var list: Node = undefined;
    list.init();

    defer {
        var it = list.iterator();
        while (it.next()) |node| {
            node.unlink();
            g.allocator.destroy(Object.from_node(node));
            // break;
        }

        var it2 = list.iterator();
        assert(it2.next() == null);
    }

    if (true) {
        var i: u32 = 0;
        while (i < 5) : (i += 1) {
            const obj = try g.allocator.create(Object);
            obj.id = i + 1;
            list.link_tail(&obj.node);
        }
    }

    {
        var it = list.iterator();
        var id: u32 = 1;
        while (it.next()) |node| : (id += 1) {
            const obj = Object.from_node(node);
            try testing.expectEqual(id, obj.id);
        }
    }

    {
        var it = list.reverse_iterator();
        var id: u32 = 5;
        while (it.next()) |node| : (id -= 1) {
            const obj = Object.from_node(node);
            try testing.expectEqual(id, obj.id);
        }
    }
}
