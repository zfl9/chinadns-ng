const std = @import("std");
const g = @import("g.zig");
const testing = std.testing;
const assert = std.debug.assert;

// =====================================================

const Node = @This();

prev: *Node,
next: *Node,

// =================== `list_head(sentinel)` ===================

/// empty list (sentinel node)
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

/// is sentinel node
pub inline fn is_empty(list: *const Node) bool {
    return list.head() == list;
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
        if (node != it.sentinel) {
            it.node = node.next;
            return node;
        }
        return null;
    }
};

pub const ReverseIterator = struct {
    sentinel: *const Node,
    node: *Node,

    pub fn next(it: *ReverseIterator) ?*Node {
        const node = it.node;
        if (node != it.sentinel) {
            it.node = node.prev;
            return node;
        }
        return null;
    }
};

// =================== `node` ===================

pub fn link_to_head(list: *Node, node: *Node) void {
    return node.link(list, list.head());
}

pub fn link_to_tail(list: *Node, node: *Node) void {
    return node.link(list.tail(), list);
}

/// assume that the `node` is linked to the `list`
pub fn move_to_head(list: *Node, node: *Node) void {
    if (node != list.head()) {
        node.unlink();
        list.link_to_head(node);
    }
}

/// assume that the `node` is linked to the `list`
pub fn move_to_tail(list: *Node, node: *Node) void {
    if (node != list.tail()) {
        node.unlink();
        list.link_to_tail(node);
    }
}

fn link(node: *Node, prev: *Node, next: *Node) void {
    prev.next = node;
    node.prev = prev;
    node.next = next;
    next.prev = node;
}

/// `node.prev` and `node.next` are unmodified, use `node.init()` if needed.
/// `list_head.unlink()` is not allowed unless `list_head` is an empty list.
pub fn unlink(node: *Node) void {
    node.prev.next = node.next;
    node.next.prev = node.prev;
    node.prev = undefined;
    node.next = undefined;
}

// =========================================================

const Object = struct {
    id: u32,
    node: Node,

    pub fn from_node(node: *Node) *Object {
        return @fieldParentPtr(Object, "node", node);
    }
};

pub fn @"test: linked list"() !void {
    var list: Node = undefined;
    list.init();

    defer {
        var it = list.iterator();
        while (it.next()) |node| {
            node.unlink();
            g.allocator.destroy(Object.from_node(node));
            // break;
        }

        assert(list.is_empty());

        list.unlink();
        list.unlink();
        assert(list.is_empty());
    }

    {
        var i: u32 = 1;
        while (i <= 5) : (i += 1) {
            const obj = try g.allocator.create(Object);
            obj.id = i;
            list.link_to_tail(&obj.node);
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

    {
        // [1,2,3,4,5] => [1,3,4]
        var it = list.iterator();
        while (it.next()) |node| {
            const obj = Object.from_node(node);
            if (obj.id == 2 or obj.id == 5) {
                node.unlink();
                g.allocator.destroy(obj);
            }
        }

        var i: u32 = 0;
        const ids = [_]u32{ 1, 3, 4 };
        var it2 = list.iterator();
        while (it2.next()) |node| : (i += 1) {
            const obj = Object.from_node(node);
            try testing.expectEqual(ids[i], obj.id);
        }
    }

    // link_to_head
    var l: Node = undefined;
    l.init();

    defer {
        var it = l.iterator();
        while (it.next()) |node| {
            node.unlink();
            const obj = Object.from_node(node);
            g.allocator.destroy(obj);
        }

        assert(l.is_empty());

        l.unlink();
        assert(l.is_empty());
    }

    {
        var i: u32 = 3;
        while (i > 0) : (i -= 1) {
            const obj = try g.allocator.create(Object);
            obj.id = i;
            l.link_to_head(&obj.node);
        }
    }

    {
        var id: u32 = 1;
        var it = l.iterator();
        while (it.next()) |node| : (id += 1) {
            const obj = Object.from_node(node);
            try testing.expectEqual(id, obj.id);
        }
    }

    {
        var id: u32 = 3;
        var it = l.reverse_iterator();
        while (it.next()) |node| : (id -= 1) {
            const obj = Object.from_node(node);
            try testing.expectEqual(id, obj.id);
        }
    }
}
