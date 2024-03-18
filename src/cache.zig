const c = @import("c.zig");
const dns = @import("dns.zig");

const ReplyData = struct {
    last_hit: c.time_t, // last hit time
    len: u16, // data length
    // data: []u8, // {question, answer, authority, additional}

    pub fn data(self: *ReplyData) []u8 {
        _ = self;
        // return
    }
};

// _cache =
