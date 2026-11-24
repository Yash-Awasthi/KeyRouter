// Address and time-window rules, tested directly: no worker, no storage, no network.
import { test } from "node:test";
import assert from "node:assert/strict";
import { inRange, parseIp, withinHours } from "./net.js";

test("an overnight window survives a daylight-saving change in both directions", async () => {
  const night = { days: [0, 6], start: "22:00", end: "06:00", tz: "America/New_York" };
  // 2026-11-01 falls back at 02:00, so 01:30 local happens twice; both must count the same way.
  assert.ok(withinHours(night, new Date("2026-11-01T05:30:00Z")), "01:30 on the first pass");
  assert.ok(withinHours(night, new Date("2026-11-01T06:30:00Z")), "01:30 on the second pass");
  assert.ok(!withinHours(night, new Date("2026-11-01T11:00:00Z")), "06:00 local is the exclusive end, whatever the offset");
  // 2026-03-08 skips 02:00 entirely; 01:59 and 03:00 are both inside the window.
  assert.ok(withinHours(night, new Date("2026-03-08T06:59:00Z")), "01:59 EST");
  assert.ok(withinHours(night, new Date("2026-03-08T07:00:00Z")), "03:00 EDT, an hour later by the clock and the same minute of the window");
  // start == end means the whole day, and still respects the day list.
  const allDay = { days: [1], start: "00:00", end: "00:00", tz: "America/New_York" };
  assert.ok(withinHours(allDay, new Date("2026-11-02T12:00:00Z")), "Monday, any minute");
  assert.ok(!withinHours(allDay, new Date("2026-11-01T12:00:00Z")), "Sunday is not in the list");
});

test("address matching handles /0, ::1, mapped IPv4 and malformed CIDRs", async () => {
  // /0 matches everything of its own family and nothing of the other.
  assert.ok(inRange("1.2.3.4", "0.0.0.0/0"));
  assert.ok(!inRange("2001:db8::1", "0.0.0.0/0"));
  assert.ok(inRange("2001:db8::1", "::/0"));
  assert.ok(!inRange("1.2.3.4", "::/0"));
  // The loopback address in both spellings.
  assert.equal(parseIp("::1").n, 1n);
  assert.ok(inRange("::1", "::1"));
  assert.ok(inRange("::1", "::1/128"));
  assert.ok(!inRange("::2", "::1/128"));
  assert.ok(inRange("127.0.0.1", "127.0.0.0/8"));
  // A mapped address is an IPv6 address: it only matches an IPv6 range, never the bare IPv4 one.
  assert.equal(parseIp("::ffff:10.0.0.1").bits, 128);
  assert.ok(!inRange("::ffff:10.0.0.1", "10.0.0.0/8"), "mapped is not the same family");
  assert.ok(inRange("::ffff:10.0.0.1", "::ffff:10.0.0.0/104"));
  assert.ok(!inRange("10.0.0.1", "::ffff:10.0.0.0/120"));
  // A malformed range never matches, so a bad allowlist entry cannot accidentally allow everything.
  for (const bad of ["10.0.0.0/33", "10.0.0.0/-1", "10.0.0.0/abc", "10.0.0.0//24", "10.0.0.0/24/1", "::/129", "not-an-ip", ""]) {
    assert.equal(inRange("10.0.0.1", bad), false, bad);
  }
});
