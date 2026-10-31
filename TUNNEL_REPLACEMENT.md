# Tunnel replacement

Under `[tunnel]`:

```toml
max_age_seconds = 3600
 drain_seconds = 180
rtt_rebuild = true
idle_timeout_seconds = 180
```

`max_age_seconds = 0` disables age-triggered replacement. Each successful
connection gets an expiry up to 1/12 of its maximum age early (capped at
300 seconds). `drain_seconds = 0` closes the predecessor on the next
maintenance tick after successful takeover.

Each admission slot creates its own replacement. The predecessor continues
accepting requests until the replacement WebSocket connection is established.
Takeover happens immediately after connection establishment, without sending
a readiness Ping or waiting for Pong. Regular keepalive and RTT sampling remain independent.
The admission switch is serialized with request allocation. Existing handlers
remain on the predecessor until they finish or the drain deadline expires.
A failed replacement retries with 3–30 second backoff without retiring the old
connection. There is at most one pending replacement or draining predecessor
per slot. Stop cancels retry waits and closes active, pending and draining
connections. A genuine connection failure can still interrupt traffic.

RTT uses locally recorded monotonic send times, matched to the timestamp in
the returned Pong. Duplicate, unsolicited and malformed Pongs are ignored.
The current median covers 60 seconds and requires three samples. The historical
median covers the preceding ten minutes, excluding the current minute, and
requires six samples. The first 120 seconds are a warm-up period.

An anomaly is current RTT > 3 times the peer median and > 200 ms higher, or
current RTT > 3 times its historical median and > 300 ms higher. It must persist
for 60 seconds. With one tunnel, only historical comparison applies. RTT-triggered
replacement starts are separated by at least five minutes across the manager.
These detector thresholds are currently code defaults in remote/rebuild.go.
Age replacement remains useful because Pong latency does not measure throughput.

TCP idle expiry uses the existing remote close message. UDP endpoints expire
independently; no new wire protocol is introduced. Forced drain interrupts any
remaining long-lived sessions. Reverse-proxy connections arriving from the server
are not migrated between tunnels.
