# Tunnel replacement

Under `[tunnel]`:

```toml
max_age_seconds = 3600
 drain_seconds = 180
idle_timeout_seconds = 180
```

`max_age_seconds = 0` disables age-triggered replacement. Each successful
connection gets an expiry up to 1/12 of its maximum age early (capped at
300 seconds). `drain_seconds = 0` closes the predecessor on the next
maintenance tick after successful takeover.

Each admission slot creates its own replacement. The predecessor continues
accepting requests until the replacement WebSocket connection is established.
Takeover happens immediately after connection establishment, without sending
a readiness Ping or waiting for Pong. Regular idle keepalive remains independent.
The admission switch is serialized with request allocation. Existing handlers
remain on the predecessor until they finish or the drain deadline expires.
A failed replacement retries with 3–30 second backoff without retiring the old
connection. There is at most one pending replacement or draining predecessor
per slot. Stop cancels retry waits and closes active, pending and draining
connections. A genuine connection failure can still interrupt traffic.

Replacement is triggered only by connection age, never by RTT.
Keepalive Ping is sent only after the configured interval without incoming
or successfully sent business data. Either direction resets the idle timer;
incoming data also clears the unanswered Ping count. Pings reset the timer.
Pong validation and optional latency logging remain, without RTT history.

TCP idle expiry uses the existing remote close message. UDP endpoints expire
independently; no new wire protocol is introduced. Forced drain interrupts any
remaining long-lived sessions. Reverse-proxy connections arriving from the server
are not migrated between tunnels.
