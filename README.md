## Mock agave client and server

The `server` and `client` demonstrate how agave client/server works with quic-based TPU protocol.

1. Server (`server.rs`)

Open up a terminal and execute:

```text
$ cargo run --bin server
```

2. Client (`client.rs`)

In a new terminal execute:

```test
$ cargo run --bin client localhost:4433
```

## Questions

1. There is stream priority, why don't we use it for staking?
2. There is a Controller trait which defines Congestion Control. What is the default implementation? Why don't we use it for stake?
3. RW size and number of streams per connection are static by default? Or controlled by this Controller? 

## What to change in the original client

* There is no need to `Arc` structures (connection etc) which are clonable already.
* We use QUIC_CONNECTION_HANDSHAKE_TIMEOUT which should not be used, max_idle_timeout will determine timeout.
* PORT 0 means that it will identified by OS so why do we search manually?
* Do we want to keep alive staked connections? It is possible to achieve by setting:

```rust
transport_config.max_idle_timeout(Some(timeout));
transport_config.keep_alive_interval(Some(QUIC_KEEP_ALIVE));
```

Currently, what I found that we set one timeout of all and not `keep_alive_interval`

* Methods calling `handle_connection` do quite some locking to update connection cache, what is the impact of this on performance?
* In `handle_connection` variable `let mut maybe_batch = None;` should not exist, it should be part of the `hand_chunk`. Also error should be  handled on the level where it is received.
* Do we really need to handle chunks manually using packet accumulator?