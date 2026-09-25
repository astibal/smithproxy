### developer's todo notes

- Revisit regex search functions which return single result per a go. 

    They should return a container of matches. We can be missing some signature hits!
    
    ```c++
        range search_function(std::string &expr, std::string &str) override 
    ```

- Add a `panic` pressure level as the last-resort FD exhaustion circuit breaker.

    Trigger it from real process FD headroom, not merely from the number of
    active or deferred proxies. In panic mode preserve listeners, CLI and
    master sockets, but shed selected proxy sessions through their ownership
    path so the service survives. Never blindly `close(fd)` under a live
    object: first release ownership by setting the stored descriptor to `-1`,
    remove it from epoll, then shut down and close it, mark the proxy dead and
    move it to deferred cleanup. The polling-cycle pressure calculation must
    remain cheap and non-blocking. Cover the behavior with a deliberately low
    `RLIMIT_NOFILE` stress test and verify that management access survives.
