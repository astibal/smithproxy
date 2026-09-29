# Reloadable file resources

`FileReloadService` provides one polling thread for multiple independently
scheduled files. `ReloadableResource<T>` reads a changed file, invokes a caller
supplied parser and atomically publishes an immutable `PublishedSnapshot<T>`.
The infrastructure does not depend on JSON or on any particular payload type.

```cpp
auto resource = std::make_shared<ReloadableResource<MyData>>(
    WatchedFileOptions{"/etc/smithproxy/data.json", 4 * 1024 * 1024, true},
    [](std::string_view input) -> ParseResult<MyData> {
        return parse_my_data(input);
    });

FileReloadService reloads;
auto id = reloads.add(resource, std::chrono::seconds(5));
reloads.start();
```

Readers may always load the snapshot, or avoid the shared-pointer operation
when the atomic version has not changed:

```cpp
auto const observed_version = resource->version();
if (observed_version != local_version) {
    local_snapshot = resource->snapshot();
    local_version = local_snapshot ? local_snapshot->metadata.version : observed_version;
}
```

Publication stores the new snapshot before releasing the new version. A reader
that observes a new version with acquire semantics can therefore load the
corresponding or a newer snapshot. A snapshot already held by a reader remains
valid across later reloads.

By default, a missing, oversized, unstable or invalid file leaves the last
valid snapshot active. Setting `keep_last_on_error` to false atomically clears
the published pointer on failure and advances the version once, because that
is an observable publication-state change. `reload_now()` bypasses
file-signature suppression; it does not bypass size checks, parsing or
validation.

The producing process should update watched files using write, `fsync` and an
atomic rename. Periodic polling is intentionally retained even if an event
based wakeup is added later.
