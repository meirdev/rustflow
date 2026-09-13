# Test fixtures

`test.mmdb` is built by `make_mmdb.py`, which lists the records it contains:

```sh
uv run make_mmdb.py
```

It is an IPv6 tree with the IPv4 networks under `::/96`, the way MaxMind's
own databases are laid out. Values keep their types (integers, booleans,
nested maps, arrays). Regenerate it after editing the script.
