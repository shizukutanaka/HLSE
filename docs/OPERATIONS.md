# OPERATIONS.md — running HLSE in production

Minimal path from clone to a supervised, CI-gated deployment. Everything
here is verified against the shipped Makefile and binaries.

## 1. Install (rootless or system)

```sh
make                              # hlse_core + libhlse.so + hlse-server + hlsed
make check-warnings               # 0 warnings (CLI and library builds)
./hlse_core --benchmark           # F1 = 1.000, FP = 0.0%

# rootless (default PREFIX=$HOME/.local):
make install
export PATH="$HOME/.local/bin:$PATH"

# or system-wide:
sudo make install PREFIX=/usr
```

Install layout: `bin/{hlse_core,hlse-server,hlsed}`,
`lib/libhlse.so` + `lib/pkgconfig/hlse.pc`,
`include/hlse/*.h`, `share/man/man1/{hlse,hlse-server,hlsed}.1`,
`share/hlse/web/*` (compiled-in default webroot for hlse-server).
`DESTDIR` is supported for packaging:
`make install DESTDIR=/tmp/pkgroot PREFIX=/usr`.

## 2. Enable CI (one manual step)

`.github/workflows/` cannot be written by automation, so the three
shipped workflows live in `examples/workflows/`:

```sh
make install-workflows     # copies ci.yml, codeql.yml, release.yml
git add .github/workflows && git commit -m "enable CI"
```

CI then enforces on every push: `make all`, `make test`,
`make check-warnings`, `make asan-test`, `make fuzz`, `cppcheck`,
plus a Linux build (`make static` on release tags).

## 3. Run the resident monitor (hlsed)

```sh
sudo mkdir -p /etc/hlse
sudo cp examples/hlsed.conf /etc/hlse/hlsed.conf   # edit watch= lines
hlsed --check /etc/hlse/hlsed.conf                  # validate first
sudo cp examples/hlsed.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now hlsed
systemctl status hlsed
```

`hlsed` is a poll-based FIM (portable: Linux + macOS, rootless-capable).
`SIGHUP` reloads config; `SIGTERM`/`SIGINT` exits cleanly; the pid file
is flock-protected against double-start. Alerts go to the configured
`hlse_alert` sinks (see `man hlsed`). Set `state-file` in the config to
persist the dedup table across restarts (path/mtime/size tuples only).

## 4. Verify the deployment

```sh
hlse_core --version
hlse_core --benchmark | tail -3            # F1 1.000 / FP 0.0%
hlsed --check /etc/hlse/hlsed.conf          # exit 0
journalctl -u hlsed -f                      # watch the monitor
```

## 5. Upgrade / remove

```sh
git pull && make && make check-warnings && make test   # re-verify
sudo make install PREFIX=/usr
sudo systemctl restart hlsed

# remove:
sudo make uninstall PREFIX=/usr
sudo systemctl disable --now hlsed && sudo rm /etc/systemd/system/hlsed.service
```
