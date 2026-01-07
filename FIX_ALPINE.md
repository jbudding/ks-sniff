# Fixing libpcap Linking Issue on Alpine Linux

## The Problem

Alpine Linux uses musl libc and Rust tries to statically link libraries by default. However, the `libpcap-dev` package on Alpine doesn't include a static library (`libpcap.a`), and is missing the unversioned symlink (`libpcap.so`).

## Solution (Run with elevated privileges)

You need to run these commands as root/sudo to fix the libpcap installation:

### Option 1: Create the missing symlink (Recommended)

```bash
sudo ln -sf /usr/lib/libpcap.so.1.10.5 /usr/lib/libpcap.so
```

After creating the symlink, the build should work.

### Option 2: Reinstall libpcap-dev

Sometimes reinstalling helps:

```bash
sudo apk del libpcap-dev
sudo apk add libpcap-dev
sudo ln -sf /usr/lib/libpcap.so.1 /usr/lib/libpcap.so
```

## Verification

After running the above commands, verify the symlinks exist:

```bash
ls -la /usr/lib/libpcap*
```

You should see:
```
libpcap.so -> libpcap.so.1.10.5 (or libpcap.so.1)
libpcap.so.1 -> libpcap.so.1.10.5
libpcap.so.1.10.5
```

Then try building again:

```bash
cargo build --release
```

## Alternative: Use Docker

If you can't modify system libraries, you can build in a Docker container:

```bash
# Create a Dockerfile
cat > Dockerfile <<'EOF'
FROM rust:alpine

RUN apk add --no-cache libpcap-dev musl-dev && \
    ln -sf /usr/lib/libpcap.so.1 /usr/lib/libpcap.so

WORKDIR /app
COPY . .

RUN cargo build --release
EOF

# Build
docker build -t ks-sniff .
```

## What We Already Did

We created `.cargo/config.toml` which configures Rust to use dynamic linking instead of static linking. This helps, but you still need the `libpcap.so` symlink to exist.

## If You Have Root Access Now

Simply run:
```bash
sudo ln -sf /usr/lib/libpcap.so.1.10.5 /usr/lib/libpcap.so
cargo clean
cargo build --release
```
