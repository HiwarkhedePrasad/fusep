# ═══════════════════════════════════════════════════════════════════════
#  FuseViz Enterprise — Multi-Stage Production Dockerfile (C++20)
#
#  Stage 1: eBPF byte compilation
#  Stage 2: C++20 daemon build (libbpf + simple_ws + SQLite3)
#  Stage 3: Next.js UI build
#  Stage 4: Production runtime image
# ═══════════════════════════════════════════════════════════════════════

# ── Stage 1: eBPF bytecode compilation ──
FROM ubuntu:22.04 AS ebpf-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang llvm linux-headers-generic bpftool \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build/ebpf
COPY ebpf/ .

RUN clang -target bpf -g -O2 -D__TARGET_ARCH_x86 \
    -I/usr/include/x86_64-linux-gnu \
    -c fuse_trace.bpf.c -o fuse_trace.bpf.o

# ── Stage 2: C++20 daemon build ──
FROM ubuntu:22.04 AS cpp-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake git \
    libbpf-dev libsqlite3-dev libz-dev \
    g++-12 \
    && rm -rf /var/lib/apt/lists/*

# Set GCC 12 as default (C++20 full support)
RUN update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-12 100 && \
    update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-12 100

WORKDIR /build/daemon
COPY daemon/CMakeLists.txt .
COPY daemon/include/ include/
COPY daemon/src/ src/

# Create placeholder for ebpf headers (will be copied from stage 1)
RUN mkdir -p ../ebpf

RUN cmake -B build -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_CXX_COMPILER=g++-12 && \
    cmake --build build -j$(nproc)

# ── Stage 3: Next.js UI build ──
FROM node:20-bookworm AS ui-builder

WORKDIR /build

# Install pnpm (matches project lock file)
RUN npm install -g pnpm

COPY package.json pnpm-lock.yaml* package-lock.json* ./
RUN pnpm install --frozen-lockfile 2>/dev/null || npm ci

COPY . .
RUN pnpm build 2>/dev/null || npm run build

# ── Stage 4: Production runtime ──
FROM ubuntu:22.04 AS production

LABEL maintainer="FuseViz Team"
LABEL description="Enterprise FUSE Protocol Observability Platform (C++20)"
LABEL version="2.0.0-cpp"

RUN apt-get update && apt-get install -y --no-install-recommends \
    fuse3 fusermount3 fio ca-certificates curl libsqlite3-0 \
    && rm -rf /var/lib/apt/lists/*

# Copy eBPF bytecode
COPY --from=ebpf-builder /build/ebpf/fuse_trace.bpf.o /opt/fuseviz/ebpf/
COPY --from=ebpf-builder /build/ebpf/fuse_trace.h /opt/fuseviz/ebpf/

# Copy C++ daemon
COPY --from=cpp-builder /build/daemon/build/fuseviz-daemon /usr/local/bin/

# Copy Next.js UI
COPY --from=ui-builder /build/.next/standalone /opt/fuseviz/ui/
COPY --from=ui-builder /build/.next/static /opt/fuseviz/ui/.next/static
COPY --from=ui-builder /build/public /opt/fuseviz/ui/public

# Copy benchmark scripts
COPY deploy/benchmark/ /opt/fuseviz/benchmark/

# Configuration
COPY deploy/fuseviz.conf /etc/fuseviz/fuseviz.conf

RUN mkdir -p /var/lib/fuseviz /mnt/fuseviz && \
    groupadd -r fuseviz && \
    useradd -r -g fuseviz -d /var/lib/fuseviz -s /sbin/nologin fuseviz

ENV FUSEVIZ_DB_PATH=/var/lib/fuseviz/events.db
ENV FUSEVIZ_BPF_OBJ=/opt/fuseviz/ebpf/fuse_trace.bpf.o
ENV FUSEVIZ_OLLAMA_URL=http://ollama:11434

EXPOSE 8080 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/api/health || exit 1

COPY deploy/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["/usr/local/bin/fuseviz-daemon"]
