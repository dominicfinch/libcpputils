FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# -------------------------------------------------------------------
# 1. System dependencies (ALL REQUIRED)
# -------------------------------------------------------------------
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    cmake \
    ninja-build \
    pkg-config \
    curl \
    ca-certificates \
    libssl-dev \
    libcurl4-openssl-dev \
    libprotobuf-dev \
    protobuf-compiler \
    libgrpc++-dev \
    libgrpc-dev \
    zlib1g-dev \
 && rm -rf /var/lib/apt/lists/*

# -------------------------------------------------------------------
# 2. Clone google-cloud-cpp (PIN A TAG)
# -------------------------------------------------------------------
WORKDIR /opt
RUN git clone https://github.com/googleapis/google-cloud-cpp.git
WORKDIR /opt/google-cloud-cpp

# 🔒 Pin to a known stable release
RUN git checkout v2.38.0

# -------------------------------------------------------------------
# 3. Configure build (DISABLE TESTS & BENCHMARKS)
# -------------------------------------------------------------------
RUN cmake -S . -B build \
    -GNinja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=/usr/local \
    -DBUILD_TESTING=OFF \
    -DBUILD_BENCHMARKS=OFF \
    -DGOOGLE_CLOUD_CPP_ENABLE_EXAMPLES=OFF \
    -DGOOGLE_CLOUD_CPP_ENABLE=storage

# -------------------------------------------------------------------
# 4. Build & install
# -------------------------------------------------------------------
RUN cmake --build build -j \
 && cmake --install build

# -------------------------------------------------------------------
# 5. Sanity check
# -------------------------------------------------------------------
RUN ldconfig \
 && ls /usr/local/lib | grep google_cloud_cpp_storage
