FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    build-essential cmake git pkg-config \
    libpq-dev libpqxx-dev \
    libssl-dev

WORKDIR /app
COPY . /app
RUN cmake -S . -B build && cmake --build build -j4
CMD ["./build/your_server"]
