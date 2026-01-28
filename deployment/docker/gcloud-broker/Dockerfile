FROM gcr.io/google.com/cloudsdktool/cloud-sdk:slim

RUN apt-get update && apt-get install -y \
    bash \
    coreutils \
    util-linux \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /broker

COPY broker.sh /broker/broker.sh
RUN chmod +x /broker/broker.sh

EXPOSE 50051

ENTRYPOINT ["/broker/broker.sh"]
