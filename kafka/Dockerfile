FROM bitnami/java:20-debian-11
WORKDIR /kafka
COPY ./kafka /kafka
EXPOSE 9092 9093
ENTRYPOINT ["/kafka/bin/kafka-server-start.sh", "/kafka/config/server.properties"]