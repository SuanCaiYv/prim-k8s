FROM bitnami/java:20-debian-11
WORKDIR /kafka
COPY ./kafka /kafka
EXPOSE 9092 9093
RUN chmod +x /kafka/bin/*.sh
ENTRYPOINT ["sh", "-c", "cp /kafka/tmp/set-node-id.sh /etc/set-node-id.sh && chmod +x /etc/set-node-id.sh && /etc/set-node-id.sh && bin/kafka-server-start.sh config/kraft/server.properties"]