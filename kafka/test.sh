#!/bin/bash

# Step 1: Read cluster-id from /kafka/tmp/cluster.id
cluster_id=$(head -n 1 ./cluster.id)

# Check if cluster_id is empty or contains only whitespace
if [[ -z "$cluster_id" || "$cluster_id" =~ ^[[:space:]]+$ ]]; then
  echo "Error: Cluster ID is empty or contains only whitespace."
  exit 1
fi

echo "Cluster ID: $cluster_id"

# Step 2: Check if "inited" file exists in /kafka/data
if [ -f ./inited ]; then
  echo "Error: 'inited' file already exists. Aborting."
  exit 0
fi

# Step 3: Run the kafka-storage.sh command with the cluster-id
# kafka/bin/kafka-storage.sh format -t "$cluster_id" -c kafka/tmp/server.properties

# Step 4: Create the "inited" file in /kafka/data
touch ./inited