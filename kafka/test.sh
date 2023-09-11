#!/bin/sh

# Get the hostname
HOSTNAME=$(hostname)

# Define a regular expression pattern to extract the number at the end
PATTERN="([0-9]+)$"

# Check if the hostname matches the expected format
if [[ $HOSTNAME =~ $PATTERN ]]; then
  # Extract the number from the hostname
  NODE_ID=${BASH_REMATCH[1]}

  # Set the NODE_ID as an environment variable
  export KAFKA_CFG_NODE_ID="$NODE_ID"

  # Print a message indicating success
  echo "Parsed NODE_ID: $KAFKA_CFG_NODE_ID"
else
  # Print an error message if the hostname does not match the expected format
  echo "Error: Hostname does not match the expected format: $HOSTNAME"
fi
