#!/bin/bash

# Read the hostname as input
hostname_input=$(hostname)

# Define a regular expression pattern to match the format "xxx-xxx-...xxx-number"
pattern="^([^-]+-)*[0-9]+$"

# Check if the hostname matches the expected format
if [[ $hostname_input =~ $pattern ]]; then
  # Extract the number from the hostname
  node_id=${hostname_input##*-}

  echo "node_id: $node_id"
else
  echo "bad $hostname_input"
fi
