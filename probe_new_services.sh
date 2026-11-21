#!/usr/bin/env bash
# Probe operations from earlier demos against the emulator. Prints: service op -> status
source "$(dirname "$0")/env.sh"
probe() { out=$("$@" 2>&1); rc=$?; msg=$(echo "$out" | tail -1 | cut -c1-110); echo "rc=$rc | $* | $msg"; }
probe aws dsql list-clusters
probe aws lambda-microvms list-microvms
probe aws lambda-microvms list-microvm-images
probe aws cloudtrail lookup-events --max-results 1
probe aws continuum list-integrations
probe aws bedrock-agentcore-control list-agent-runtimes
probe aws lambda list-functions
probe aws lambda list-capacity-providers
probe aws logs describe-log-groups
probe aws cloudwatch list-metrics
probe aws kms list-keys
probe aws kms list-aliases
probe aws stepfunctions list-state-machines
probe aws events list-event-buses
probe aws iam list-roles
