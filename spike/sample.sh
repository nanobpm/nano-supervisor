#!/bin/bash
# Sample RSS (KB) of the spike worker and its agent children every 0.5s.
# usage: sample.sh <worker-pid> <out.tsv>
W=$1; OUT=$2
echo -e "t\tworker_kb\tagent_kb\tagent_pids" > "$OUT"
while kill -0 "$W" 2>/dev/null; do
  WR=$(ps -o rss= -p "$W" | tr -d ' ')
  KIDS=$(pgrep -P "$W" | tr '\n' ' ')
  AR=0
  if [ -n "$KIDS" ]; then AR=$(ps -o rss= -p $(echo $KIDS | tr ' ' ',') | awk '{s+=$1} END {print s+0}'); fi
  echo -e "$(date +%s.%N | cut -c1-14)\t${WR:-0}\t$AR\t$KIDS" >> "$OUT"
  sleep 0.5
done
