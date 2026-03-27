#!/bin/bash

set -euo pipefail

CONFIG_ROOT="$PWD/.nuclei-config"
RUN_LOG_DIR="$PWD/.integration-logs"
SETUP_CONFIG_DIR="$CONFIG_ROOT/setup"
INTEGRATION_PARALLELISM="${INTEGRATION_PARALLELISM:-2}"

mkdir -p "$CONFIG_ROOT" "$RUN_LOG_DIR" "$SETUP_CONFIG_DIR"
touch "$SETUP_CONFIG_DIR/.nuclei-ignore"
export NUCLEI_CONFIG_DIR="$SETUP_CONFIG_DIR"

run_protocol() {
  local proto="$1"
  local config_dir
  local cache_dir
  local appdata_dir
  local home_dir
  config_dir="$(mktemp -d "$CONFIG_ROOT/run-${proto}.XXXXXX")"
  cache_dir="$config_dir/cache"
  appdata_dir="$config_dir/appdata"
  home_dir="$config_dir/home"

  mkdir -p "$cache_dir" "$appdata_dir" "$home_dir"
  touch "$config_dir/.nuclei-ignore"

  echo "Running protocol ${proto}"
  if env \
    NUCLEI_CONFIG_DIR="$config_dir" \
    XDG_CACHE_HOME="$cache_dir" \
    XDG_CONFIG_HOME="$config_dir" \
    HOME="$home_dir" \
    USERPROFILE="$home_dir" \
    APPDATA="$appdata_dir" \
    LOCALAPPDATA="$appdata_dir" \
    PROTO="$proto" \
    ./integration-test; then
    echo "[✓] ${proto}"
    rm -rf "$config_dir"
    return 0
  fi

  echo "[✘] ${proto}"
  rm -rf "$config_dir"
  return 1
}

run_protocol_group() {
  local group="$1"
  local status=0
  local protocol_csv="$group"
  local old_ifs="$IFS"
  IFS=','
  read -r -a protocols <<< "$protocol_csv"
  IFS="$old_ifs"

  for proto in "${protocols[@]}"; do
    if ! run_protocol "$proto"; then
      status=1
    fi
  done

  return "$status"
}

list_protocols() {
  local mode="$1"
  ./integration-test -list-protocols "$mode"
}

join_protocols() {
  local old_ifs="$IFS"
  IFS=','
  echo "$*"
  IFS="$old_ifs"
}

read_protocols_into_array() {
  local mode="$1"
  local array_name="$2"
  local value

  eval "$array_name=()"
  while IFS= read -r value; do
    if [ -n "$value" ]; then
      eval "$array_name+=(\"$value\")"
    fi
  done <<EOF
$(list_protocols "$mode")
EOF
}

echo "::group::Build nuclei"
rm -f integration-test fuzzplayground nuclei
cd ../cmd/nuclei
go build -race .
mv nuclei ../../integration_tests/nuclei
echo "::endgroup::"

echo "::group::Build nuclei integration-test"
cd ../integration-test
go build
mv integration-test ../../integration_tests/integration-test
cd ../../integration_tests
echo "::endgroup::"

read_protocols_into_array parallel parallel_protocols
read_protocols_into_array serial serial_protocols

parallel_protocol_groups=()
while IFS= read -r group; do
  if [ -n "$group" ]; then
    parallel_protocol_groups+=("$group")
  fi
done <<EOF
$(./integration-test -list-protocol-groups parallel -group-count "$INTEGRATION_PARALLELISM")
EOF

echo "::group::Installing nuclei templates"
./nuclei -update-templates
echo "::endgroup::"

parallel_failed=0
parallel_pids=()
parallel_logs=()

for idx in "${!parallel_protocol_groups[@]}"; do
  lane=$((idx + 1))
  lane_log="$RUN_LOG_DIR/parallel-lane-${lane}.log"
  parallel_logs+=("$lane_log")
  (
    run_protocol_group "${parallel_protocol_groups[$idx]}"
  ) >"$lane_log" 2>&1 &
  parallel_pids+=("$!")
done

for idx in "${!parallel_pids[@]}"; do
  if ! wait "${parallel_pids[$idx]}"; then
    parallel_failed=1
  fi
  cat "${parallel_logs[$idx]}"
done

serial_failed=0
for proto in "${serial_protocols[@]}"; do
  proto_log="$RUN_LOG_DIR/serial-${proto}.log"
  if ! run_protocol "$proto" >"$proto_log" 2>&1; then
    serial_failed=1
  fi
  cat "$proto_log"
done

if [ "$parallel_failed" -ne 0 ] || [ "$serial_failed" -ne 0 ]; then
  exit 1
fi
