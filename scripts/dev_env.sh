#!/usr/bin/env bash
# Load the development defaults for the scripts: `.env`, then `.env.example` (see .env.example).
#
#   . scripts/dev_env.sh
#   load_dev_env "$PWD"
#
# A variable that is already set keeps its value, so the order of precedence is the environment,
# then .env, then .env.example. Lines are read as NAME=value and never evaluated, so a value
# cannot run a command. Quotes are not removed.

load_dev_env() {
  local root=$1 file line name
  for file in "$root/.env" "$root/.env.example"; do
    [ -f "$file" ] || continue
    while IFS= read -r line || [ -n "$line" ]; do
      case $line in '' | '#'*) continue ;; esac
      name=${line%%=*}
      [[ $name =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || continue
      [ -n "${!name+x}" ] || export "$name=${line#*=}"
    done <"$file"
  done
}
