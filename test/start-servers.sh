#!/bin/sh -x

ORACLE=${ORACLE:-../../zig-out/bin/oracle}
PIDS=""

cleanup() {
 echo killing oracles ${PIDS}
 kill ${PIDS}
 exit
}

function start_server() {
   printf "starting oracle %s" "$1"
   cd "$1"
   "$ORACLE" >log 2>&1 &
   PIDS="$PIDS $!"
   sleep 0.1
   cd - >/dev/null
}

start_server 0
start_server 1
start_server 2

trap "cleanup" INT
while true; do sleep 1 ;done
