#!/bin/sh -x

ORACLE=${ORACLE:-../../zig-out/bin/oracle}
PIDS=""

cleanup() {
 echo killing oracles ${PIDS}
 kill ${PIDS}
 exit
}

start_server() {
   printf "starting %s %s\n" "$ORACLE" "$1"
   cd "$1"
   setarch `uname -m` -R "$ORACLE" >log 2>&1 &
   PIDS="$PIDS $!"
   sleep 0.1
   cd - >/dev/null
}

start_server 0
start_server 1
start_server 2

trap "cleanup" INT
tail -f 0/log
#while true; do sleep 1 ;done
