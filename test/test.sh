#!/bin/sh -e

SPHINX=${SPHINX:-~/tasks/sphinx/pwdsphinx/pwdsphinx/sphinx.py}
ORACLE=${ORACLE:-../../zig-out/bin/oracle}
PIDS=""

cleanup() {
 echo killing oracles "$PIDS"
 kill $PIDS
 exit ${1:-0}
}

start_server() {
   printf "starting oracle %s" "$1"
   cd "$1"
   "$ORACLE" >log 2>&1 &
   PIDS="$PIDS $!"
   printf " pid: %s\n" $!
   sleep 0.1
   cd - >/dev/null
}

op() {
   op="$1"
   user="$2"
   host="$3"
   pass="$4"
   [ "x$fail" == "xtrue" ] && printf "fail: "
   if [ "$op" == "change" ]; then
      newpass="$5"
      printf "%s %s %s <'%s' <'%s'" $op "$user" "$host" "$pass" "$newpass" >&2
      rwd="$(printf "%s\n%s" "$pass" "$newpass" | "$SPHINX" "$op" "$user" "$host" 2>>sphinx.err)"
      ret=$?
      expected=""
   else
      expected="$5"
      printf "%s %s %s <'%s' " $op "$user" "$host" "$pass" >&2
      rwd="$(printf "%s" "$pass" | "$SPHINX" "$op" "$user" "$host" 2>>sphinx.err)"
      ret=$?
   fi
   [ "$ret" -ne 0 ] && return $ret
   [ -n "$expected" ] && [ "$expected" != "$rwd" ] && {
      [ "x$fail" != "xtrue" ] &&  echo "test failed $expected != $rwd" >&2
      return 1
   } 
   [ "x$fail" == "xtrue" ] && [ "$ret" -eq 0 ] && return 0

   case "$op" in 
      create|change) echo "${rwd}"
   esac
   return 0
}

start_server 0
start_server 1
start_server 2

trap "cleanup" INT TERM

rm -rf */data/[0-9a-f]*

user1=user1
host1=host1
u1pwd1="asdf"
u1pwd2="qwer"
u1rwd0=$(op create "$user1" "$host1" "$u1pwd1") && echo " ok" >&2
op get "$user1" "$host1" "$u1pwd1" "${u1rwd0}" && echo " ok" >&2
u1rwd1=$(op change "$user1" "$host1" "$u1pwd1" "$u1pwd2") && echo " ok" >&2
op get "$user1" "$host1" "$u1pwd1" "${u1rwd0}" && echo " ok" >&2
op commit "$user1" "$host1" "$u1pwd1" && echo " ok" >&2
op get "$user1" "$host1" "$u1pwd2" "${u1rwd1}" && echo " ok" >&2

user2=user2
host2=host2
u2pwd1="long password is long with weird chars\r"
u2pwd2="shorter password, less sophisticated"
u2rwd0=$(op create "$user2" "$host2" "$u2pwd1") && echo " ok" >&2
op get "$user2" "$host2" "$u2pwd1" "${u2rwd0}" && echo " ok" >&2
u2rwd1=$(op change "$user2" "$host2" "$u2pwd1" "$u2pwd2") && echo " ok" >&2
op get "$user2" "$host2" "$u2pwd1" "${u2rwd0}" && echo " ok" >&2
op commit "$user2" "$host2" "$u2pwd1" && echo " ok" >&2
op get "$user2" "$host2" "$u2pwd2" "${u2rwd1}" && echo " ok" >&2

# must fail since user2/host2 already exists
u2rwd2=$(fail=true op create "$user2" "$host2") && 
   echo " fail" >&2 ||
   echo " ok" >&2

# bad password should fail due to check_digit
fail=true op get "$user2" "$host2" "$u2pwd1" "${u2rwd1}" &&
   echo " fail" >&2 ||
   echo " ok" >&2

# bad username should
fail=true op get "$user1" "$host2" "$u2pwd1" "${u2rwd1}" &&
   echo " fail" >&2 ||
   echo " ok" >&2

# bad host should fail
fail=true op get "$user2" "$host1" "$u2pwd1" "${u2rwd1}" &&
   echo " fail" >&2 ||
   echo " ok" >&2

op delete "$user2" "$host2" "$u2pwd2" && echo " ok" >&2

fail=true op delete "$user2" "$host2" "$u2pwd2" &&
   echo " fail" >&2 ||
   echo " ok" >&2

for op in get change commit undo delete; do 
   # bad user
   fail=true op $op "$user2" "$host1" "$u1pwd1" "${u1pwd1}" &&
      { echo " fail" >&2 ; cleanup ; } ||
      echo " ok" >&2
   # bad host
   fail=true op $op "$user1" "$host2" "$u1pwd1" "${u1pwd1}" &&
      { echo " fail" >&2 ; cleanup ; } ||
      echo " ok" >&2
   # bad password
   fail=true op $op "$user1" "$host1" "$u2pwd1" "${u1pwd1}" &&
      { echo " fail (is rwd_keys false?)" >&2 ; cleanup ; } ||
      echo " ok" >&2
done

rm -rf */data/[0-9a-f]*
echo "all ok"
cleanup
