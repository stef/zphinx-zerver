#/bin/sh -e

SPHINX=~/tasks/sphinx/pwdsphinx/pwdsphinx/sphinx.py

rm -rf */data/[0-9a-f]*

echo -n 'asdf' | "$SPHINX" create user host
echo -n 'asdf' | "$SPHINX" get user host
echo -ne 'asdf\nqwer' | "$SPHINX" change user host
echo -n 'asdf' | "$SPHINX" commit user host
echo -n 'qwer' | "$SPHINX" get user host
echo -n 'qwer' | "$SPHINX" undo user host
echo -n 'asdf' | "$SPHINX" get user host
"$SPHINX" list host

