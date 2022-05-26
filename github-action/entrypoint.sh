#!/bin/sh -l

echo "$1" > /.authz0.yml
out=$(/app/authz0 scan /.authz0.yml -f 'json')
echo "::set-output name=output::$out"