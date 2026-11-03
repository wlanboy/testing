#!/usr/bin/env bash
set -euo pipefail

MAIN_BRANCH="master"
REMOTE="origin"

# Nächste freie patch-Nummer ermitteln (lokal + remote)
next_num=1
while git show-ref --verify --quiet "refs/heads/patch-${next_num}" \
   || git ls-remote --exit-code --heads "$REMOTE" "patch-${next_num}" &>/dev/null; do
    next_num=$((next_num + 1))
done
BRANCH_NAME="patch-${next_num}"

echo ">> Erstelle und wechsle zu Branch '${BRANCH_NAME}'"
git checkout -b "$BRANCH_NAME"

echo ">> Push und Upstream setzen"
git push -u "$REMOTE" "$BRANCH_NAME"

echo
read -r -p "Zurück zu '${MAIN_BRANCH}' wechseln, '${BRANCH_NAME}' löschen und Löschung pushen? [y/N] " answer

if [[ "$answer" =~ ^[Yy]$ ]]; then
    git checkout "$MAIN_BRANCH"
    git branch -D "$BRANCH_NAME"
    git push "$REMOTE" --delete "$BRANCH_NAME"
    echo ">> Branch '${BRANCH_NAME}' wurde lokal und remote gelöscht."
else
    echo ">> Branch '${BRANCH_NAME}' bleibt bestehen (lokal & remote)."
fi
