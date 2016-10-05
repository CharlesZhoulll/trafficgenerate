#!/bin/bash
branch="$1"
comment="$2"
git add .
git commit -m "$comment"
git push -u origin "$branch"

