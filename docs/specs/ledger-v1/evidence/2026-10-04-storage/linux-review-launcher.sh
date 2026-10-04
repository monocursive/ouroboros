#!/bin/sh
set -eu
cd /home/ubuntu/ouro-ledger-storage-20261004-r1
mkdir review-validation.started
setsid -f sh -c 'echo $$ > review-validation.pid; exec ./review-validate-ledger.sh > review-validation-driver.log 2>&1' < /dev/null > /dev/null 2>&1
printf 'started\n'
