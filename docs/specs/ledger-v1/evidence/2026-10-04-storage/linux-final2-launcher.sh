#!/bin/sh
cd /home/ubuntu/ouro-ledger-storage-20261004-r1 && mkdir final2-validation.started && setsid -f sh -c 'echo $$ > final2-validation.pid; ( ./validate-ledger-final2.sh ) > final2-validation-driver.log 2>&1' < /dev/null > /dev/null 2>&1 && echo started
