#!/bin/bash
set -euo pipefail

gate=script/check-image-promotion-gate.sh
"$gate" 0.1.29 0.1.29 0.1.29 0.1.29
"$gate" 0.1.29 0.1.30 0.1.30 0.1.30
! "$gate" 0.1.29 0.1.28 0.1.28 0.1.28
! "$gate" 0.1.29 0.1.29-rc.1 0.1.29-rc.1 0.1.29-rc.1
! "$gate" 0.1.29 0.1.29 0.1.29 0.1.28
echo 'image promotion gate tests: OK'
