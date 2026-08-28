#!/bin/bash
set -euo pipefail

PROJECT="$(cd "$(dirname "$0")/.." && pwd -P)"

DT_BUILD102739B_MODE=1 \
  bash "$PROJECT/scripts/build102739a_post_wall2_observer.sh"
