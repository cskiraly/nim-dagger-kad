
# nim-eth
# Copyright (c) 2018-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
    chronos, chronos/timer

proc doSleep*(timeout: timer.Duration, p: proc() {.gcsafe, raises: [Defect].}) {.async.} =
  await sleepAsync(timeout)
  p()

template onTimeout*(timeout: timer.Duration, b: untyped) =
  asyncSpawn doSleep(timeout) do():
    b
