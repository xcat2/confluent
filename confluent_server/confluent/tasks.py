# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2024 Lenovo
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Manage tasks, loops, and background

import asyncio
import inspect
import random

tsks = {}


tasksitter = None
logtrace = None

async def _sit_tasks():
    while True:
        while not tsks:
            await asyncio.sleep(15)
        tsk_list = [tsks[x] for x in tsks]
        cmpl, pnding = await asyncio.wait(tsk_list, return_when=asyncio.FIRST_COMPLETED, timeout=15)
        for tskid in list(tsks):
            if tsks[tskid].done():
                try:
                    tsk = tsks[tskid]
                    del tsks[tskid]
                    await tsk
                except Exception as e:
                    if logtrace:
                        logtrace()
                    else:
                        print(repr(e))


def spawn_task(coro):
    try:
        return asyncio.create_task(coro)
    except AttributeError:
        return asyncio.get_event_loop().create_task(coro)


def spawn(coro):
    global tasksitter
    if not tasksitter:
        tasksitter = spawn_task(_sit_tasks())
    tskid = random.random()
    while tskid in tsks:
        tskid = random.random()
    tsks[tskid] = spawn_task(coro)


async def _sleep_and_run(sleeptime, func, args):
    await asyncio.sleep(sleeptime)
    ret = func(*args)
    if inspect.isawaitable(ret):
        await ret


def spawn_after(sleeptime, func, *args):
    if func is None:
        raise Exception('tf')
    return spawn(_sleep_and_run(sleeptime, func, args))


def spawn_task_after(sleeptime, func, *args):
    if func is None:
        raise Exception('tf')
    return spawn_task(_sleep_and_run(sleeptime, func, args))

