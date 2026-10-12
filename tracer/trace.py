#!/bin/env python3

import argparse
import logging
import os
import sys
import time
import pathlib
import frida
from slow.trace_slow import do_slowmode_output
from frinet import (
    FrinetTraceWriter,
    build_spawn_kwargs,
    is_android_system_parameters,
    trace_filename,
    wait_for_quiet,
)

wd = os.path.dirname(os.path.abspath(__file__))
MODULE_JS_PATH = os.path.join(wd,'trace.js')
MODULE_C_X64_PATH = os.path.join(wd,'trace_x64.c')
MODULE_C_ARM64_PATH = os.path.join(wd,'trace_arm64.c')
MODULE_C_ARM_PATH = os.path.join(wd,'trace_arm.c')
MODULE_JS_SLOW_PATH = os.path.join(wd,'slow','trace_slow.js')
TRACES_DIR = os.path.join(wd,"traces")

pathlib.Path(TRACES_DIR).mkdir(exist_ok=True)

def file_read(path: str) -> str:
    root_dir = os.path.dirname(os.path.realpath(__file__))
    with open(os.path.join(root_dir, path), 'r') as fd:
        return fd.read()


def file_append(path: str, data: str):
    root_dir = os.path.dirname(os.path.realpath(__file__))
    filepath = os.path.join(root_dir, path)
    if not os.path.isfile(filepath):
        logging.info("Creating trace file "+filepath)
    with open(filepath, 'a') as fd:
        return fd.write(data)


def do_spawn(args):
    do_trace(args, False)

def do_attach(args):
    do_trace(args, True)

def do_trace(args, attach):
    global arch
    devmgr = frida.get_device_manager()

    if args.device:
        logging.info('Connecting to device...')
        try:
            dev = devmgr.get_device(args.device)
        except frida.InvalidArgumentError as exc:
            logging.error(f'Cannot connect to device: `{exc}`.')
            return 1
    elif args.remote or args.host:
        host = args.host
        if args.host is None:
            host = '127.0.0.1:27042'
            logging.warning(f'Host is not defined... using {host!r}.')

        logging.info('Adding remote device...')
        dev = devmgr.add_remote_device(host)
    elif args.usb:
        logging.info('Connecting to USB device...')
        try:
            dev = devmgr.get_usb_device()
        except frida.InvalidArgumentError as exc:
            logging.error(f'Cannot connect to USB device: `{exc}`.')
            return 1
    else:
        logging.info('Using local device')
        dev = devmgr.get_local_device()

    # FRINET conversion state (created once the device is known); the tail of
    # every thread file is flushed on every exit path.
    writer = None
    flush_writer = lambda: None

    try:
        sysenv = dev.query_system_parameters()
        logging.debug(f'sysenv: {sysenv}')
        logging.info(f'''Connected to device ({sysenv['arch']} {sysenv['platform']} {sysenv['os']['name']} {sysenv['os']['version']}).''')

        process = args.process
        procname = process

        # The target platform decides how the process is spawned; it is taken
        # from the *device* parameters, never from the host OS.
        is_android = is_android_system_parameters(sysenv)
        logging.info(f'Target is {"Android" if is_android else sysenv["platform"]}.')

        if attach :
            if process.isnumeric():
                process = int(process)
                logging.info(f'Attaching to PID {process}...')
            else:
                logging.info(f'Attaching to process name {process!r}...')
        else:
            def on_output(pid, fd, data):
                if 0 < fd < 3:
                    prefix = "STDOUT"
                    if fd==2:
                        prefix = "STDERR"
                    try:print(prefix+" : "+data.decode().replace("\n", f"\n{prefix} : "))
                    except:print(prefix+" : "+repr(data))
            dev.on("output", on_output)
            argv = None
            if args.args:
                argv = args.args.split(",")
            procname = process.split("/")[-1]
            # Android: `env` must not be passed (frida rejects/breaks on it),
            # desktop: keep the historical `env={}` + `stdio="pipe"`.
            spawn_kwargs = build_spawn_kwargs(argv, is_android)
            logging.debug(f'spawn kwargs: {spawn_kwargs}')
            process = int(dev.spawn(process, **spawn_kwargs))
            logging.info("Spawning process ")
        sess = dev.attach(process)

        # TODO: refactor + cleanup...
        epoch = str(int(time.time()))
        writer = FrinetTraceWriter(warn=logging.warning)
        seen_tids = set() # seen thread IDs (kept for logging)
        msg_count = [0]   # number of trace messages handled (used to drain frida)
        logging.info('Loading JS module...')

        def trace_path(tid):
            return f'{TRACES_DIR}/' + trace_filename(procname, epoch, tid)

        def flush_writer():
            """Write whatever partial record is still buffered."""
            if writer is None:
                return
            for tid, text in writer.flush().items():
                if text:
                    file_append(trace_path(tid), text)

        script = sess.create_script(file_read(MODULE_JS_PATH))
        def on_message(msg, data):
            logging.debug(f'message: {msg}')

            if msg['type'] == 'error':
                # TODO: handle errors
                raise Exception(f'Script error: `{msg}`')
            elif msg['type'] == 'send':
                payload = msg['payload']

                if isinstance(payload, str): #Slow mode
                    logging.info("JS | "+payload)
                    return

                if isinstance(payload, list): #Slow mode
                    payload = do_slowmode_output(payload, arch)

                if not isinstance(payload, dict):
                    return

                msg_id = payload.get('id')
                if msg_id == 'slide':
                    # runtime module base + size: `off=` is only emitted for
                    # PCs inside [slide, slide + size)
                    writer.set_slide(payload.get('slide'), payload.get('size'))
                    if writer.slide is None:
                        logging.warning('ASLR slide is not valid, off= fields are disabled.')
                    elif writer.size is None:
                        logging.warning('Module size is unknown, off= fields are disabled.')
                    else:
                        logging.info(f'Received ASLR slide: 0x{writer.slide:x} (module size 0x{writer.size:x}).')
                    return
                elif msg_id == 'trace':
                    tid = payload.get('tid')
                    if tid is None:
                        return
                    chunk = payload.get('data')
                    if not chunk:
                        return
                    msg_count[0] += 1
                    if tid not in seen_tids:
                        seen_tids.add(tid)
                        logging.info(f'Received trace data for new thread {tid}.')
                    # FRINET conversion: complete records only, `off=` prepended,
                    # `slide=` header emitted once per per-thread file.
                    text = writer.convert(tid, chunk)
                    if text:
                        logging.debug(f'Writing trace data of {len(text)} bytes...')
                        file_append(trace_path(tid), text)
                    return
        script.on('message', on_message)
        script.load()

        arch = script.exports_sync.arch()
        if arch != 'arm64' and arch != "arm" and arch != "x64" and arch != "ia32":
            logging.error(f'Process architecture {arch} is not supported.')
            return 1

        elif arch!="arm64" and arch!='x64' and not args.slow:
            logging.warning(f'Process architecture {arch} is only supported in slow mode.\n Slow mode has been acivated.')
            args.slow = True

        writer.set_arch(arch)
        
        if args.slow and not args.exclude:
            logging.warning("The exclude option was activated because it is required for slow mode")
            args.exclude = True

        logging.info('Loading C module...')
        if arch == 'x64':
            c_path = MODULE_C_X64_PATH
        if arch == 'arm64':
            c_path = MODULE_C_ARM64_PATH
        js_path = MODULE_JS_SLOW_PATH

        if args.slow:
            js_src = file_read(js_path)
            script.exports_sync.send_src({'src': js_src, 'is_c':False})
        else:
            c_src = file_read(c_path)
            script.exports_sync.send_src({'src': c_src, 'is_c':True})
        

        try:
            addr = int(args.addr, 0)
        except ValueError:
            logging.error('Invalid address.')
            return 1

        logging.info('Tracing...')
        errcode = script.exports_sync.trace({
            'module': args.module,
            'addr': addr,
            'once': not args.multirun,
            'exclude' : args.exclude,
            'swap_rw' : 1 if (arch == "arm64" and sysenv['os']['name']=="Android") else 0,
            'slow' : args.slow,
            'end_addr' : int(args.end,16) if args.end else None,
            'trace_addr' : int(args.flushaddr,16) if args.flushaddr else None
        })
        logging.debug(f'errcode: {errcode}')

        if errcode != 0:
            logging.error('Something went wrong.')
            return 1

        if not attach:
            dev.resume(process)

        logging.info("CTRL+C to interrupt trace")
        try:
            sys.stdin.read()
        except KeyboardInterrupt:
            logging.info('Interrupting...')

        print("")
        script.exports_sync.end()
        # frida delivers the final flush messages asynchronously: give them a
        # moment to arrive so no record is cut short.
        wait_for_quiet(lambda: msg_count[0], quiet=0.2, timeout=3.0)
        flush_writer()
        script.unload()
        sess.detach()
    except frida.ServerNotRunningError as exc:
        logging.error(f'Cannot connect to remote frida server: `{exc}`.')
        return 1
    except frida.ProcessNotFoundError as exc:
        logging.error(f'Unable to find process: `{exc}`.')
        return 1
    except frida.TransportError as exc:
        logging.critical(f'Connection to remote frida server closed: `{exc}`.')
        return 1
    except frida.ProcessNotRespondingError as exc:
        logging.critical(f'Process is not responding: `{exc}`.')
        return 1
    except frida.InvalidOperationError as exc:
        logging.critical(f'Aw, Snap! Something went wrong: `{exc}`.')
        return 1
    finally:
        # never lose the tail of a thread file (Ctrl+C, crash, early return)
        try:
            flush_writer()
        except Exception as exc:
            logging.debug(f'Could not flush the trace buffer: {exc}')

    return 0


def main():
    parser = argparse.ArgumentParser('Tenet Frida Tracer')

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='verbose output'
    )

    parser.add_argument(
        '-D', '--device',
        type=str,
        help='connect to device with the given ID',
    )

    parser.add_argument(
        '-U', '--usb',
        action='store_true',
        help='connect to USB device',
    )

    parser.add_argument(
        '-R', '--remote',
        action='store_true',
        help='connect to remote frida server'
    )

    parser.add_argument(
        '-H', '--host',
        type=str,
        help='connect to remote frida server on host'
    )

    parser.add_argument(
        '-m', '--multirun',
        action='store_true',
        help='do not unhook after first execution'
    )

    parser.add_argument(
        '-a', '--args',
        type=str,
        help='comma-separated argument list for spawn (including binary name) : "/bin/sh,-c,ls"'
    )

    parser.add_argument(
        '-e', '--exclude',
        action='store_true',
        help='exclude all other modules (memory tracing will be inaccurate)'
    )

    parser.add_argument(
        '-s', '--slow',
        action='store_true',
        help='use slower JS implementation (multiarch)'
    )

    parser.add_argument(
        '-E', '--end',
        type=str,
        help='specify end address instead of function exit (-1 to never end)'
    )

    parser.add_argument(
        '-F', '--flushaddr',
        type=str,
        help='Address of instruction that will force a trace flush (useful when investigating a crash)'
    )

    sp = parser.add_subparsers()
    sp_spawn = sp.add_parser('spawn', help='Spawn process')
    sp_attach = sp.add_parser('attach', help='Attach to process')

    parser.add_argument(
        'process',
        type=str,
        help='attach:[process name or PID]; spawn:[binary path or package name]'
    )

    parser.add_argument(
        'module',
        type=str,
        help='module name to instrument'
    )

    parser.add_argument(
        'addr',
        type=str,
        help='entrypoint function address'
    )

    sp_spawn.set_defaults(func=do_spawn)
    sp_attach.set_defaults(func=do_attach)

    args = parser.parse_args()

    logging.basicConfig(format='%(asctime)s %(levelname)8s | %(message)s',
        level=logging.DEBUG if args.verbose else logging.INFO)

    return args.func(args)


if __name__ == '__main__':
    errcode = main()
    sys.exit(errcode)

