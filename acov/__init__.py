#!/usr/bin/env python3

import click
from click_option_group import optgroup, RequiredMutuallyExclusiveOptionGroup
import json
import frida
import sys
import os
from pkg_resources import resource_string
from tabulate import tabulate


script = None
device = None
pid = None
coverage_info = []


@click.command()
@optgroup.group(cls=RequiredMutuallyExclusiveOptionGroup)
@optgroup.option("--attach-pid", "-p", type=int)
@optgroup.option("--attach-name", "-n", type=str)
@optgroup.option("--file", "-f", type=str)
@click.option("--output", "-o", type=str, required=True)
def cli(attach_pid, attach_name, file, output):
    global script
    global device
    global pid

    devices = frida.get_device_manager().enumerate_devices()
    device = get_device(devices)

    process = None
    if attach_pid:
        process = device.attach(attach_pid)
    elif attach_name:
        for p in device.enumerate_processes():
            if p.name == attach_name:
                process = device.attach(p.pid)
                break
        else:
            click.echo(
                "[-] Unable to find process named: {}".format(attach_name), err=True
            )
            return
    elif file:
        pid = device.spawn([file])
        process = device.attach(pid)

    js = resource_string("acov.build", "_agent.js").decode()
    script = process.create_script(js, runtime="v8")
    script.on("message", on_message)
    script.load()

    if file:
        device.resume(pid)

    input()
    print("[+] Detaching session...")
    process.detach()
    print("[+] Saving output...")
    save_output(output)
    sys.exit(0)


def save_output(output):
    buckets = {}
    for i in coverage_info:
        tid = i["tid"]
        m = {"module": i["module"], "offset": i["offset"]}
        if tid not in buckets:
            buckets[tid] = [m]
        else:
            buckets[tid].append(m)

    for tid in buckets:
        with open("{}_{}.cov".format(output, tid), "w") as f:
            print("[+] Writing to {}".format(f.name))
            for i in buckets[tid]:
                f.write("{}+{}\n".format(i["module"], i["offset"]))


def on_message(message, data):
    payload = message["payload"]
    print("[+] New basic block event")
    coverage_info.append(
        {
            "module": payload["module"],
            "offset": payload["offset"],
            "tid": payload["tid"],
        }
    )


def get_device(devices):
    click.echo("Available devices:")
    list_devices(devices)

    click.echo()
    click.echo("Select device (by index): ", nl=False)
    selection = input()

    try:
        return devices[int(selection)]
    except:
        click.echo("Please enter a valid device selection...")
        os._exit(1)


def list_devices(devices):
    devices_info = [(i.id, i.name, i.type) for i in devices]
    click.echo(tabulate(devices_info, headers=["id", "name", "type"], showindex=True))
