#!/usr/bin/env python3

import click
import json
import frida
import sys
import os
from pkg_resources import resource_string
from tabulate import tabulate


script = None
device = None
pid = None

@click.command()
@click.option("--attach-pid", "-p", type=int, required=True)
def cli(attach_pid):
    global script
    global device
    global pid

    devices = frida.get_device_manager().enumerate_devices()
    device = get_device(devices)

    process = device.attach(attach_pid)

    js = resource_string("acov.build", "_agent.js").decode()
    script = process.create_script(js)

    script.load()

    input()
    print("Stopped tracing...")


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
    click.echo(tabulate(
        devices_info, headers=["id", "name", "type"], showindex=True))
