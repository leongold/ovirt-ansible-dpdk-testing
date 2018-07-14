#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2018 Red Hat, Inc.
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
#
import subprocess
import traceback

from ansible.module_utils.basic import AnsibleModule


def _exec_cmd(args):
    proc = subprocess.Popen(
        args, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    out, err = proc.communicate()
    return proc.returncode, out, err


def _fetch_present_driver(pci_address):
    out = subprocess.check_output(['lspci', '-v', '-s', pci_address])
    lines = out.strip().split('\n')
    for line in lines:
        if 'Kernel driver' in line:
            return line.split(':')[1].strip()


def _using_virtio(addr):
    out = subprocess.check_output(['lspci'])

    devices = out.split('\n')
    for device in devices:
        short_addr, info = device.split(' ', 1)
        if addr.split(':', 1)[1] == short_addr:
            if 'Virtio' in info:
                return True
            return False

    raise Exception('Could not determine device type @ {}'.format(addr))


def _enable_unsafe_vfio_noiommu_mode():
    _remove_vfio_pci()
    _remove_vfio()

    rc, _, err = _exec_cmd(
        ['modprobe', 'vfio', 'enable_unsafe_noiommu_mode=1']
    )
    if rc:
        raise Exception('Could not set unsafe noiommu mode: {}'.format(err))


def _remove_vfio_pci():
    _remove_module('vfio_pci')


def _remove_vfio():
    _remove_module('vfio')


def _remove_module(module):
    rc, _, err = _exec_cmd(['modprobe', '-r', module])
    if rc:
        if 'No such file' in err:
            return
        else:
            raise Exception(
                'Could not remove {} module: {}'.format(module, err)
            )


def _bind_device_to_vfio(pci_address, driver):
    if _using_virtio(pci_address):
        _enable_unsafe_vfio_noiommu_mode()
    _bind_device_to_driver(pci_address, driver)


def _bind_device_to_driver(pci_address, driver):
    rc, _, err = _exec_cmd(['driverctl', 'set-override', pci_address, driver])
    if rc:
        raise Exception(
            'Could not bind device to {}: {}'.format(driver, err)
        )


def main():
    DPDK_DRIVERS = ('vfio-pci',)

    module = AnsibleModule(
        argument_spec=dict(
            device_map=dict(default=None, type='dict', required=True)
        )
    )
    device_map = module.params.get('device_map')
    bind_function_map = {'vfio-pci': _bind_device_to_vfio}
    changed = False
    try:
        for pci_address, driver in device_map.viewitems():
            present_driver = _fetch_present_driver(pci_address)
            if present_driver != driver:
                bind_func = bind_function_map.get(
                    driver, _bind_device_to_driver
                )
                bind_func(pci_address, driver)
                changed = True
    except Exception as e:
        module.fail_json(msg=str(e), exception=traceback.format_exc())

    module.exit_json(
        changed=changed,
        start_ovs=any(driver in DPDK_DRIVERS
                      for driver in device_map.viewvalues())
    )


if __name__ == "__main__":
    main()
