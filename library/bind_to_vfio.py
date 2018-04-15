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
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate()
    return proc.returncode, out, err


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


def _enable_unsafe_noiommu_mode():
    _remove_vfio_pci()
    _remove_vfio()

    rc, _, err = _exec_cmd(['modprobe', 'vfio', 'enable_unsafe_noiommu_mode=1'])
    if rc:
        raise Exception('Could not set unsafe noiommu mode: {}'.format(err))


def _remove_vfio_pci():
    rc, _, err = _exec_cmd(['modprobe', '-r', 'vfio_pci'])
    if rc:
        if 'No such file' in err:
            return
        else:
            raise Exception('Could not remove vfio_pci module: {}'.format(err))


def _remove_vfio():
    rc, _, err = _exec_cmd(['modprobe', '-r', 'vfio'])
    if rc:
        if 'No such file' in err:
            return
        else:
            raise Exception('Could not remove vfio module: {}'.format(err))


def _bind_devices_to_vfio(pci_addresses):
    if any(_using_virtio(addr) for addr in pci_addresses):
        _enable_unsafe_noiommu_mode()

    for addr in pci_addresses:
        rc, _, err = _exec_cmd(['driverctl', 'set-override', addr, 'vfio-pci'])
        if rc:
            raise Exception('Could not bind device to vfio-pci: {}'.format(err))


def main():
    module = AnsibleModule(
        argument_spec=dict(
            pci_addresses=dict(default=None, type='list', required=True)
        )
    )

    pci_addresses = module.params.get('pci_addresses')
    try:
        _bind_devices_to_vfio(pci_addresses)
    except Exception as e:
        module.fail_json(msg=str(e), exception=traceback.format_exc())

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()