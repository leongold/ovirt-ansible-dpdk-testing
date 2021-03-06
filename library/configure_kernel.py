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
DOCUMENTATION = '''
---
short_description: Configures the kernel to be DPDK compatible.
author: "Leon Goldberg (@leongold)"
description:
    - "Module to configure the kernel to be DPDK compatible."
options:
    pci_drivers:
        description:
            - "Map of PCI address to device drivers. DPDK compatible
               devices\drivers has their CPU's isolated."
        required: true
'''

EXAMPLES = '''
- name: configure kernel
  configure_kernel:
    pci_drivers:
      "0000:00:04.0": "vfio-pci"
'''

RETURN = '''
changed:
    description: Describes whether any alterations to the kernel were made.
    returned: On success.
    type: boolean
    sample: true
'''

import os
import subprocess
import traceback

from ansible.module_utils.basic import AnsibleModule


class ReadKernelArgsError(Exception):
    pass


class UpdateKernelError(Exception):
    pass


class SelectCpuPartitioningError(Exception):
    pass


def _exec_cmd(args):
    proc = subprocess.Popen(
        args, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    out, err = proc.communicate()
    return proc.returncode, out, err


def _get_cpu_list(pci_addresses):
    cores = []
    for addr in pci_addresses:
        local_cpu_list = _get_nic_cpus_without_zero_core(addr)
        if local_cpu_list not in cores:
            cores.append(local_cpu_list)
    return ','.join(cores)


def _get_nic_cpus_without_zero_core(pci_address):
    local_cpu_list = _get_nic_cpu_list(pci_address)
    if _is_first_core_zero(local_cpu_list):
        local_cpu_list = _remove_first_core(local_cpu_list)
    return local_cpu_list


def _get_nic_cpu_list(pci_address):
    DEVICE_PATH_FMT = '/sys/bus/pci/devices/{}'

    local_cpulist = os.path.join(
        DEVICE_PATH_FMT.format(pci_address), 'local_cpulist'
    )
    with open(local_cpulist) as f:
        return f.read()


def _is_first_core_zero(cores):
    return cores[:1] == '0'


def _remove_first_core(cores):
    if cores[1] == '-':
        return '1' + cores[1:]
    elif cores[1] == ',':
        return cores[2:]
    else:
        return ""


def _get_default_kernel():
    proc = subprocess.Popen(['grubby', '--default-kernel'],
                            stdout=subprocess.PIPE)
    return proc.stdout.read().strip()


def _add_hugepages(kernel):
    if _current_hugepages():
        return

    args = 'default_hugepagesz=2M hugepagesz=2M hugepages=1024'
    proc = subprocess.Popen(['grubby', '--args="{}"'.format(args),
                             '--update-kernel', kernel])
    out, err = proc.communicate()
    if err:
        raise UpdateKernelError(out)
    return True


def _change_isolated_cpus(cpu_list):
    VARIABLES_FILE = '/etc/tuned/cpu-partitioning-variables.conf'

    changed = False
    has_isolated_cores = False
    new_lines = []
    with open(VARIABLES_FILE) as f:
        lines = f.readlines()
        for line in lines:
            if line.startswith('isolated_cores'):
                has_isolated_cores = True
                required_line = 'isolated_cores={}'.format(cpu_list)
                if line != required_line:
                    line = required_line
                    changed = True
            new_lines.append(line)
    if not has_isolated_cores:
        new_lines.append('isolated_cores={}'.format(cpu_list))
        changed = True

    with open(VARIABLES_FILE, 'w') as f:
        f.writelines(new_lines)

    return changed


def _current_hugepages():
    kernel_args = _get_kernel_args()
    args_list = kernel_args.split()

    return all([
        any([arg.startswith('hugepages=') for arg in args_list]),
        any([arg.startswith('hugepagesz=') for arg in args_list]),
        any([arg.startswith('default_hugepagesz=') for arg in args_list])
    ])


def _get_kernel_args():
    rc, out, err = _exec_cmd(['grubby', '--info', _get_default_kernel()])
    if rc != 0:
        raise ReadKernelArgsError(err)

    return [l.split('=', 1)[1].strip('"')
            for l in out.split('\n') if
            l.startswith('args')][0]


def _select_cpu_partitioning(cpu_list):
    profile = 'cpu-partitioning' if cpu_list else 'balanced'
    rc, _, err = _exec_cmd(['tuned-adm', 'profile', profile])
    if rc != 0:
        raise SelectCpuPartitioningError(err)


def _add_iommu(kernel):
    if _is_iommu_set():
        return False

    rc, _, err = _exec_cmd(['grubby', '--args=iommu=pt intel_iommu=on',
                            '--update-kernel={}'.format(kernel)])
    if rc != 0:
        raise UpdateKernelError(err)
    return True


def _is_iommu_set():
    kernel_args = _get_kernel_args()
    return 'iommu=pt' in kernel_args and 'intel_iommu=on' in kernel_args


def _using_virtio(addr):
    out = subprocess.check_output(['lspci'])

    devices = out.split('\n')
    for device in devices:
        short_addr, info = device.split(' ', 1)
        if addr.split(':', 1)[1] == short_addr:
            return 'Virtio' in info

    raise Exception('Could not determine device type @ {}'.format(addr))


def _configure_kernel(pci_addresses):
    cpu_list = _get_cpu_list(pci_addresses)
    default_kernel = _get_default_kernel()

    added_hugepages = _add_hugepages(default_kernel)
    changed_isolated_cpus = _change_isolated_cpus(cpu_list)
    _select_cpu_partitioning(cpu_list)
    added_iommu = _add_iommu(default_kernel)

    return any([added_hugepages, changed_isolated_cpus, added_iommu])


def main():
    DPDK_DRIVERS = ('vfio-pci',)

    module = AnsibleModule(
        argument_spec=dict(
            pci_drivers=dict(default=None, type='dict', required=True)
        )
    )
    pci_drivers = module.params.get('pci_drivers')
    pci_addresses = [addr for addr, driver in pci_drivers.iteritems()
                     if driver in DPDK_DRIVERS]
    try:
        changed = _configure_kernel(pci_addresses)
    except Exception as e:
        module.fail_json(msg=str(e), exception=traceback.format_exc())

    module.exit_json(changed=changed)


if __name__ == "__main__":
    main()
