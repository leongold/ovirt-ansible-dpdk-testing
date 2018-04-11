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
import os
import subprocess
import traceback

from ansible.module_utils.basic import AnsibleModule


DEVICE_PATH_FMT = '/sys/bus/pci/devices/{}'


def _remove_first_core(cores):
    if cores[1] == '-':
        return '1' + cores[1:]
    elif cores[1] == ',':
        return cores[2:]
    else:
        return ""

def _is_first_core_zero(cores):
    return cores[:1] == '0'

def _get_nic_cpu_list(pci_address):
    local_cpulist = os.path.join(
        DEVICE_PATH_FMT.format(pci_address),
        'local_cpulist'
    )
    with open(local_cpulist) as f:
        return f.read()


def _get_numa_node(pci_address):
    numa_node = os.path.join(
        DEVICE_PATH_FMT.format(pci_address),
        'numa_node'
    )
    with open(numa_node) as f:
        return f.read()


def _get_nic_cpus_without_zero_core(pci_address):
    local_cpu_list = _get_nic_cpu_list(pci_address)
    if _is_first_core_zero(local_cpu_list):
        local_cpu_list = _remove_first_core(local_cpu_list)
    return local_cpu_list


def _range_to_list(core_list):
    edges = core_list.rstrip().split('-')
    return list(range(int(edges[0]), int(edges[1]) + 1))

def _list_from_string(str_list):
    return list(map(int, str_list.rstrip().split(',')))

def _get_cpu_list(cores):
    if '-' in cores:
        return _range_to_list(cores)
    if ',' in cores:
        return _list_from_string(cores)

def _get_numa_nodes_nr():
    ls_proc = subprocess.Popen(
            "ls -l /sys/devices/system/node/".split(),
            stdout=subprocess.PIPE)
    grep_proc = subprocess.Popen(
            "grep node".split(),
            stdin=ls_proc.stdout,
            stdout=subprocess.PIPE)
    wc_proc = subprocess.Popen(
            "wc -l".split(),
            stdin=grep_proc.stdout,
            stdout=subprocess.PIPE)

    output, error = wc_proc.communicate()
    return int(output)

def get_core_mask(cores):
    mask = 0
    for core in cores:
        mask |= (1 << int(core))
    return hex(mask)

def get_pmd_cores(nics_numa_info, pmd_threads_count):
    pmd_cores = []
    for node_info in nics_numa_info.values():
        nics_count = node_info['nics']
        cores = _get_cpu_list(node_info['cpu_list'])

        num_cores = nics_count * pmd_threads_count
        while num_cores > 0:
            min_core = min(cores)
            pmd_cores.append(min_core)
            cores.remove(min_core)
            num_cores -= 1

    return pmd_cores

def get_dpdk_lcores(pmd_cores, cpu_list):
    socket_mem = ""
    cores = _get_cpu_list(cpu_list)
    available_cores = list(set(cores) - set(pmd_cores))
    return available_cores[:2]

def get_socket_mem(nics_numa_info):
    socket_mem_list = []
    numa_nodes = list(nics_numa_info.keys())

    for i in range(0, _get_numa_nodes_nr()):
        if i in numa_nodes:
            socket_mem_list.append('2048')
        else:
            socket_mem_list.append('1024')

    return ','.join(socket_mem_list)


def get_dpdk_nics_numa_info(pci_addresses):
    nics_per_numa = {}
    for addr in pci_addresses:
        numa_node = int(_get_numa_node(addr))
        if numa_node == -1:
            numa_node = 0
        if numa_node in nics_per_numa:
            nics_per_numa[numa_node]['nics'] += 1
        else:
            nics_per_numa[numa_node] = {}
            nics_per_numa[numa_node]['nics'] = 1
            nics_per_numa[numa_node]['cpu_list'] = \
                _get_nic_cpus_without_zero_core(addr)

    return nics_per_numa


if __name__ == '__main__':
    module = AnsibleModule(
        argument_spec=dict(
            pci_addresses=dict(default=None, type='list', required=True),
            nr_queues=dict(default=None, type='int', required=True),
            cpu_list=dict(default=None, type='str', required=True),
        )
    )

    nr_queues = module.params.get('nr_queues')
    pci_addresses = module.params.get('pci_addresses')
    cpu_list = module.params.get('cpu_list')
    try:
        numa_info = get_dpdk_nics_numa_info(pci_addresses)
        pmd_cores = get_pmd_cores(numa_info, nr_queues)
        dpdk_lcore_mask = get_core_mask(get_dpdk_lcores(pmd_cores, cpu_list))
        dpdk_socket_mem = get_socket_mem(numa_info)
        pmd_cpu_mask = get_core_mask(pmd_cores)
    except Exception as e:
        module.fail_json(msg=str(e), exception=traceback.format_exc())

    module.exit_json(numa_info=numa_info,
                     pmd_cores=pmd_cores,
                     dpdk_lcore_mask=dpdk_lcore_mask,
                     dpdk_socket_mem=dpdk_socket_mem,
                     pmd_cpu_mask=pmd_cpu_mask)
