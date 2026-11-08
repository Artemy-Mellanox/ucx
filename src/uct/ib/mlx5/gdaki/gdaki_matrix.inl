/**
 * Copyright (c) NVIDIA CORPORATION & AFFILIATES, 2026. ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

#ifndef UCT_GDAKI_MATRIX_INL
#define UCT_GDAKI_MATRIX_INL

#include <ucs/datastruct/array.h>
#include <ucs/debug/log.h>
#include <ucs/sys/compiler_def.h>
#include <ucs/sys/topo/base/topo_groups.h>
#include <ucs/type/status.h>

#include <stdint.h>


/*
 * A NUMA node of a Vera Rubin system has two GPUs and four ConnectX-9 HCAs. The
 * HCAs sit on boards of two, which are consecutive in PCI address order. This
 * file has the assignment of the HCAs to the GPUs which gives each GPU one HCA
 * of each board. It does not depend on CUDA, so it can be unit tested.
 */
#define UCT_GDAKI_BOARD_GPUS_PER_GROUP 2
#define UCT_GDAKI_BOARD_NICS_PER_GROUP 4
#define UCT_GDAKI_BOARD_NICS_PER_BOARD 2


/* An HCA device to assign to the GPUs */
typedef struct {
    ucs_sys_device_t sys_dev;     /* The HCA device, input */
    unsigned         ibdev_index; /* Index of the device, for the caller */
    uint64_t         gpu_mask;    /* GPUs of the device, output. A bit for each
                                     index in the array of the GPUs */
} uct_gdaki_board_dev_t;


/*
 * Index, among the GPUs of a topology group, of the GPU which takes a NIC. The
 * NICs are in PCI address order, so every NICS_PER_BOARD consecutive NICs are a
 * board, and each GPU takes one NIC of each board. This is the "flip" walk of
 * the UCP GPU to NIC assignment (see ucp_gpu_nic_assignment_get_gpu_idx), for
 * two GPUs: the owners of the NICs are 0, 1, 1, 0, 0, 1, 1, 0...
 */
static unsigned uct_gdaki_board_nic_gpu_idx(unsigned nic_idx)
{
    return ((nic_idx >> 1) ^ nic_idx) & 1;
}

/* Find the GPU of a group element among the GPUs. Returns num_gpus if it is
 * not one of them */
static unsigned
uct_gdaki_board_find_gpu(const ucs_topo_group_element_t *element,
                         const ucs_sys_device_t *gpu_sys_devs,
                         unsigned num_gpus)
{
    unsigned gpu_idx;
    size_t i;

    for (gpu_idx = 0; gpu_idx < num_gpus; ++gpu_idx) {
        for (i = 0; i < element->num_sys_devs; ++i) {
            if (element->sys_devs[i] == gpu_sys_devs[gpu_idx]) {
                return gpu_idx;
            }
        }
    }

    return num_gpus;
}

/* Check that the groups which have GPUs are Vera Rubin NUMA nodes, and that
 * their GPUs are exactly the given ones. Groups without GPUs are ignored. Set
 * the number of devices of an HCA, which is the same for all of them, so that
 * all the GPUs have the same number of devices */
static ucs_status_t
uct_gdaki_board_check_groups(const ucs_topo_groups_t *groups,
                             const ucs_sys_device_t *gpu_sys_devs,
                             unsigned num_gpus, size_t *num_funcs_p)
{
    uint64_t gpu_mask = 0;
    size_t num_funcs  = 0;
    const ucs_topo_group_t *group;
    const ucs_topo_group_element_t *element;
    unsigned gpu_idx;

    if ((num_gpus == 0) || (num_gpus >= 64)) {
        return UCS_ERR_UNSUPPORTED;
    }

    ucs_array_for_each(group, groups) {
        if (ucs_array_is_empty(&group->gpus)) {
            continue;
        }

        if ((ucs_array_length(&group->gpus) !=
             UCT_GDAKI_BOARD_GPUS_PER_GROUP) ||
            (ucs_array_length(&group->nics) !=
             UCT_GDAKI_BOARD_NICS_PER_GROUP)) {
            ucs_debug("topology group has %zu gpus and %zu hcas, expected %u "
                      "and %u", ucs_array_length(&group->gpus),
                      ucs_array_length(&group->nics),
                      UCT_GDAKI_BOARD_GPUS_PER_GROUP,
                      UCT_GDAKI_BOARD_NICS_PER_GROUP);
            return UCS_ERR_UNSUPPORTED;
        }

        ucs_array_for_each(element, &group->nics) {
            if (num_funcs == 0) {
                num_funcs = element->num_sys_devs;
            } else if (element->num_sys_devs != num_funcs) {
                ucs_debug("hcas have %zu and %zu devices", num_funcs,
                          element->num_sys_devs);
                return UCS_ERR_UNSUPPORTED;
            }
        }

        ucs_array_for_each(element, &group->gpus) {
            gpu_idx = uct_gdaki_board_find_gpu(element, gpu_sys_devs, num_gpus);
            if ((gpu_idx == num_gpus) || (gpu_mask & UCS_BIT(gpu_idx))) {
                ucs_debug("topology group has an unexpected gpu, system "
                          "device %u", element->sys_devs[0]);
                return UCS_ERR_UNSUPPORTED;
            }

            gpu_mask |= UCS_BIT(gpu_idx);
        }
    }

    if (gpu_mask != UCS_MASK(num_gpus)) {
        ucs_debug("only gpus 0x%lx of %u are in topology groups",
                  (unsigned long)gpu_mask, num_gpus);
        return UCS_ERR_UNSUPPORTED;
    }

    *num_funcs_p = num_funcs;
    return UCS_OK;
}

/* Assign the devices of a NIC to a GPU, up to max_per_gpu devices of the GPU */
static void
uct_gdaki_board_assign_nic_dev(uct_gdaki_board_dev_t *devs, unsigned num_devs,
                               ucs_sys_device_t sys_dev, unsigned gpu_idx,
                               unsigned long max_per_gpu,
                               unsigned long *num_assigned_p)
{
    unsigned dev_idx;

    for (dev_idx = 0; dev_idx < num_devs; ++dev_idx) {
        if ((devs[dev_idx].sys_dev == sys_dev) &&
            (*num_assigned_p < max_per_gpu)) {
            devs[dev_idx].gpu_mask |= UCS_BIT(gpu_idx);
            ++(*num_assigned_p);
        }
    }
}

/*
 * Give each GPU one HCA of each board. The topology groups are of the GPUs and
 * the HCAs, which are the devices to assign. A GPU gets the devices of its HCAs
 * in the order of the HCA functions, then of the boards, so that if the number
 * of devices of a GPU is limited, it still gets an HCA of each board first.
 *
 * Returns UCS_OK, or UCS_ERR_UNSUPPORTED if the groups are not of the expected
 * layout, and then the devices are not changed.
 */
static ucs_status_t
uct_gdaki_board_assign(const ucs_topo_groups_t *groups,
                       const ucs_sys_device_t *gpu_sys_devs, unsigned num_gpus,
                       uct_gdaki_board_dev_t *devs, unsigned num_devs,
                       unsigned long max_per_gpu)
{
    const ucs_topo_group_t *group;
    const ucs_topo_group_element_t *nic;
    unsigned long num_assigned;
    unsigned own_idx, gpu_idx, nic_idx;
    size_t num_funcs, func;
    ucs_status_t status;

    status = uct_gdaki_board_check_groups(groups, gpu_sys_devs, num_gpus,
                                          &num_funcs);
    if (status != UCS_OK) {
        return status;
    }

    ucs_array_for_each(group, groups) {
        if (ucs_array_is_empty(&group->gpus)) {
            continue;
        }

        for (own_idx = 0; own_idx < UCT_GDAKI_BOARD_GPUS_PER_GROUP; ++own_idx) {
            gpu_idx      = uct_gdaki_board_find_gpu(
                    &ucs_array_elem(&group->gpus, own_idx), gpu_sys_devs,
                    num_gpus);
            num_assigned = 0;
            for (func = 0; func < num_funcs; ++func) {
                for (nic_idx = 0; nic_idx < UCT_GDAKI_BOARD_NICS_PER_GROUP;
                     ++nic_idx) {
                    if (uct_gdaki_board_nic_gpu_idx(nic_idx) != own_idx) {
                        continue;
                    }

                    nic = &ucs_array_elem(&group->nics, nic_idx);
                    uct_gdaki_board_assign_nic_dev(devs, num_devs,
                                                   nic->sys_devs[func],
                                                   gpu_idx, max_per_gpu,
                                                   &num_assigned);
                }
            }

            ucs_debug("gpu %u takes %lu hca devices", gpu_idx, num_assigned);
        }
    }

    return UCS_OK;
}

/* Convert the GPUs of a device to a map of CUDA devices. A GPU which is not
 * visible to CUDA, which has a negative CUDA index, takes its devices without
 * having them in the map, so all the processes have the same assignment */
static uint64_t
uct_gdaki_board_cuda_map(uint64_t gpu_mask, const int *cuda_idxs,
                         unsigned num_gpus)
{
    uint64_t cuda_map = 0;
    unsigned gpu_idx;

    for (gpu_idx = 0; gpu_idx < num_gpus; ++gpu_idx) {
        if ((gpu_mask & UCS_BIT(gpu_idx)) && (cuda_idxs[gpu_idx] >= 0)) {
            cuda_map |= UCS_BIT(cuda_idxs[gpu_idx]);
        }
    }

    return cuda_map;
}

#endif
