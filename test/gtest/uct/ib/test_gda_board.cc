/**
 * Copyright (c) NVIDIA CORPORATION & AFFILIATES, 2026. ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

#include <common/test.h>

extern "C" {
#include <ucs/sys/string.h>
#include <uct/ib/mlx5/gdaki/gdaki_matrix.inl>
}

#include <algorithm>
#include <climits>
#include <deque>
#include <initializer_list>
#include <numeric>
#include <random>
#include <string>
#include <vector>


/*
 * Test the assignment of ConnectX-9 HCAs to GPUs by HCA board. The topology
 * is made of synthetic devices, so there is no need for the hardware.
 *
 * A device is named by its place: n<NUMA node>g<GPU> for a GPU, and
 * n<NUMA node>c<card>f<function> for an HCA device. The GPUs and the cards of
 * a NUMA node are numbered in PCI address order, which is not the order of
 * their registration and of their IB devices.
 */
class test_gda_board : public ucs::test {
protected:
    typedef std::vector<std::string> names_t;

    struct desc_t {
        std::string             name;
        ucs_sys_bus_id_t        bus_id;
        ucs_topo_device_class_t device_class;
        ucs_numa_node_t         numa_node;
        bool                    hca; /* A device to assign to the GPUs */
    };

    virtual void cleanup()
    {
        release_groups();
        ucs::test::cleanup();
    }

    static std::string dev_name(unsigned numa, unsigned card, unsigned func)
    {
        return "n" + std::to_string(numa) + "c" + std::to_string(card) + "f" +
               std::to_string(func);
    }

    static std::string gpu_name(unsigned numa, unsigned gpu)
    {
        return "n" + std::to_string(numa) + "g" + std::to_string(gpu);
    }

    static names_t sorted(names_t names)
    {
        std::sort(names.begin(), names.end());
        return names;
    }

    void add_desc(const std::string &name, uint16_t domain, uint8_t bus,
                  uint8_t function, ucs_topo_device_class_t device_class,
                  ucs_numa_node_t numa_node, bool hca)
    {
        desc_t desc;

        desc.name            = name;
        desc.bus_id          = ucs_sys_bus_id_t();
        desc.bus_id.domain   = domain;
        desc.bus_id.bus      = bus;
        desc.bus_id.function = function;
        desc.device_class    = device_class;
        desc.numa_node       = numa_node;
        desc.hca             = hca;
        m_descs.push_back(desc);
    }

    /* Add the devices of a NUMA node. The PCI address of a card and of a GPU
     * grows with its number, and the cards have different bus numbers as in a
     * real system, so the domain is the most significant */
    void add_numa(unsigned numa, unsigned num_gpus, unsigned num_cards,
                  unsigned num_funcs)
    {
        unsigned gpu, card, func;

        for (gpu = 0; gpu < num_gpus; ++gpu) {
            add_desc(gpu_name(numa, gpu), 0x1000 + 0x100 * numa + gpu, 1, 0,
                     UCS_TOPO_DEVICE_CLASS_ACC,
                     static_cast<ucs_numa_node_t>(numa), false);
        }

        for (card = 0; card < num_cards; ++card) {
            for (func = 0; func < num_funcs; ++func) {
                add_desc(dev_name(numa, card, func),
                         0x2000 + 0x100 * numa + card, (card % 2) ? 1 : 3,
                         func, UCS_TOPO_DEVICE_CLASS_NET,
                         static_cast<ucs_numa_node_t>(numa), true);
            }
        }
    }

    desc_t &find_desc(const std::string &name)
    {
        for (size_t i = 0; i < m_descs.size(); ++i) {
            if (m_descs[i].name == name) {
                return m_descs[i];
            }
        }

        ADD_FAILURE() << "no device " << name;
        return m_descs.front();
    }

    void remove_desc(const std::string &name)
    {
        desc_t &desc = find_desc(name);

        m_descs.erase(m_descs.begin() + (&desc - &m_descs[0]));
    }

    void release_groups()
    {
        ucs_topo_release_groups(&m_groups);
        m_groups = ucs_topo_groups_t();
    }

    ucs_sys_device_t add_device(const desc_t &desc)
    {
        ucs_topo_sys_device_info_t device = {};

        m_names.push_back(desc.name);

        device.bus_id        = desc.bus_id;
        device.name          = const_cast<char*>(m_names.back().c_str());
        device.numa_node     = desc.numa_node;
        device.user_value    = UCS_SYS_DEVICE_USER_VALUE_EMPTY;
        device.device_class  = desc.device_class;
        device.class_ordinal = UCS_SYS_DEVICE_ORDINAL_INVALID;
        device.sys_dev_aux   = UCS_SYS_DEVICE_ID_UNKNOWN;
        UCS_STATIC_BITMAP_RESET_ALL(&device.siblings);

        m_devices.push_back(device);
        return static_cast<ucs_sys_device_t>(m_devices.size() - 1);
    }

    /* Register the devices, in an order which depends on the seed, and build
     * the topology groups. The order of the GPUs and of the HCA devices, which
     * are the IB devices, is the order of the registration. Seed 0 keeps the
     * order in which the devices were added. */
    void build(unsigned seed = 0)
    {
        std::vector<size_t> order(m_descs.size());
        ucs_sys_device_bitmap_t filter;
        ucs_sys_device_t sys_dev;
        uct_gdaki_board_dev_t hca;
        size_t i;

        release_groups();
        m_devices.clear();
        m_names.clear();
        m_gpu_sys_devs.clear();
        m_hcas.clear();

        std::iota(order.begin(), order.end(), 0);
        if (seed != 0) {
            std::mt19937 rng(seed);
            std::shuffle(order.begin(), order.end(), rng);
        }

        UCS_STATIC_BITMAP_RESET_ALL(&filter);
        for (i = 0; i < order.size(); ++i) {
            const desc_t &desc = m_descs[order[i]];

            sys_dev = add_device(desc);
            if (desc.device_class == UCS_TOPO_DEVICE_CLASS_ACC) {
                m_gpu_sys_devs.push_back(sys_dev);
            } else if (desc.hca) {
                UCS_STATIC_BITMAP_SET(&filter, sys_dev);
                hca             = uct_gdaki_board_dev_t();
                hca.sys_dev     = sys_dev;
                hca.ibdev_index = static_cast<unsigned>(m_hcas.size());
                m_hcas.push_back(hca);
            }
        }

        ASSERT_UCS_OK(ucs_topo_build_groups_inner(
                m_devices.data(), static_cast<unsigned>(m_devices.size()),
                &filter, &m_groups));
    }

    ucs_status_t assign(unsigned long max_per_gpu = UCS_ULUNITS_AUTO)
    {
        return uct_gdaki_board_assign(&m_groups, m_gpu_sys_devs.data(),
                                      static_cast<unsigned>(
                                              m_gpu_sys_devs.size()),
                                      m_hcas.data(),
                                      static_cast<unsigned>(m_hcas.size()),
                                      max_per_gpu);
    }

    unsigned gpu_index(const std::string &name) const
    {
        for (size_t i = 0; i < m_gpu_sys_devs.size(); ++i) {
            if (name == m_devices[m_gpu_sys_devs[i]].name) {
                return static_cast<unsigned>(i);
            }
        }

        ADD_FAILURE() << "no gpu " << name;
        return 0;
    }

    /* The HCA devices of a GPU, sorted */
    names_t hcas_of(const std::string &gpu) const
    {
        const uint64_t gpu_bit = UCS_BIT(gpu_index(gpu));
        names_t names;

        for (size_t i = 0; i < m_hcas.size(); ++i) {
            if (m_hcas[i].gpu_mask & gpu_bit) {
                names.push_back(m_devices[m_hcas[i].sys_dev].name);
            }
        }

        return sorted(names);
    }

    void expect_untouched() const
    {
        for (size_t i = 0; i < m_hcas.size(); ++i) {
            EXPECT_EQ(0ul, m_hcas[i].gpu_mask)
                    << m_devices[m_hcas[i].sys_dev].name;
        }
    }

    /* The expected HCA devices of a GPU of a NUMA node: one card of each
     * board, which are the cards 0, 1 and 2, 3. The first GPU takes the first
     * card of the first board and the second card of the second board. All
     * the functions of a card are taken, the first functions of the cards
     * first, and then the next ones, up to max devices */
    static names_t expected(unsigned numa, unsigned gpu, unsigned num_funcs,
                            size_t max = UINT_MAX)
    {
        static const unsigned cards[2][2] = {{0, 3}, {1, 2}};
        names_t names;
        unsigned func, board;

        for (func = 0; func < num_funcs; ++func) {
            for (board = 0; board < 2; ++board) {
                if (names.size() < max) {
                    names.push_back(dev_name(numa, cards[gpu][board], func));
                }
            }
        }

        return sorted(names);
    }

    void expect_vera_rubin(unsigned num_numas, unsigned num_funcs,
                           size_t max = UINT_MAX) const
    {
        unsigned numa, gpu;

        for (numa = 0; numa < num_numas; ++numa) {
            for (gpu = 0; gpu < 2; ++gpu) {
                EXPECT_EQ(expected(numa, gpu, num_funcs, max),
                          hcas_of(gpu_name(numa, gpu)))
                        << "gpu " << gpu_name(numa, gpu);
            }
        }
    }

    std::vector<desc_t>                     m_descs;
    std::deque<std::string>                 m_names;
    std::vector<ucs_topo_sys_device_info_t> m_devices;
    std::vector<ucs_sys_device_t>           m_gpu_sys_devs;
    std::vector<uct_gdaki_board_dev_t>      m_hcas;
    ucs_topo_groups_t                       m_groups = {};
};


UCS_TEST_F(test_gda_board, nic_gpu_idx) {
    /* Each board of two NICs has one NIC of each GPU */
    static const unsigned owners[] = {0, 1, 1, 0, 0, 1, 1, 0};

    for (unsigned nic_idx = 0; nic_idx < ucs_static_array_size(owners);
         ++nic_idx) {
        EXPECT_EQ(owners[nic_idx], uct_gdaki_board_nic_gpu_idx(nic_idx))
                << "nic " << nic_idx;
    }
}

UCS_TEST_F(test_gda_board, one_device_per_card) {
    add_numa(0, 2, 4, 1);
    add_numa(1, 2, 4, 1);
    build();

    ASSERT_UCS_OK(assign());
    expect_vera_rubin(2, 1);

    /* The first GPU gets the first HCA of the first board and the second HCA
     * of the second board */
    EXPECT_EQ(sorted({"n0c0f0", "n0c3f0"}), hcas_of("n0g0"));
    EXPECT_EQ(sorted({"n0c1f0", "n0c2f0"}), hcas_of("n0g1"));
    EXPECT_EQ(sorted({"n1c0f0", "n1c3f0"}), hcas_of("n1g0"));
    EXPECT_EQ(sorted({"n1c1f0", "n1c2f0"}), hcas_of("n1g1"));
}

UCS_TEST_F(test_gda_board, two_devices_per_card) {
    add_numa(0, 2, 4, 2);
    add_numa(1, 2, 4, 2);
    build();

    ASSERT_UCS_OK(assign());
    expect_vera_rubin(2, 2);

    /* The devices of a card are together */
    EXPECT_EQ(sorted({"n0c0f0", "n0c0f1", "n0c3f0", "n0c3f1"}),
              hcas_of("n0g0"));
}

UCS_TEST_F(test_gda_board, registration_order) {
    add_numa(0, 2, 4, 2);
    add_numa(1, 2, 4, 2);

    /* The result does not depend on the order of the GPUs and of the IB
     * devices, only on the PCI addresses */
    for (unsigned seed = 1; seed <= 16; ++seed) {
        build(seed);
        ASSERT_UCS_OK(assign());
        expect_vera_rubin(2, 2);
        if (HasFailure()) {
            UCS_TEST_MESSAGE << "seed " << seed;
            return;
        }
    }
}

UCS_TEST_F(test_gda_board, max_per_gpu) {
    add_numa(0, 2, 4, 2);

    /* A limited GPU still takes one HCA of each board first */
    for (unsigned long max = 0; max <= 4; ++max) {
        build();
        ASSERT_UCS_OK(assign(max));
        expect_vera_rubin(1, 2, max);
    }
}

UCS_TEST_F(test_gda_board, max_per_gpu_above_all) {
    unsigned long max_values[] = {5, 100, UCS_ULUNITS_AUTO, UCS_ULUNITS_INF};

    add_numa(0, 2, 4, 2);

    for (size_t i = 0; i < ucs_static_array_size(max_values); ++i) {
        build();
        ASSERT_UCS_OK(assign(max_values[i]));
        expect_vera_rubin(1, 2);
    }
}

UCS_TEST_F(test_gda_board, max_one_per_gpu) {
    add_numa(0, 2, 4, 1);
    build();

    ASSERT_UCS_OK(assign(1));
    EXPECT_EQ(sorted({"n0c0f0"}), hcas_of("n0g0"));
    EXPECT_EQ(sorted({"n0c1f0"}), hcas_of("n0g1"));
}

UCS_TEST_F(test_gda_board, hidden_gpu) {
    std::vector<int> cuda_idxs;
    unsigned gpu_idx;

    add_numa(0, 2, 4, 1);
    add_numa(1, 2, 4, 1);
    build();
    ASSERT_UCS_OK(assign());

    /* The second GPU of the first NUMA node is hidden from CUDA. The other GPUs
     * are numbered by CUDA in the order of the array */
    cuda_idxs.resize(m_gpu_sys_devs.size());
    for (gpu_idx = 0; gpu_idx < cuda_idxs.size(); ++gpu_idx) {
        cuda_idxs[gpu_idx] = (gpu_idx == gpu_index("n0g1")) ?
                                     -1 : static_cast<int>(gpu_idx);
    }

    for (size_t i = 0; i < m_hcas.size(); ++i) {
        const std::string name = m_devices[m_hcas[i].sys_dev].name;
        const uint64_t cuda_map = uct_gdaki_board_cuda_map(
                m_hcas[i].gpu_mask, &cuda_idxs[0],
                static_cast<unsigned>(cuda_idxs.size()));

        if ((name == "n0c1f0") || (name == "n0c2f0")) {
            /* Reserved by the hidden GPU, not in the map of any GPU */
            EXPECT_EQ(0ul, cuda_map) << name;
        } else {
            EXPECT_NE(0ul, cuda_map) << name;
        }
    }

    /* The GPUs which are not hidden have the same HCAs as without a hidden
     * GPU */
    expect_vera_rubin(2, 1);
}

UCS_TEST_F(test_gda_board, cuda_map) {
    const int cuda_idxs[] = {0, -1, 1, 2};

    EXPECT_EQ(0ul, uct_gdaki_board_cuda_map(0, cuda_idxs, 4));
    EXPECT_EQ(UCS_BIT(0), uct_gdaki_board_cuda_map(UCS_BIT(0), cuda_idxs, 4));
    EXPECT_EQ(0ul, uct_gdaki_board_cuda_map(UCS_BIT(1), cuda_idxs, 4));
    EXPECT_EQ(UCS_BIT(1) | UCS_BIT(2),
              uct_gdaki_board_cuda_map(UCS_BIT(1) | UCS_BIT(2) | UCS_BIT(3),
                                       cuda_idxs, 4));
}

UCS_TEST_F(test_gda_board, hca_not_in_filter) {
    /* A device of another kind, such as a storage NIC, which is not in the
     * devices to assign, does not change the groups */
    add_numa(0, 2, 4, 1);
    add_desc("storage", 0x3000, 1, 0, UCS_TOPO_DEVICE_CLASS_NET, 0, false);
    build();

    ASSERT_UCS_OK(assign());
    expect_vera_rubin(1, 1);
}

UCS_TEST_F(test_gda_board, hca_only_numa_node) {
    /* The HCAs of a NUMA node without GPUs are not assigned */
    add_numa(0, 2, 4, 1);
    add_numa(1, 0, 4, 1);
    build();

    ASSERT_UCS_OK(assign());
    expect_vera_rubin(1, 1);

    for (size_t i = 0; i < m_hcas.size(); ++i) {
        if (m_devices[m_hcas[i].sys_dev].numa_node == 1) {
            EXPECT_EQ(0ul, m_hcas[i].gpu_mask)
                    << m_devices[m_hcas[i].sys_dev].name;
        }
    }
}

UCS_TEST_F(test_gda_board, three_cards) {
    add_numa(0, 2, 3, 1);
    build();

    EXPECT_EQ(UCS_ERR_UNSUPPORTED, assign());
    expect_untouched();
}

UCS_TEST_F(test_gda_board, six_cards) {
    add_numa(0, 2, 6, 1);
    build();

    EXPECT_EQ(UCS_ERR_UNSUPPORTED, assign());
    expect_untouched();
}

UCS_TEST_F(test_gda_board, one_gpu) {
    add_numa(0, 1, 4, 1);
    build();

    EXPECT_EQ(UCS_ERR_UNSUPPORTED, assign());
    expect_untouched();
}

UCS_TEST_F(test_gda_board, three_gpus) {
    add_numa(0, 3, 4, 1);
    build();

    EXPECT_EQ(UCS_ERR_UNSUPPORTED, assign());
    expect_untouched();
}

UCS_TEST_F(test_gda_board, one_bad_numa_node) {
    /* All the groups with GPUs have to be as expected */
    add_numa(0, 2, 4, 1);
    add_numa(1, 2, 3, 1);
    build();

    EXPECT_EQ(UCS_ERR_UNSUPPORTED, assign());
    expect_untouched();
}

UCS_TEST_F(test_gda_board, different_devices_per_card) {
    add_numa(0, 2, 4, 2);
    remove_desc("n0c3f1");
    build();

    EXPECT_EQ(UCS_ERR_UNSUPPORTED, assign());
    expect_untouched();
}

UCS_TEST_F(test_gda_board, different_devices_per_card_numa) {
    add_numa(0, 2, 4, 2);
    add_numa(1, 2, 4, 1);
    build();

    EXPECT_EQ(UCS_ERR_UNSUPPORTED, assign());
    expect_untouched();
}

UCS_TEST_F(test_gda_board, hca_without_numa_node) {
    /* A device without a NUMA node is not in any group */
    add_numa(0, 2, 4, 1);
    find_desc("n0c1f0").numa_node = UCS_NUMA_NODE_UNDEFINED;
    build();

    EXPECT_EQ(UCS_ERR_UNSUPPORTED, assign());
    expect_untouched();
}

UCS_TEST_F(test_gda_board, gpu_without_numa_node) {
    add_numa(0, 2, 4, 1);
    add_numa(1, 2, 4, 1);
    find_desc("n1g1").numa_node = UCS_NUMA_NODE_UNDEFINED;
    build();

    EXPECT_EQ(UCS_ERR_UNSUPPORTED, assign());
    expect_untouched();
}

UCS_TEST_F(test_gda_board, gpu_not_in_groups) {
    add_numa(0, 2, 4, 1);
    build();

    /* A GPU which is not in the topology groups */
    m_gpu_sys_devs.push_back(m_hcas[0].sys_dev);

    EXPECT_EQ(UCS_ERR_UNSUPPORTED, assign());
    expect_untouched();
}

UCS_TEST_F(test_gda_board, group_gpu_not_in_gpus) {
    add_numa(0, 2, 4, 1);
    build();

    /* A GPU of a group which is not one of the GPUs */
    m_gpu_sys_devs.pop_back();

    EXPECT_EQ(UCS_ERR_UNSUPPORTED, assign());
    expect_untouched();
}

UCS_TEST_F(test_gda_board, no_gpus) {
    add_numa(0, 0, 4, 1);
    build();

    EXPECT_EQ(UCS_ERR_UNSUPPORTED, assign());
    expect_untouched();
}
