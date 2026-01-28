#include "CumulusHelper.h"
#include "SSHDeployer.h"
#include <iostream>
#include <filesystem>
#include <vector>

// Global instance
CumulusHelper g_cumulus;

CumulusHelper::CumulusHelper()
{
}

std::string CumulusHelper::getLogPrefix() const
{
    return "[Cumulus]";
}

// ==================== Connection ====================

bool CumulusHelper::connect()
{
    return g_ssh_deployer_cumulus.testConnection();
}

bool CumulusHelper::configureSwp1325()
{

    // 1. Test connection
    if (!connect())
    {
        std::cerr << getLogPrefix() << " Configuration failed: Cannot connect to switch" << std::endl;
        return false;
    }

    // for (int vlan_id = 97; vlan_id <= 100; vlan_id++)
    // {
    //     if (!addVLAN("swp13", vlan_id))
    //     {
    //         std::cerr << getLogPrefix() << " Failed to add VLAN " << vlan_id << " to swp13" << std::endl;
    //         return false;
    //     }
    // }

    // for (int vlan_id = 225; vlan_id <= 228; vlan_id++)
    // {
    //     if (!addVLAN("swp13", vlan_id))
    //     {
    //         std::cerr << getLogPrefix() << " Failed to add VLAN " << vlan_id << " to swp13" << std::endl;
    //         return false;
    //     }
    // }

    // if (!setUntaggedVLAN("swp13", 49))
    // {
    //     std::cerr << getLogPrefix() << " Failed to set untagged VLAN 1 on swp13" << std::endl;
    //     return false;
    // }

    // if (!apply())
    //     return false;

    // if (!addVLAN("swp25s0", 97))
    // {
    //     std::cerr << getLogPrefix() << " Failed to add VLAN " << "97" << " to swp25s0" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    if (!egressUntagged("swp25s0", 97, true))
    {
        std::cerr << getLogPrefix() << " Failed to add bridge VLAN 97 untagged to swp25s0  " << std::endl;
        return false;
    }
    // if (!apply())
    //     return false;

    // // 4. nv set interface swp25s3 bridge domain br_default untagged 4
    // if (!setUntaggedVLAN("swp25s0", 225))
    // {
    //     std::cerr << getLogPrefix() << " Failed to set untagged VLAN 225 on swp25s3" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    /********************************** */

    // if (!addVLAN("swp25s1", 98))
    // {
    //     std::cerr << getLogPrefix() << " Failed to add VLAN " << "98" << " to swp25s1" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    if (!egressUntagged("swp25s1", 98, true))
    {
        std::cerr << getLogPrefix() << " Failed to add bridge VLAN 98 untagged to swp25s1  " << std::endl;
        return false;
    }
    // if (!apply())
    //     return false;

    // if (!setUntaggedVLAN("swp25s1", 226))
    // {
    //     std::cerr << getLogPrefix() << " Failed to set untagged VLAN 226 on swp25s1" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    /********************************** */

    // if (!addVLAN("swp25s2", 99))
    // {
    //     std::cerr << getLogPrefix() << " Failed to add VLAN " << "99" << " to swp25s2" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    if (!egressUntagged("swp25s2", 99, true))
    {
        std::cerr << getLogPrefix() << " Failed to add bridge VLAN 99 untagged to swp25s2  " << std::endl;
        return false;
    }
    // if (!apply())
    //     return false;

    // if (!setUntaggedVLAN("swp25s2", 227))
    // {
    //     std::cerr << getLogPrefix() << " Failed to set untagged VLAN 227 on swp25s2" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    /********************************** */

    // if (!addVLAN("swp25s3", 100))
    // {
    //     std::cerr << getLogPrefix() << " Failed to add VLAN " << "100" << " to swp25s3" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    if (!egressUntagged("swp25s3", 100, true))
    {
        std::cerr << getLogPrefix() << " Failed to add bridge VLAN 100 untagged to swp25s3  " << std::endl;
        return false;
    }
    // if (!apply())
    //     return false;

    // if (!setUntaggedVLAN("swp25s3", 228))
    // {
    //     std::cerr << getLogPrefix() << " Failed to set untagged VLAN 228 on swp25s3" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    std::cout << "\n========================================" << std::endl;
    std::cout << getLogPrefix() << " VLAN Configuration Sw13 and Swp25 Completed Successfully!" << std::endl;
    std::cout << "========================================\n"
              << std::endl;

    return true;
}

bool CumulusHelper::configureSwp1426()
{

    // 1. Test connection
    if (!connect())
    {
        std::cerr << getLogPrefix() << " Configuration failed: Cannot connect to switch" << std::endl;
        return false;
    }

    // for (int vlan_id = 101; vlan_id <= 104; vlan_id++)
    // {
    //     if (!addVLAN("swp14", vlan_id))
    //     {
    //         std::cerr << getLogPrefix() << " Failed to add VLAN " << vlan_id << " to swp14" << std::endl;
    //         return false;
    //     }
    // }

    // for (int vlan_id = 229; vlan_id <= 232; vlan_id++)
    // {
    //     if (!addVLAN("swp14", vlan_id))
    //     {
    //         std::cerr << getLogPrefix() << " Failed to add VLAN " << vlan_id << " to swp14" << std::endl;
    //         return false;
    //     }
    // }

    // if (!setUntaggedVLAN("swp14", 50))
    // {
    //     std::cerr << getLogPrefix() << " Failed to set untagged VLAN 2 on swp14" << std::endl;
    //     return false;
    // }

    // if (!apply())
    //     return false;

    // if (!addVLAN("swp26s0", 101))
    // {
    //     std::cerr << getLogPrefix() << " Failed to add VLAN " << "101" << " to swp26s0" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    if (!egressUntagged("swp26s0", 101, true))
    {
        std::cerr << getLogPrefix() << " Failed to add bridge VLAN 101 untagged to swp26s0  " << std::endl;
        return false;
    }
    // if (!apply())
    //     return false;

    // // 4. nv set interface swp25s3 bridge domain br_default untagged 4
    // if (!setUntaggedVLAN("swp26s0", 229))
    // {
    //     std::cerr << getLogPrefix() << " Failed to set untagged VLAN 229 on swp26s0" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    // /********************************** */

    // if (!addVLAN("swp26s1", 102))
    // {
    //     std::cerr << getLogPrefix() << " Failed to add VLAN " << "102" << " to swp26s1" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    if (!egressUntagged("swp26s1", 102, true))
    {
        std::cerr << getLogPrefix() << " Failed to add bridge VLAN 102 untagged to swp26s1  " << std::endl;
        return false;
    }
    // if (!apply())
    //     return false;

    // if (!setUntaggedVLAN("swp26s1", 230))
    // {
    //     std::cerr << getLogPrefix() << " Failed to set untagged VLAN 230 on swp26s1" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    /********************************** */

    // if (!addVLAN("swp26s2", 103))
    // {
    //     std::cerr << getLogPrefix() << " Failed to add VLAN " << "103" << " to swp26s2" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    if (!egressUntagged("swp26s2", 103, true))
    {
        std::cerr << getLogPrefix() << " Failed to add bridge VLAN 103 untagged to swp26s2  " << std::endl;
        return false;
    }
    // if (!apply())
    //     return false;

    // if (!setUntaggedVLAN("swp26s2", 231))
    // {
    //     std::cerr << getLogPrefix() << " Failed to set untagged VLAN 231 on swp26s2" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    // /********************************** */

    // if (!addVLAN("swp26s3", 104))
    // {
    //     std::cerr << getLogPrefix() << " Failed to add VLAN " << "104" << " to swp26s3" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    if (!egressUntagged("swp26s3", 104, true))
    {
        std::cerr << getLogPrefix() << " Failed to add bridge VLAN 100 untagged to swp26s3  " << std::endl;
        return false;
    }
    // if (!apply())
    //     return false;

    // if (!setUntaggedVLAN("swp26s3", 232))
    // {
    //     std::cerr << getLogPrefix() << " Failed to set untagged VLAN 232 on swp26s3" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    std::cout << "\n========================================" << std::endl;
    std::cout << getLogPrefix() << " VLAN Configuration Sw14 and Swp26 Completed Successfully!" << std::endl;
    std::cout << "========================================\n"
              << std::endl;

    return true;
}

bool CumulusHelper::configureSwp1527()
{

    // 1. Test connection
    if (!connect())
    {
        std::cerr << getLogPrefix() << " Configuration failed: Cannot connect to switch" << std::endl;
        return false;
    }

    // for (int vlan_id = 105; vlan_id <= 108; vlan_id++)
    // {
    //     if (!addVLAN("swp15", vlan_id))
    //     {
    //         std::cerr << getLogPrefix() << " Failed to add VLAN " << vlan_id << " to swp15" << std::endl;
    //         return false;
    //     }
    // }

    // for (int vlan_id = 233; vlan_id <= 236; vlan_id++)
    // {
    //     if (!addVLAN("swp15", vlan_id))
    //     {
    //         std::cerr << getLogPrefix() << " Failed to add VLAN " << vlan_id << " to swp15" << std::endl;
    //         return false;
    //     }
    // }

    // if (!setUntaggedVLAN("swp15", 51))
    // {
    //     std::cerr << getLogPrefix() << " Failed to set untagged VLAN 3 on swp15" << std::endl;
    //     return false;
    // }

    // if (!apply())
    //     return false;

    // if (!addVLAN("swp27s0", 105))
    // {
    //     std::cerr << getLogPrefix() << " Failed to add VLAN " << "105" << " to swp27s0" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    if (!egressUntagged("swp27s0", 105, true))
    {
        std::cerr << getLogPrefix() << " Failed to add bridge VLAN 105 untagged to swp27s0  " << std::endl;
        return false;
    }
    // if (!apply())
    //     return false;

    // // 4. nv set interface swp25s3 bridge domain br_default untagged 4
    // if (!setUntaggedVLAN("swp27s0", 233))
    // {
    //     std::cerr << getLogPrefix() << " Failed to set untagged VLAN 233 on swp27s0" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    // /********************************** */

    // if (!addVLAN("swp27s1", 106))
    // {
    //     std::cerr << getLogPrefix() << " Failed to add VLAN " << "106" << " to swp27s1" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    if (!egressUntagged("swp27s1", 106, true))
    {
        std::cerr << getLogPrefix() << " Failed to add bridge VLAN 106 untagged to swp27s1  " << std::endl;
        return false;
    }
    // if (!apply())
    //     return false;

    // if (!setUntaggedVLAN("swp27s1", 234))
    // {
    //     std::cerr << getLogPrefix() << " Failed to set untagged VLAN 234 on swp27s1" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    // /********************************** */

    // if (!addVLAN("swp27s2", 107))
    // {
    //     std::cerr << getLogPrefix() << " Failed to add VLAN " << "107" << " to swp27s2" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    if (!egressUntagged("swp27s2", 107, true))
    {
        std::cerr << getLogPrefix() << " Failed to add bridge VLAN 107 untagged to swp27s2  " << std::endl;
        return false;
    }
    // if (!apply())
    //     return false;

    // if (!setUntaggedVLAN("swp27s2", 235))
    // {
    //     std::cerr << getLogPrefix() << " Failed to set untagged VLAN 235 on swp27s2" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    // /********************************** */

    // if (!addVLAN("swp27s3", 108))
    // {
    //     std::cerr << getLogPrefix() << " Failed to add VLAN " << "108" << " to swp27s3" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    if (!egressUntagged("swp27s3", 108, true))
    {
        std::cerr << getLogPrefix() << " Failed to add bridge VLAN 108 untagged to swp27s3  " << std::endl;
        return false;
    }
    // if (!apply())
    //     return false;

    // if (!setUntaggedVLAN("swp27s3", 236))
    // {
    //     std::cerr << getLogPrefix() << " Failed to set untagged VLAN 236 on swp27s3" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    std::cout << "\n========================================" << std::endl;
    std::cout << getLogPrefix() << " VLAN Configuration Sw15 and Swp27 Completed Successfully!" << std::endl;
    std::cout << "========================================\n"
              << std::endl;

    return true;
}

bool CumulusHelper::configureSwp1628()
{

    // 1. Test connection
    if (!connect())
    {
        std::cerr << getLogPrefix() << " Configuration failed: Cannot connect to switch" << std::endl;
        return false;
    }

    // for (int vlan_id = 109; vlan_id <= 112; vlan_id++)
    // {
    //     if (!addVLAN("swp16", vlan_id))
    //     {
    //         std::cerr << getLogPrefix() << " Failed to add VLAN " << vlan_id << " to swp16" << std::endl;
    //         return false;
    //     }
    // }

    // for (int vlan_id = 237; vlan_id <= 240; vlan_id++)
    // {
    //     if (!addVLAN("swp16", vlan_id))
    //     {
    //         std::cerr << getLogPrefix() << " Failed to add VLAN " << vlan_id << " to swp16" << std::endl;
    //         return false;
    //     }
    // }

    // if (!setUntaggedVLAN("swp16", 52))
    // {
    //     std::cerr << getLogPrefix() << " Failed to set untagged VLAN 4 on swp16" << std::endl;
    //     return false;
    // }

    // if (!apply())
    //     return false;

    // if (!addVLAN("swp28s0", 109))
    // {
    //     std::cerr << getLogPrefix() << " Failed to add VLAN " << "109" << " to swp28s0" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    if (!egressUntagged("swp28s0", 109, true))
    {
        std::cerr << getLogPrefix() << " Failed to add bridge VLAN 109 untagged to swp28s0  " << std::endl;
        return false;
    }
    // if (!apply())
    //     return false;

    // // 4. nv set interface swp25s3 bridge domain br_default untagged 4
    // if (!setUntaggedVLAN("swp28s0", 237))
    // {
    //     std::cerr << getLogPrefix() << " Failed to set untagged VLAN 237 on swp28s0" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    // /********************************** */

    // if (!addVLAN("swp28s1", 110))
    // {
    //     std::cerr << getLogPrefix() << " Failed to add VLAN " << "110" << " to swp28s1" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    if (!egressUntagged("swp28s1", 110, true))
    {
        std::cerr << getLogPrefix() << " Failed to add bridge VLAN 110 untagged to swp28s1  " << std::endl;
        return false;
    }
    // if (!apply())
    //     return false;

    // if (!setUntaggedVLAN("swp28s1", 238))
    // {
    //     std::cerr << getLogPrefix() << " Failed to set untagged VLAN 238 on swp28s1" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    // /********************************** */

    // if (!addVLAN("swp28s2", 111))
    // {
    //     std::cerr << getLogPrefix() << " Failed to add VLAN " << "111" << " to swp28s2" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    if (!egressUntagged("swp28s2", 111, true))
    {
        std::cerr << getLogPrefix() << " Failed to add bridge VLAN 111 untagged to swp28s2  " << std::endl;
        return false;
    }
    // if (!apply())
    //     return false;

    // if (!setUntaggedVLAN("swp28s2", 239))
    // {
    //     std::cerr << getLogPrefix() << " Failed to set untagged VLAN 239 on swp28s2" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    // /********************************** */

    // if (!addVLAN("swp28s3", 112))
    // {
    //     std::cerr << getLogPrefix() << " Failed to add VLAN " << "112" << " to swp28s3" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    if (!egressUntagged("swp28s3", 112, true))
    {
        std::cerr << getLogPrefix() << " Failed to add bridge VLAN 112 untagged to swp28s3  " << std::endl;
        return false;
    }
    // if (!apply())
    //     return false;

    // if (!setUntaggedVLAN("swp28s3", 240))
    // {
    //     std::cerr << getLogPrefix() << " Failed to set untagged VLAN 240 on swp28s3" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    std::cout << "\n========================================" << std::endl;
    std::cout << getLogPrefix() << " VLAN Configuration Sw16 and Swp28 Completed Successfully!" << std::endl;
    std::cout << "========================================\n"
              << std::endl;

    return true;
}

bool CumulusHelper::configureSwp1729()
{

    // 1. Test connection
    if (!connect())
    {
        std::cerr << getLogPrefix() << " Configuration failed: Cannot connect to switch" << std::endl;
        return false;
    }

    // for (int vlan_id = 113; vlan_id <= 116; vlan_id++)
    // {
    //     if (!addVLAN("swp17", vlan_id))
    //     {
    //         std::cerr << getLogPrefix() << " Failed to add VLAN " << vlan_id << " to swp17" << std::endl;
    //         return false;
    //     }
    // }

    // for (int vlan_id = 241; vlan_id <= 244; vlan_id++)
    // {
    //     if (!addVLAN("swp17", vlan_id))
    //     {
    //         std::cerr << getLogPrefix() << " Failed to add VLAN " << vlan_id << " to swp17" << std::endl;
    //         return false;
    //     }
    // }

    // if (!setUntaggedVLAN("swp17", 53))
    // {
    //     std::cerr << getLogPrefix() << " Failed to set untagged VLAN 5 on swp17" << std::endl;
    //     return false;
    // }

    // if (!apply())
    //     return false;

    // if (!addVLAN("swp29s0", 113))
    // {
    //     std::cerr << getLogPrefix() << " Failed to add VLAN " << "113" << " to swp29s0" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    if (!egressUntagged("swp29s0", 113, true))
    {
        std::cerr << getLogPrefix() << " Failed to add bridge VLAN 113 untagged to swp29s0  " << std::endl;
        return false;
    }
    // if (!apply())
    //     return false;

    // // 4. nv set interface swp25s3 bridge domain br_default untagged 4
    // if (!setUntaggedVLAN("swp29s0", 241))
    // {
    //     std::cerr << getLogPrefix() << " Failed to set untagged VLAN 241 on swp29s0" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    // /********************************** */

    // if (!addVLAN("swp29s1", 114))
    // {
    //     std::cerr << getLogPrefix() << " Failed to add VLAN " << "114" << " to swp29s1" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    if (!egressUntagged("swp29s1", 114, true))
    {
        std::cerr << getLogPrefix() << " Failed to add bridge VLAN 114 untagged to swp29s1  " << std::endl;
        return false;
    }
    // if (!apply())
    //     return false;

    // if (!setUntaggedVLAN("swp29s1", 242))
    // {
    //     std::cerr << getLogPrefix() << " Failed to set untagged VLAN 242 on swp28s1" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    // /********************************** */

    // if (!addVLAN("swp29s2", 115))
    // {
    //     std::cerr << getLogPrefix() << " Failed to add VLAN " << "115" << " to swp29s2" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    if (!egressUntagged("swp29s2", 115, true))
    {
        std::cerr << getLogPrefix() << " Failed to add bridge VLAN 115 untagged to swp29s2  " << std::endl;
        return false;
    }
    // if (!apply())
    //     return false;

    // if (!setUntaggedVLAN("swp29s2", 243))
    // {
    //     std::cerr << getLogPrefix() << " Failed to set untagged VLAN 234 on swp29s2" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    // /********************************** */

    // if (!addVLAN("swp29s3", 116))
    // {
    //     std::cerr << getLogPrefix() << " Failed to add VLAN " << "116" << " to swp29s3" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    if (!egressUntagged("swp29s3", 116, true))
    {
        std::cerr << getLogPrefix() << " Failed to add bridge VLAN 116 untagged to swp29s3  " << std::endl;
        return false;
    }
    // if (!apply())
    //     return false;

    // if (!setUntaggedVLAN("swp29s3", 244))
    // {
    //     std::cerr << getLogPrefix() << " Failed to set untagged VLAN 244 on swp29s3" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    std::cout << "\n========================================" << std::endl;
    std::cout << getLogPrefix() << " VLAN Configuration Sw17 and Swp29 Completed Successfully!" << std::endl;
    std::cout << "========================================\n"
              << std::endl;

    return true;
}

bool CumulusHelper::configureSwp1830()
{

    // 1. Test connection
    if (!connect())
    {
        std::cerr << getLogPrefix() << " Configuration failed: Cannot connect to switch" << std::endl;
        return false;
    }

    // for (int vlan_id = 117; vlan_id <= 120; vlan_id++)
    // {
    //     if (!addVLAN("swp18", vlan_id))
    //     {
    //         std::cerr << getLogPrefix() << " Failed to add VLAN " << vlan_id << " to swp18" << std::endl;
    //         return false;
    //     }
    // }

    // for (int vlan_id = 245; vlan_id <= 248; vlan_id++)
    // {
    //     if (!addVLAN("swp18", vlan_id))
    //     {
    //         std::cerr << getLogPrefix() << " Failed to add VLAN " << vlan_id << " to swp18" << std::endl;
    //         return false;
    //     }
    // }

    // if (!setUntaggedVLAN("swp18", 54))
    // {
    //     std::cerr << getLogPrefix() << " Failed to set untagged VLAN 6 on swp18" << std::endl;
    //     return false;
    // }

    // if (!apply())
    //     return false;

    // if (!addVLAN("swp30s0", 117))
    // {
    //     std::cerr << getLogPrefix() << " Failed to add VLAN " << "117" << " to swp30s0" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    if (!egressUntagged("swp30s0", 117, true))
    {
        std::cerr << getLogPrefix() << " Failed to add bridge VLAN 117 untagged to swp30s0  " << std::endl;
        return false;
    }
    // if (!apply())
    //     return false;

    // // 4. nv set interface swp25s3 bridge domain br_default untagged 4
    // if (!setUntaggedVLAN("swp30s0", 245))
    // {
    //     std::cerr << getLogPrefix() << " Failed to set untagged VLAN 245 on swp30s0" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    // /********************************** */

    // if (!addVLAN("swp30s1", 118))
    // {
    //     std::cerr << getLogPrefix() << " Failed to add VLAN " << "118" << " to swp30s1" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    if (!egressUntagged("swp30s1", 118, true))
    {
        std::cerr << getLogPrefix() << " Failed to add bridge VLAN 118 untagged to swp30s1  " << std::endl;
        return false;
    }
    // if (!apply())
    //     return false;

    // if (!setUntaggedVLAN("swp30s1", 246))
    // {
    //     std::cerr << getLogPrefix() << " Failed to set untagged VLAN 246 on swp30s1" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    // /********************************** */

    // if (!addVLAN("swp30s2", 119))
    // {
    //     std::cerr << getLogPrefix() << " Failed to add VLAN " << "119" << " to swp30s2" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    if (!egressUntagged("swp30s2", 119, true))
    {
        std::cerr << getLogPrefix() << " Failed to add bridge VLAN 119 untagged to swp30s2  " << std::endl;
        return false;
    }
    // if (!apply())
    //     return false;

    // if (!setUntaggedVLAN("swp30s2", 247))
    // {
    //     std::cerr << getLogPrefix() << " Failed to set untagged VLAN 247 on swp30s2" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    // /********************************** */

    // if (!addVLAN("swp30s3", 120))
    // {
    //     std::cerr << getLogPrefix() << " Failed to add VLAN " << "120" << " to swp30s3" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    if (!egressUntagged("swp30s3", 120, true))
    {
        std::cerr << getLogPrefix() << " Failed to add bridge VLAN 120 untagged to swp30s3  " << std::endl;
        return false;
    }
    // if (!apply())
    //     return false;

    // if (!setUntaggedVLAN("swp30s3", 248))
    // {
    //     std::cerr << getLogPrefix() << " Failed to set untagged VLAN 248 on swp30s3" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    std::cout << "\n========================================" << std::endl;
    std::cout << getLogPrefix() << " VLAN Configuration Sw18 and Swp30 Completed Successfully!" << std::endl;
    std::cout << "========================================\n"
              << std::endl;

    return true;
}

bool CumulusHelper::configureSwp1931()
{

    // 1. Test connection
    if (!connect())
    {
        std::cerr << getLogPrefix() << " Configuration failed: Cannot connect to switch" << std::endl;
        return false;
    }

    // for (int vlan_id = 121; vlan_id <= 124; vlan_id++)
    // {
    //     if (!addVLAN("swp19", vlan_id))
    //     {
    //         std::cerr << getLogPrefix() << " Failed to add VLAN " << vlan_id << " to swp19" << std::endl;
    //         return false;
    //     }
    // }

    // for (int vlan_id = 249; vlan_id <= 252; vlan_id++)
    // {
    //     if (!addVLAN("swp19", vlan_id))
    //     {
    //         std::cerr << getLogPrefix() << " Failed to add VLAN " << vlan_id << " to swp19" << std::endl;
    //         return false;
    //     }
    // }

    // if (!setUntaggedVLAN("swp19", 55))
    // {
    //     std::cerr << getLogPrefix() << " Failed to set untagged VLAN 7 on swp19" << std::endl;
    //     return false;
    // }

    // if (!apply())
    //     return false;

    // if (!addVLAN("swp31s0", 121))
    // {
    //     std::cerr << getLogPrefix() << " Failed to add VLAN " << "121" << " to swp31s0" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    if (!egressUntagged("swp31s0", 121, true))
    {
        std::cerr << getLogPrefix() << " Failed to add bridge VLAN 121 untagged to swp31s0  " << std::endl;
        return false;
    }
    // if (!apply())
    //     return false;

    // // 4. nv set interface swp25s3 bridge domain br_default untagged 4
    // if (!setUntaggedVLAN("swp31s0", 249))
    // {
    //     std::cerr << getLogPrefix() << " Failed to set untagged VLAN 249 on swp31s0" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    // /********************************** */

    // if (!addVLAN("swp31s1", 122))
    // {
    //     std::cerr << getLogPrefix() << " Failed to add VLAN " << "122" << " to swp31s1" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    if (!egressUntagged("swp31s1", 122, true))
    {
        std::cerr << getLogPrefix() << " Failed to add bridge VLAN 122 untagged to swp31s1  " << std::endl;
        return false;
    }
    // if (!apply())
    //     return false;

    // if (!setUntaggedVLAN("swp31s1", 250))
    // {
    //     std::cerr << getLogPrefix() << " Failed to set untagged VLAN 250 on swp31s1" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    // /********************************** */

    // if (!addVLAN("swp31s2", 123))
    // {
    //     std::cerr << getLogPrefix() << " Failed to add VLAN " << "123" << " to swp31s2" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    if (!egressUntagged("swp31s2", 123, true))
    {
        std::cerr << getLogPrefix() << " Failed to add bridge VLAN 123 untagged to swp31s2  " << std::endl;
        return false;
    }
    // if (!apply())
    //     return false;

    // if (!setUntaggedVLAN("swp31s2", 251))
    // {
    //     std::cerr << getLogPrefix() << " Failed to set untagged VLAN 251 on swp31s2" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    // /********************************** */

    // if (!addVLAN("swp31s3", 124))
    // {
    //     std::cerr << getLogPrefix() << " Failed to add VLAN " << "124" << " to swp31s3" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    if (!egressUntagged("swp31s3", 124, true))
    {
        std::cerr << getLogPrefix() << " Failed to add bridge VLAN 124 untagged to swp31s3  " << std::endl;
        return false;
    }
    // if (!apply())
    //     return false;

    // if (!setUntaggedVLAN("swp31s3", 252))
    // {
    //     std::cerr << getLogPrefix() << " Failed to set untagged VLAN 252 on swp31s3" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    std::cout << "\n========================================" << std::endl;
    std::cout << getLogPrefix() << " VLAN Configuration Swp19 and Swp31 Completed Successfully!" << std::endl;
    std::cout << "========================================\n"
              << std::endl;

    return true;
}

bool CumulusHelper::configureSwp2032()
{

    // 1. Test connection
    if (!connect())
    {
        std::cerr << getLogPrefix() << " Configuration failed: Cannot connect to switch" << std::endl;
        return false;
    }

    // for (int vlan_id = 125; vlan_id <= 128; vlan_id++)
    // {
    //     if (!addVLAN("swp20", vlan_id))
    //     {
    //         std::cerr << getLogPrefix() << " Failed to add VLAN " << vlan_id << " to swp20" << std::endl;
    //         return false;
    //     }
    // }

    // for (int vlan_id = 253; vlan_id <= 256; vlan_id++)
    // {
    //     if (!addVLAN("swp20", vlan_id))
    //     {
    //         std::cerr << getLogPrefix() << " Failed to add VLAN " << vlan_id << " to swp20" << std::endl;
    //         return false;
    //     }
    // }

    // if (!setUntaggedVLAN("swp20", 56))
    // {
    //     std::cerr << getLogPrefix() << " Failed to set untagged VLAN 8 on swp20" << std::endl;
    //     return false;
    // }

    // if (!apply())
    //     return false;

    // if (!addVLAN("swp32s0", 125))
    // {
    //     std::cerr << getLogPrefix() << " Failed to add VLAN " << "125" << " to swp32s0" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    if (!egressUntagged("swp32s0", 125, true))
    {
        std::cerr << getLogPrefix() << " Failed to add bridge VLAN 125 untagged to swp32s0  " << std::endl;
        return false;
    }
    // if (!apply())
    //     return false;

    // // 4. nv set interface swp25s3 bridge domain br_default untagged 4
    // if (!setUntaggedVLAN("swp32s0", 253))
    // {
    //     std::cerr << getLogPrefix() << " Failed to set untagged VLAN 253 on swp32s0" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    // /********************************** */

    // if (!addVLAN("swp32s1", 126))
    // {
    //     std::cerr << getLogPrefix() << " Failed to add VLAN " << "126" << " to swp32s1" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    if (!egressUntagged("swp32s1", 126, true))
    {
        std::cerr << getLogPrefix() << " Failed to add bridge VLAN 126 untagged to swp32s1  " << std::endl;
        return false;
    }
    // if (!apply())
    //     return false;

    // if (!setUntaggedVLAN("swp32s1", 254))
    // {
    //     std::cerr << getLogPrefix() << " Failed to set untagged VLAN 254 on swp32s1" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    // /********************************** */

    // if (!addVLAN("swp32s2", 127))
    // {
    //     std::cerr << getLogPrefix() << " Failed to add VLAN " << "127" << " to swp32s2" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    if (!egressUntagged("swp32s2", 127, true))
    {
        std::cerr << getLogPrefix() << " Failed to add bridge VLAN 127 untagged to swp32s2  " << std::endl;
        return false;
    }
    // if (!apply())
    //     return false;

    // if (!setUntaggedVLAN("swp32s2", 255))
    // {
    //     std::cerr << getLogPrefix() << " Failed to set untagged VLAN 255 on swp32s2" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    // /********************************** */

    // if (!addVLAN("swp32s3", 128))
    // {
    //     std::cerr << getLogPrefix() << " Failed to add VLAN " << "128" << " to swp32s3" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    if (!egressUntagged("swp32s3", 128, true))
    {
        std::cerr << getLogPrefix() << " Failed to add bridge VLAN 128 untagged to swp32s3  " << std::endl;
        return false;
    }
    // if (!apply())
    //     return false;

    // if (!setUntaggedVLAN("swp32s3", 256))
    // {
    //     std::cerr << getLogPrefix() << " Failed to set untagged VLAN 256 on swp32s3" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    std::cout << "\n========================================" << std::endl;
    std::cout << getLogPrefix() << " VLAN Configuration Swp20 and Swp32 Completed Successfully!" << std::endl;
    std::cout << "========================================\n"
              << std::endl;

    return true;
}

bool CumulusHelper::configureSequence()
{
    std::cout << "\n========================================" << std::endl;
    std::cout << getLogPrefix() << " Starting VLAN Configuration Sequence" << std::endl;
    std::cout << "========================================" << std::endl;

    // 1. Test connection
    if (!connect())
    {
        std::cerr << getLogPrefix() << " Configuration failed: Cannot connect to switch" << std::endl;
        return false;
    }

    configureSwp1325();
    configureSwp1426();
    configureSwp1527();
    configureSwp1628();
    configureSwp1729();
    configureSwp1830();
    configureSwp1931();
    configureSwp2032();

    // // 2. nv set interface swp25s3 bridge domain br_default vlan 100
    // if (!addVLAN("swp25s3", 100))
    // {
    //     std::cerr << getLogPrefix() << " Failed to add VLAN 100 to swp25s3" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    // // 3. sudo bridge vlan add dev swp25s3 vid 100 untagged
    // if (!bridgeVLANAdd("swp25s3", 100, true))
    // {
    //     std::cerr << getLogPrefix() << " Failed to add bridge VLAN 100 untagged to swp25s3" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    // // 4. nv set interface swp25s3 bridge domain br_default untagged 4
    // if (!setUntaggedVLAN("swp25s3", 4))
    // {
    //     std::cerr << getLogPrefix() << " Failed to set untagged VLAN 4 on swp25s3" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    // // 5. nv set interface swp29s3 bridge domain br_default untagged 244
    // if (!setUntaggedVLAN("swp29s3", 244))
    // {
    //     std::cerr << getLogPrefix() << " Failed to set untagged VLAN 244 on swp29s3" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    // // 6. nv set interface swp17 bridge domain br_default vlan 244
    // if (!addVLAN("swp17", 244))
    // {
    //     std::cerr << getLogPrefix() << " Failed to add VLAN 244 to swp17" << std::endl;
    //     return false;
    // }
    // if (!apply())
    //     return false;

    // std::cout << "\n========================================" << std::endl;
    // std::cout << getLogPrefix() << " VLAN Configuration Completed Successfully!" << std::endl;
    // std::cout << "========================================\n"
    //           << std::endl;

    return true;
}

// ==================== NVUE VLAN Commands ====================

bool CumulusHelper::addVLAN(const std::string &interface, int vlan_id, const std::string &bridge)
{
    std::cout << getLogPrefix() << " Adding VLAN " << vlan_id << " to " << interface << std::endl;
    // nv set interface swp25s3 bridge domain br_default vlan 100
    std::string cmd = "nv set interface " + interface + " bridge domain " + bridge + " vlan " + std::to_string(vlan_id);
    return g_ssh_deployer_cumulus.execute(cmd);
}

bool CumulusHelper::removeVLAN(const std::string &interface, int vlan_id, const std::string &bridge)
{
    std::cout << getLogPrefix() << " Removing VLAN " << vlan_id << " from " << interface << std::endl;
    std::string cmd = "nv unset interface " + interface + " bridge domain " + bridge + " vlan " + std::to_string(vlan_id);
    return g_ssh_deployer_cumulus.execute(cmd);
}

bool CumulusHelper::setUntaggedVLAN(const std::string &interface, int vlan_id, const std::string &bridge)
{
    std::cout << getLogPrefix() << " Setting untagged VLAN " << vlan_id << " on " << interface << std::endl;
    // nv set interface swp25s3 bridge domain br_default untagged 4
    std::string cmd = "nv set interface " + interface + " bridge domain " + bridge + " untagged " + std::to_string(vlan_id);
    return g_ssh_deployer_cumulus.execute(cmd);
}

// ==================== Bridge Commands (Direct) ====================

bool CumulusHelper::egressUntagged(const std::string &interface, int vlan_id, bool untagged)
{
    std::cout << getLogPrefix() << " Bridge: Adding VLAN " << vlan_id << " to " << interface;
    if (untagged)
        std::cout << " (untagged)";
    std::cout << std::endl;

    // sudo bridge vlan add dev swp25s3 vid 100 untagged
    std::string cmd = "bridge vlan add dev " + interface + " vid " + std::to_string(vlan_id);
    if (untagged)
    {
        cmd += " untagged";
    }
    return g_ssh_deployer_cumulus.execute(cmd, nullptr, true);
}

bool CumulusHelper::bridgeVLANRemove(const std::string &interface, int vlan_id)
{
    std::cout << getLogPrefix() << " Bridge: Removing VLAN " << vlan_id << " from " << interface << std::endl;
    std::string cmd = "bridge vlan del dev " + interface + " vid " + std::to_string(vlan_id);
    return g_ssh_deployer_cumulus.execute(cmd, nullptr, true);
}

// ==================== Configuration ====================

bool CumulusHelper::apply()
{
    std::cout << getLogPrefix() << " Applying configuration..." << std::endl;
    // Use sudo for password and 'yes' pipe for y/n confirmation
    return g_ssh_deployer_cumulus.execute("yes | nv config apply", nullptr, true);
}

bool CumulusHelper::save()
{
    std::cout << getLogPrefix() << " Saving configuration..." << std::endl;
    return g_ssh_deployer_cumulus.execute("nv config save");
}

// ==================== Network Interfaces Deployment ====================

bool CumulusHelper::deployNetworkInterfaces(const std::string& local_interfaces_path)
{
    std::cout << "\n========================================" << std::endl;
    std::cout << getLogPrefix() << " Deploying Network Interfaces" << std::endl;
    std::cout << "========================================" << std::endl;

    // Resolve file path - search in multiple locations for relative paths
    std::string resolved_path;
    std::filesystem::path input_path(local_interfaces_path);

    if (input_path.is_absolute())
    {
        resolved_path = local_interfaces_path;
    }
    else
    {
        // Search locations: current dir, parent dir, grandparent dir (project root from build/bin/)
        std::vector<std::filesystem::path> search_paths = {
            std::filesystem::current_path() / input_path,
            std::filesystem::current_path().parent_path() / input_path,
            std::filesystem::current_path().parent_path().parent_path() / input_path
        };

        for (const auto& path : search_paths)
        {
            if (std::filesystem::exists(path))
            {
                resolved_path = path.string();
                break;
            }
        }

        if (resolved_path.empty())
        {
            std::cerr << getLogPrefix() << " Deploy failed: Cannot find file '" << local_interfaces_path << "'" << std::endl;
            std::cerr << getLogPrefix() << " Searched in:" << std::endl;
            for (const auto& path : search_paths)
            {
                std::cerr << "  - " << path.string() << std::endl;
            }
            return false;
        }
    }

    std::cout << getLogPrefix() << " Using interfaces file: " << resolved_path << std::endl;

    // 1. Test connection
    std::cout << getLogPrefix() << " [Step 1/3] Testing connection..." << std::endl;
    if (!connect())
    {
        std::cerr << getLogPrefix() << " Deploy failed: Cannot connect to switch" << std::endl;
        return false;
    }

    // 2. Copy interfaces file to /etc/network/interfaces (with sudo)
    std::cout << getLogPrefix() << " [Step 2/3] Copying interfaces file..." << std::endl;
    if (!g_ssh_deployer_cumulus.copyFileToPath(resolved_path, "/etc/network/interfaces", true))
    {
        std::cerr << getLogPrefix() << " Deploy failed: Cannot copy interfaces file" << std::endl;
        return false;
    }

    // 3. Run ifreload -a to apply configuration
    std::cout << getLogPrefix() << " [Step 3/3] Reloading network interfaces (ifreload -a)..." << std::endl;
    if (!g_ssh_deployer_cumulus.execute("ifreload -a", nullptr, true))
    {
        // ifreload may return non-zero exit code but still apply changes
        std::cerr << getLogPrefix() << " Warning: ifreload -a returned non-zero exit code (changes may still be applied)" << std::endl;
    }

    std::cout << "\n========================================" << std::endl;
    std::cout << getLogPrefix() << " Network Interfaces Deployed Successfully!" << std::endl;
    std::cout << "========================================\n" << std::endl;

    return true;
}

bool CumulusHelper::showPending()
{
    std::cout << getLogPrefix() << " Showing pending changes..." << std::endl;
    return g_ssh_deployer_cumulus.execute("nv config diff");
}

// ==================== Show Commands ====================

bool CumulusHelper::showInterface(const std::string &interface)
{
    if (interface.empty())
    {
        std::cout << getLogPrefix() << " Showing all interfaces..." << std::endl;
        return g_ssh_deployer_cumulus.execute("nv show interface");
    }
    else
    {
        std::cout << getLogPrefix() << " Showing interface " << interface << "..." << std::endl;
        return g_ssh_deployer_cumulus.execute("nv show interface " + interface);
    }
}

bool CumulusHelper::showVLAN()
{
    std::cout << getLogPrefix() << " Showing VLAN configuration..." << std::endl;
    return g_ssh_deployer_cumulus.execute("nv show bridge domain br_default vlan");
}

bool CumulusHelper::showBridgeVLAN()
{
    std::cout << getLogPrefix() << " Showing bridge VLAN table..." << std::endl;
    return g_ssh_deployer_cumulus.execute("bridge vlan show");
}

// ==================== Raw Commands ====================

bool CumulusHelper::nv(const std::string &nv_command, std::string *output)
{
    std::cout << getLogPrefix() << " nv " << nv_command << std::endl;
    return g_ssh_deployer_cumulus.execute("nv " + nv_command, output);
}

bool CumulusHelper::execute(const std::string &command, std::string *output, bool use_sudo)
{
    return g_ssh_deployer_cumulus.execute(command, output, use_sudo);
}
