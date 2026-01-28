#include "UnitManager.h"
#include <algorithm>
#include <iostream>

UnitManager g_UnitManager;

UnitManager::UnitManager()
{
    // Constructor
}

UnitManager::~UnitManager()
{
    // Destructor - stop all devices
    for (const auto &deviceId : m_activeDevices)
    {
        stopDevice(deviceId);
    }
}

bool UnitManager::startDevice(const std::string &deviceId)
{
    // Return false if device is already running
    if (isDeviceRunning(deviceId))
    {
        std::cout << "Device already running: " << deviceId << std::endl;
        return false;
    }

    // TODO: Actual device start operation will be implemented here

    m_activeDevices.push_back(deviceId);
    std::cout << "Device started: " << deviceId << std::endl;
    return true;
}

bool UnitManager::stopDevice(const std::string &deviceId)
{
    // Return false if device is not running
    if (!isDeviceRunning(deviceId))
    {
        std::cout << "Device not running: " << deviceId << std::endl;
        return false;
    }

    // TODO: Actual device stop operation will be implemented here

    auto it = std::find(m_activeDevices.begin(), m_activeDevices.end(), deviceId);
    if (it != m_activeDevices.end())
    {
        m_activeDevices.erase(it);
    }

    std::cout << "Device stopped: " << deviceId << std::endl;
    return true;
}

bool UnitManager::isDeviceRunning(const std::string &deviceId) const
{
    return std::find(m_activeDevices.begin(), m_activeDevices.end(), deviceId) != m_activeDevices.end();
}

Unit UnitManager::unitSelector()
{
    int choice = 0;
    Unit unit;
    while (true)
    {
        std::cout << "Select Unit?\n";
        std::cout << "1) CMC\n";
        std::cout << "2) MMC\n";
        std::cout << "3) VMC\n";
        std::cout << "4) DTN\n";
        std::cout << "5) HSN\n";
        std::cout << "Enter choice: ";
        std::cin >> choice;

        // User entered letter, symbol, etc.
        if (std::cin.fail())
        {
            std::cin.clear();
            std::cin.ignore(1000, '\n');
            std::cout << "Invalid input!\n\n";
            continue;
        }

        // User entered valid number but wrong range
        if (choice < 1 || choice > 5)
        {
            std::cout << "Invalid option! Please select between 1 - 5.\n\n";
            continue;
        }

        // Valid input
        break;
    }

    unit = (Unit)choice;
    std::cout << "You selected: " << enumToString(unit) << std::endl;
    return unit;
}

bool UnitManager::configureDeviceForUnit(Unit unit)
{
    switch (unit)
    {
    case CMC:
    {
        g_cmc.configureSequence();
        break;
    }
    case MMC:
    {
        g_mmc.configureSequence();
        break;
    }
    case VMC:
    {
        g_vmc.configureSequence();
        break;
    }
    case DTN:
    {
        g_dtn.configureSequence();
        break;
    }
    case HSN:
    {
        g_hsn.configureSequence();

        break;
    }
    default:
        std::cout << "Unknown unit type!" << std::endl;
        return false;
    }

    return true;
}

std::vector<std::string> UnitManager::getDeviceList() const
{
    return m_activeDevices;
}

std::string UnitManager::enumToString(Unit unit)
{
    switch (unit)
    {
    case Unit::CMC:
        return "CMC";
    case Unit::MMC:
        return "MMC";
    case Unit::VMC:
        return "VMC";
    case Unit::DTN:
        return "DTN";
    case Unit::HSN:
        return "HSN";
    }
    return "UNKNOWN";
}
