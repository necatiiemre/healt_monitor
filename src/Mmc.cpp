#include "Mmc.h"
#include <iostream>
#include <unistd.h>
#include <iomanip>
// 28V 3.0A

Mmc g_mmc;

Mmc::Mmc()
{
}

Mmc::~Mmc()
{
}

bool Mmc::configureSequence()
{
    g_Server.onWithWait(3);
    // Create and connect both PSUs for MMC

    // Create PSU G300 (300V, 5.6A)
    if (!g_DeviceManager.create(PSUG300))
    {
        std::cout << "MMC: Failed to create PSU G300!" << std::endl;
        return false;
    }

    // Connect to PSU G300
    if (!g_DeviceManager.connect(PSUG300))
    {
        std::cout << "MMC: Failed to connect to PSU G300!" << std::endl;
        return false;
    }

    if (!g_DeviceManager.setCurrent(PSUG300, 1.5))
    {
        std::cout << "MMC: Failed to set current on PSU G300!" << std::endl;
        return false;
    }

    if (!g_DeviceManager.setVoltage(PSUG300, 20.0))
    {
        std::cout << "MMC: Failed to set voltage on PSU G300!" << std::endl;
        return false;
    }

    if (!g_DeviceManager.enableOutput(PSUG300, true))
    {
        std::cout << "MMC: Failed to enable output on PSU G300!" << std::endl;
        return false;
    }

    serial::sendSerialCommand("/dev/ttyACM0", "VMC_ID 1");

    for (int i = 0; i < 1000; i++)
    {
        if (i % 20 == 0)
        {
            double current = g_DeviceManager.measureCurrent(PSUG300);
            double voltage = g_DeviceManager.measureVoltage(PSUG300);
            double power = g_DeviceManager.measurePower(PSUG300);
            double get_current = g_DeviceManager.getCurrent(PSUG300);
            double get_voltage = g_DeviceManager.getVoltage(PSUG300);

            {
                utils::FloatFormatGuard guard(std::cout, 2, true);
                std::cout << "Current: " << current << " " << "Voltage: " << voltage << " " << "Power: " << power << " " << "Get Current: " << get_current << " " << "Get Voltage:" << get_voltage << std::endl;
            }
        }
    }

    if (!g_DeviceManager.enableOutput(PSUG300, false))
    {
        std::cout << "MMC: Failed to disable output on PSU G300!" << std::endl;
        return false;
    }

    if (!g_DeviceManager.disconnect(PSUG300))
    {
        std::cout << "MMC: Failed to disconnect PSU G300!" << std::endl;
        return false;
    }

    g_Server.offWithWait(300);

    std::cout << "MMC: PSU configured successfully." << std::endl;
    return true;
}
