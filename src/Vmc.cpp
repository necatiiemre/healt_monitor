#include "Vmc.h"
#include <iostream>
#include <unistd.h>
#include <iomanip>
// 28V 3.0A

Vmc g_vmc;

Vmc::Vmc()
{
}

Vmc::~Vmc()
{
}

bool Vmc::configureSequence()
{

    g_Server.onWithWait(3);
    // Create and connect both PSUs for VMC

    // Create PSU G30 (30V, 56A)
    if (!g_DeviceManager.create(PSUG30))
    {
        std::cout << "VMC: Failed to create PSU G30!" << std::endl;
        return false;
    }

    // Connect to PSU G30
    if (!g_DeviceManager.connect(PSUG30))
    {
        std::cout << "VMC: Failed to connect to PSU G30!" << std::endl;
        return false;
    }

    if (!g_DeviceManager.setCurrent(PSUG30, 1.5))
    {
        std::cout << "VMC: Failed to set current on PSU G30!" << std::endl;
        return false;
    }

    if (!g_DeviceManager.setVoltage(PSUG30, 20.0))
    {
        std::cout << "VMC: Failed to set voltage on PSU G30!" << std::endl;
        return false;
    }

    if (!g_DeviceManager.enableOutput(PSUG30, true))
    {
        std::cout << "VMC: Failed to enable output on PSU G30!" << std::endl;
        return false;
    }

    serial::sendSerialCommand("/dev/ttyACM0", "VMC_ID 1");

    for (int i = 0; i < 1000; i++)
    {
        if (i % 20 == 0)
        {
            double current = g_DeviceManager.measureCurrent(PSUG30);
            double voltage = g_DeviceManager.measureVoltage(PSUG30);
            double power = g_DeviceManager.measurePower(PSUG30);
            double get_current = g_DeviceManager.getCurrent(PSUG30);
            double get_voltage = g_DeviceManager.getVoltage(PSUG30);

            {
                utils::FloatFormatGuard guard(std::cout, 2, true);
                std::cout << "Current: " << current << " " << "Voltage: " << voltage << " " << "Power: " << power << " " << "Get Current: " << get_current << " " << "Get Voltage:" << get_voltage << std::endl;
            }
        }
    }

    if (!g_DeviceManager.enableOutput(PSUG30, false))
    {
        std::cout << "VMC: Failed to disable output on PSU G30!" << std::endl;
        return false;
    }

    if (!g_DeviceManager.disconnect(PSUG30))
    {
        std::cout << "VMC: Failed to disconnect PSU G30!" << std::endl;
        return false;
    }

    g_Server.offWithWait(300);

    std::cout << "VMC: PSU configured successfully." << std::endl;
    return true;
}
