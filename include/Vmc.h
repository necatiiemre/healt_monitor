#ifndef VMC_H
#define VMC_H

#include <string>
#include <vector>
#include "DeviceManager.h"
#include "Utils.h"
#include "SerialPort.h"
#include "Server.h"
#include "SystemCommand.h"

class Vmc
{
private:
    /* data */
public:
    Vmc();
    ~Vmc();

    bool configureSequence();
};

extern Vmc g_vmc;

#endif // VMC_H
