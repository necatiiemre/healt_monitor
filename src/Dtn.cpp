#include "Dtn.h"
#include "SSHDeployer.h"
#include "CumulusHelper.h"
#include "SerialTimeForwarder.h"
#include <iostream>
#include <unistd.h>
#include <iomanip>
#include <filesystem>
#include <limits>
#include <csignal>
#include <atomic>
#include "Utils.h"

// Global flag for Ctrl+C handling in DPDK monitoring
static std::atomic<bool> g_dpdk_monitoring_running{true};

static void dpdk_monitor_signal_handler(int sig) {
    (void)sig;
    g_dpdk_monitoring_running = false;
}

// PSU Configuration: 28V 3.0A

Dtn g_dtn;

Dtn::Dtn()
{
}

Dtn::~Dtn()
{
}

bool Dtn::latencyTestSequence()
{
    bool valid_test = false;

    if (askQuestion("Do you want to run HW Timestamp Latency Test (Default measured latency : 14us)"))
    {
        while (!valid_test)
        {
            bool answer = askQuestion("You need to install the LoopBack connectors for this test. Check before starting the test. Should I start the test?");
            if (answer)
            {
                valid_test = true;
                runLatencyTest("-n 1 -vvv");
            }
            else
            {
                if (askQuestion("Do you want to skip the test?"))
                {
                    valid_test = true;
                    return 1;
                }
            }
        }
    }
    return 0;
}

bool Dtn::askQuestion(const std::string &question)
{
    char response;
    while (true)
    {
        std::cout << question << " [y/n]: ";
        std::cin >> response;

        if (std::cin.fail())
        {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::cout << "Invalid input! Please enter 'y' or 'n'.\n";
            continue;
        }

        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

        if (response == 'y' || response == 'Y')
        {
            return true;
        }
        else if (response == 'n' || response == 'N')
        {
            return false;
        }
        else
        {
            std::cout << "Invalid input! Please enter 'y' or 'n'.\n";
        }
    }
}

bool Dtn::ensureLogDirectories()
{
    try
    {
        std::filesystem::create_directories(LogPaths::CMC());
        std::filesystem::create_directories(LogPaths::VMC());
        std::filesystem::create_directories(LogPaths::MMC());
        std::filesystem::create_directories(LogPaths::DTN());
        std::filesystem::create_directories(LogPaths::HSN());
        std::cout << "DTN: Log directories created/verified at " << LogPaths::baseDir() << std::endl;
        return true;
    }
    catch (const std::exception &e)
    {
        std::cerr << "DTN: Failed to create log directories: " << e.what() << std::endl;
        return false;
    }
}

bool Dtn::runLatencyTest(const std::string &run_args, int timeout_seconds)
{
    std::cout << "======================================" << std::endl;
    std::cout << "DTN: HW Timestamp Latency Test" << std::endl;
    std::cout << "======================================" << std::endl;

    // Ensure log directories exist
    if (!ensureLogDirectories())
    {
        std::cerr << "DTN: Failed to create log directories!" << std::endl;
        return false;
    }

    // Build local log path
    std::string local_log_path = LogPaths::DTN() + "/latency_test.log";

    std::cout << "DTN: Run arguments: " << (run_args.empty() ? "(default)" : run_args) << std::endl;
    std::cout << "DTN: Timeout: " << timeout_seconds << " seconds" << std::endl;
    std::cout << "DTN: Log output: " << local_log_path << std::endl;

    // Run the test using SSHDeployer
    bool result = g_ssh_deployer_server.deployBuildRunAndFetchLog(
        "latency_test", // Source folder (auto-resolved from source root)
        "latency_test", // Executable name
        run_args,           // Arguments (e.g., "-n 10 -v")
        local_log_path,     // Local log path
        timeout_seconds     // Timeout
    );

    if (result)
    {
        std::cout << "======================================" << std::endl;
        std::cout << "DTN: Latency Test COMPLETED" << std::endl;
        std::cout << "DTN: Log saved to: " << local_log_path << std::endl;
        std::cout << "======================================" << std::endl;
    }
    else
    {
        std::cerr << "DTN: Latency Test FAILED!" << std::endl;
    }

    return result;
}

bool Dtn::runDpdkInteractive(const std::string& eal_args, const std::string& make_args)
{
    std::cout << "======================================" << std::endl;
    std::cout << "DTN: DPDK Interactive Deployment" << std::endl;
    std::cout << "======================================" << std::endl;

    // Step 1: Test connection
    if (!g_ssh_deployer_server.testConnection())
    {
        std::cerr << "DTN: Cannot connect to server!" << std::endl;
        return false;
    }

    // Step 2: Deploy and build DPDK (without running)
    std::cout << "DTN: Deploying and building DPDK..." << std::endl;
    if (!g_ssh_deployer_server.deployAndBuild(
            "dpdk",             // source folder
            "",                 // app name (auto-detect)
            false,              // DON'T run after build (we'll run interactively)
            false,              // no sudo for build
            BuildSystem::AUTO,  // auto-detect (will find Makefile)
            "",                 // no run args (not running yet)
            make_args,          // make args (e.g., "NUM_TX_CORES=4")
            false               // not background
            ))
    {
        std::cerr << "DTN: DPDK build failed!" << std::endl;
        return false;
    }

    // Step 3: Run DPDK interactively
    // User can answer y/n prompts for latency tests
    // After tests complete, DPDK will fork to background automatically
    std::cout << std::endl;
    std::cout << "======================================" << std::endl;
    std::cout << "DTN: Starting DPDK Interactive Mode" << std::endl;
    std::cout << "DTN: You can answer latency test prompts (y/n)" << std::endl;
    std::cout << "DTN: After tests, DPDK will continue in background" << std::endl;
    std::cout << "======================================" << std::endl;
    std::cout << std::endl;

    std::string remote_dir = g_ssh_deployer_server.getRemoteDirectory();

    // IMPORTANT: Don't pipe password to sudo, it breaks stdin for interactive input!
    // Instead: First authenticate sudo (caches credentials), then run DPDK
    // sudo -v = validate/refresh sudo timestamp without running a command
    // sudo -S = read password from stdin (only for the -v part)
    // After -v succeeds, subsequent sudo commands don't need password (within timeout)
    // --daemon flag: tells DPDK to fork to background after latency tests
    std::string dpdk_command = "cd " + remote_dir + "/dpdk && "
                               "echo 'q' | sudo -S -v && "  // Authenticate sudo first
                               "sudo ./dpdk_app --daemon " + eal_args;  // --daemon for background mode

    bool result = g_ssh_deployer_server.executeInteractive(dpdk_command, false);

    if (result)
    {
        std::cout << std::endl;
        std::cout << "======================================" << std::endl;
        std::cout << "DTN: DPDK started successfully!" << std::endl;
        std::cout << "DTN: Running in background on server" << std::endl;
        std::cout << "DTN: Log file: /tmp/dpdk_app.log" << std::endl;
        std::cout << "======================================" << std::endl;
    }
    else
    {
        std::cerr << "DTN: DPDK interactive execution failed!" << std::endl;
    }

    return result;
}

bool Dtn::configureSequence()
{
    // Create and connect PSU for DTN

    // g_Server.onWithWait(3);

    // // Create PSU G30 (30V, 56A)
    // if (!g_DeviceManager.create(PSUG30))
    // {
    //     std::cout << "DTN: Failed to create PSU G30!" << std::endl;
    //     return false;
    // }

    // // Connect to PSU G30
    // if (!g_DeviceManager.connect(PSUG30))
    // {
    //     std::cout << "DTN: Failed to connect to PSU G30!" << std::endl;
    //     return false;
    // }

    // if (!g_DeviceManager.setCurrent(PSUG30, 3.0))
    // {
    //     std::cout << "DTN: Failed to set current on PSU G30!" << std::endl;
    //     return false;
    // }

    // if (!g_DeviceManager.setVoltage(PSUG30, 28.0))
    // {
    //     std::cout << "DTN: Failed to set voltage on PSU G30!" << std::endl;
    //     return false;
    // }

    // if (!g_DeviceManager.enableOutput(PSUG30, true))
    // {
    //     std::cout << "DTN: Failed to enable output on PSU G30!" << std::endl;
    //     return false;
    // }

    //Send serial command
    g_systemCommand.execute("echo \"VMC_ID 2\" > /dev/ttyACM0");

    //sleep(1);
    utils::waitForCtrlC();
    if (g_cumulus.deployNetworkInterfaces("/home/user/DTN/today/interfaces"))
    {
        std::cout << "Network configuration deployed successfully!" << std::endl;
    }
    else
    {
        std::cerr << "Failed to deploy network configuration!" << std::endl;
        return 1;
    }

    sleep(1);

    // Configure Cumulus switch VLANs
    if (!g_cumulus.configureSequence())
    {
        std::cout << "DTN: Cumulus configuration failed!" << std::endl;
        return false;
    }

    sleep(1);

    // // SSH Deployment to Server
    // if (!g_ssh_deployer_server.testConnection())
    // {
    //     std::cout << "DTN: Cannot connect to server!" << std::endl;
    //     return false;
    // }

    // // List directory on server
    // g_ssh_deployer_server.execute("ls -la /home/user");

    //Deploy, build and run with sudo (required for raw sockets)
    //Just pass folder name - path is auto-resolved from source root
    if (!g_ssh_deployer_server.deployAndBuild("remote_config_sender", "", true, true))
    {
        std::cout << "DTN: Deployment unsuccessful!" << std::endl;
        return false;
    }
    utils::waitForCtrlC();
    // utils::waitForCtrlC();
    // Start SerialTimeForwarder after remote_config_sender is running
    // Reads time from MicroChip SyncServer (USB0), forwards to USB1, verifies on USB2
    serial::SerialTimeForwarder timeForwarder("/dev/ttyUSB0", "/dev/ttyUSB1");
    if (timeForwarder.start())
    {
        std::cout << "DTN: SerialTimeForwarder started successfully." << std::endl;
    }
    else
    {
        std::cerr << "DTN: Failed to start SerialTimeForwarder: "
                  << timeForwarder.getLastError() << std::endl;
    }

    //DPDK - Interactive mode with embedded latency test
    //1. Deploy and build DPDK on server
    //2. Run interactively (user answers y/n for latency tests)
    //3. After latency tests, DPDK forks to background automatically
    if (!runDpdkInteractive("-l 0-255 -n 16"))
    {
        std::cout << "DTN: DPDK deployment unsuccessful!" << std::endl;
        return false;
    }

    // DPDK is now running in background on server
    // Main software can continue with other tasks
    std::cout << "DTN: DPDK is running in background, continuing..." << std::endl;

    // Monitor DPDK stats every 10 seconds until Ctrl+C
    std::cout << std::endl;
    std::cout << "======================================" << std::endl;
    std::cout << "DTN: Monitoring DPDK (every 10 seconds)" << std::endl;
    std::cout << "DTN: Press Ctrl+C to stop" << std::endl;
    std::cout << "======================================" << std::endl;

    // Setup signal handler for Ctrl+C
    g_dpdk_monitoring_running = true;
    struct sigaction sa;
    sa.sa_handler = dpdk_monitor_signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, nullptr);

    while (g_dpdk_monitoring_running)
    {
        // Wait 10 seconds (check flag each second)
        for (int i = 0; i < 10 && g_dpdk_monitoring_running; i++)
        {
            sleep(1);
        }

        if (!g_dpdk_monitoring_running) break;

        // Fetch latest complete stats table from DPDK log
        // Get content from the last "==========" separator to end of file
        // This ensures we get a complete table, not a partial one
        std::string output;
        g_ssh_deployer_server.execute(
            "grep -n '==========' /tmp/dpdk_app.log | tail -1 | cut -d: -f1 | "
            "xargs -I{} tail -n +{} /tmp/dpdk_app.log",
            &output, false);

        if (!output.empty())
        {
            // Clear screen and show latest stats
            std::cout << "\033[2J\033[H";  // Clear screen, move cursor to top
            std::cout << "=== DPDK Live Stats (Press Ctrl+C to stop) ===" << std::endl;
            std::cout << output << std::endl;
        }
        else
        {
            std::cout << "(No log output yet - DPDK might still be starting)" << std::endl;
        }
    }

    // std::cout << "\nDTN: Monitoring stopped (Ctrl+C received)." << std::endl;

    // Stop SerialTimeForwarder and show stats
    if (timeForwarder.isRunning())
    {
        std::cout << "DTN: SerialTimeForwarder stats:" << std::endl;
        std::cout << "  Packets sent: " << timeForwarder.getPacketsSent() << std::endl;
        std::cout << "  Last timestamp: " << timeForwarder.getLastTimestamp() << std::endl;
        std::cout << "  Last time string: " << timeForwarder.getLastTimeString() << std::endl;
        timeForwarder.stop();
        std::cout << "DTN: SerialTimeForwarder stopped." << std::endl;
    }

    // Stop DPDK on server
    std::cout << "DTN: Stopping DPDK on server..." << std::endl;
    if (g_ssh_deployer_server.isApplicationRunning("dpdk_app"))
    {
        g_ssh_deployer_server.stopApplication("dpdk_app", true);
        std::cout << "DTN: DPDK stopped." << std::endl;
    }
    else
    {
        std::cout << "DTN: DPDK was not running." << std::endl;
    }

    // Fetch DPDK log from server to local PC
    std::cout << "DTN: Fetching DPDK log from server..." << std::endl;
    ensureLogDirectories();
    std::string local_dpdk_log = LogPaths::DTN() + "/dpdk_app.log";
    if (g_ssh_deployer_server.fetchFile("/tmp/dpdk_app.log", local_dpdk_log))
    {
        std::cout << "DTN: DPDK log saved to: " << local_dpdk_log << std::endl;
    }
    else
    {
        std::cerr << "DTN: Failed to fetch DPDK log (file may not exist)" << std::endl;
    }
    //  // Monitor PSU measurements
    //  for (int i = 0; i < 1000; i++)
    //  {
    //      if (i % 20 == 0)
    //      {
    //          double current = g_DeviceManager.measureCurrent(PSUG30);
    //          double voltage = g_DeviceManager.measureVoltage(PSUG30);
    //          double power = g_DeviceManager.measurePower(PSUG30);
    //          double get_current = g_DeviceManager.getCurrent(PSUG30);
    //          double get_voltage = g_DeviceManager.getVoltage(PSUG30);

    //         {
    //             utils::FloatFormatGuard guard(std::cout, 2, true);
    //             std::cout << "Current: " << current << " " << "Voltage: " << voltage << " " << "Power: " << power << " " << "Get Current: " << get_current << " " << "Get Voltage:" << get_voltage << std::endl;
    //         }
    //     }
    // }

    // if (!g_DeviceManager.enableOutput(PSUG30, false))
    // {
    //     std::cout << "DTN: Failed to disable output on PSU G30!" << std::endl;
    //     return false;
    // }

    // if (!g_DeviceManager.disconnect(PSUG30))
    // {
    //     std::cout << "DTN: Failed to disconnect PSU G30!" << std::endl;
    //     return false;
    // }

    // g_Server.offWithWait(300);

    std::cout << "DTN: PSU configured successfully." << std::endl;
    return true;
}
