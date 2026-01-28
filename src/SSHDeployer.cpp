#include "SSHDeployer.h"
#include "SystemCommand.h"
#include <iostream>
#include <filesystem>
#include <unistd.h>

// ==================== Global Instances ====================

// Server deployer (10.1.33.2)
SSHDeployer g_ssh_deployer_server("10.1.33.2", "user", "q", "/home/user/Desktop", "Server");

// Cumulus switch deployer
SSHDeployer g_ssh_deployer_cumulus("10.1.33.3", "cumulus", "%T86Ovk7RCH%h@CC", "", "Cumulus");

// Legacy alias for backward compatibility (points to server deployer)
SSHDeployer& g_Deployer = g_ssh_deployer_server;

// ==================== Constructors ====================

SSHDeployer::SSHDeployer()
    : m_host("")
    , m_username("")
    , m_password("")
    , m_remote_directory("")
    , m_name("SSHDeployer") {
}

SSHDeployer::SSHDeployer(const SSHConfig& config)
    : m_host(config.host)
    , m_username(config.username)
    , m_password(config.password)
    , m_remote_directory(config.remote_directory)
    , m_name(config.name.empty() ? "SSHDeployer" : config.name) {
}

SSHDeployer::SSHDeployer(const std::string& host,
                         const std::string& username,
                         const std::string& password,
                         const std::string& remote_directory,
                         const std::string& name)
    : m_host(host)
    , m_username(username)
    , m_password(password)
    , m_remote_directory(remote_directory)
    , m_name(name.empty() ? "SSHDeployer" : name) {
}

// ==================== Configuration ====================

void SSHDeployer::configure(const SSHConfig& config) {
    m_host = config.host;
    m_username = config.username;
    m_password = config.password;
    m_remote_directory = config.remote_directory;
    if (!config.name.empty()) {
        m_name = config.name;
    }
}

void SSHDeployer::setCredentials(const std::string& host,
                                  const std::string& username,
                                  const std::string& password) {
    m_host = host;
    m_username = username;
    m_password = password;
}

void SSHDeployer::setHost(const std::string& host) {
    m_host = host;
}

std::string SSHDeployer::getHost() const {
    return m_host;
}

void SSHDeployer::setUsername(const std::string& username) {
    m_username = username;
}

std::string SSHDeployer::getUsername() const {
    return m_username;
}

void SSHDeployer::setPassword(const std::string& password) {
    m_password = password;
}

void SSHDeployer::setRemoteDirectory(const std::string& path) {
    m_remote_directory = path;
}

std::string SSHDeployer::getRemoteDirectory() const {
    return m_remote_directory;
}

void SSHDeployer::setName(const std::string& name) {
    m_name = name;
}

std::string SSHDeployer::getName() const {
    return m_name;
}

bool SSHDeployer::isConfigured() const {
    return !m_host.empty() && !m_username.empty() && !m_password.empty();
}

std::string SSHDeployer::getExecutableDir() {
    // Linux: /proc/self/exe gives the full path to the executable
    std::filesystem::path exe_path = std::filesystem::canonical("/proc/self/exe");
    return exe_path.parent_path().string();
}

std::string SSHDeployer::getSourceRoot() {
    // Executable is at: build/bin/mainSoftware
    // Source root is: ../../ from executable
    std::filesystem::path exe_dir = getExecutableDir();
    // Go up from bin -> build -> source_root
    std::filesystem::path source_root = exe_dir / ".." / "..";
    return std::filesystem::canonical(source_root).string();
}

// ==================== Internal Helpers ====================

std::string SSHDeployer::getLogPrefix() const {
    return "[" + m_name + "]";
}

std::string SSHDeployer::buildSSHCommand(const std::string& remote_command) const {
    return "sshpass -p '" + m_password + "' "
           "ssh -o StrictHostKeyChecking=no "
           "-o ConnectTimeout=10 "
           + m_username + "@" + m_host + " "
           "\"" + remote_command + "\"";
}

std::string SSHDeployer::buildSCPCommand(const std::string& local_path,
                                          const std::string& remote_path) const {
    return "sshpass -p '" + m_password + "' "
           "scp -o StrictHostKeyChecking=no "
           "-o ConnectTimeout=10 "
           + local_path + " "
           + m_username + "@" + m_host + ":" + remote_path;
}

// ==================== Utilities ====================

bool SSHDeployer::testConnection() {
    std::cout << getLogPrefix() << " Testing connection to " << m_host << "..." << std::endl;

    std::string cmd = buildSSHCommand("echo 'Connection OK'");
    auto result = g_systemCommand.execute(cmd);

    if (result.success) {
        std::cout << getLogPrefix() << " Connection successful!" << std::endl;
        return true;
    } else {
        std::cerr << getLogPrefix() << " Connection failed: " << result.error << std::endl;
        return false;
    }
}

// ==================== File Operations ====================

bool SSHDeployer::copyFile(const std::string& local_path) {
    // Check if file exists
    if (!std::filesystem::exists(local_path)) {
        std::cerr << getLogPrefix() << " Local file not found: " << local_path << std::endl;
        return false;
    }

    std::string filename = std::filesystem::path(local_path).filename().string();
    std::string remote_path = m_remote_directory + "/" + filename;

    std::cout << getLogPrefix() << " Copying " << local_path << " -> " << remote_path << std::endl;

    // Create target directory first
    std::string mkdir_cmd = buildSSHCommand("mkdir -p " + m_remote_directory);
    g_systemCommand.execute(mkdir_cmd);

    // Copy file
    std::string scp_cmd = buildSCPCommand(local_path, remote_path);
    auto result = g_systemCommand.execute(scp_cmd);

    if (result.success) {
        std::cout << getLogPrefix() << " File copied successfully!" << std::endl;
        return true;
    } else {
        std::cerr << getLogPrefix() << " Copy failed: " << result.error << std::endl;
        return false;
    }
}

bool SSHDeployer::deploy(const std::string& local_path) {
    // Copy file
    if (!copyFile(local_path)) {
        return false;
    }

    // Make executable
    std::string filename = std::filesystem::path(local_path).filename().string();
    std::string remote_path = m_remote_directory + "/" + filename;

    std::cout << getLogPrefix() << " Making executable: " << remote_path << std::endl;

    std::string chmod_cmd = buildSSHCommand("chmod +x " + remote_path);
    auto result = g_systemCommand.execute(chmod_cmd);

    if (result.success) {
        std::cout << getLogPrefix() << " Deploy completed!" << std::endl;
        return true;
    } else {
        std::cerr << getLogPrefix() << " chmod failed: " << result.error << std::endl;
        return false;
    }
}

bool SSHDeployer::copyDirectory(const std::string& local_dir, const std::string& remote_name) {
    // Check if directory exists
    if (!std::filesystem::exists(local_dir) || !std::filesystem::is_directory(local_dir)) {
        std::cerr << getLogPrefix() << " Local directory not found: " << local_dir << std::endl;
        return false;
    }

    std::string dir_name = remote_name.empty()
        ? std::filesystem::path(local_dir).filename().string()
        : remote_name;
    std::string remote_path = m_remote_directory + "/" + dir_name;

    std::cout << getLogPrefix() << " Copying directory " << local_dir << " -> " << remote_path << std::endl;

    // Create target directory first
    std::string mkdir_cmd = buildSSHCommand("mkdir -p " + m_remote_directory);
    g_systemCommand.execute(mkdir_cmd);

    // Remove old directory (if exists)
    std::string rm_cmd = buildSSHCommand("rm -rf " + remote_path);
    g_systemCommand.execute(rm_cmd);

    // Copy directory (scp -r)
    std::string scp_cmd = "sshpass -p '" + m_password + "' "
                          "scp -r -o StrictHostKeyChecking=no "
                          "-o ConnectTimeout=30 "
                          + local_dir + " "
                          + m_username + "@" + m_host + ":" + m_remote_directory + "/";

    auto result = g_systemCommand.execute(scp_cmd);

    if (result.success) {
        std::cout << getLogPrefix() << " Directory copied successfully!" << std::endl;
        return true;
    } else {
        std::cerr << getLogPrefix() << " Directory copy failed: " << result.error << std::endl;
        return false;
    }
}

bool SSHDeployer::copyFileToPath(const std::string& local_path, const std::string& remote_path, bool use_sudo) {
    // Check if file exists
    if (!std::filesystem::exists(local_path)) {
        std::cerr << getLogPrefix() << " Local file not found: " << local_path << std::endl;
        return false;
    }

    std::string filename = std::filesystem::path(local_path).filename().string();

    std::cout << getLogPrefix() << " Copying " << local_path << " -> " << remote_path;
    if (use_sudo) std::cout << " (with sudo)";
    std::cout << std::endl;

    if (use_sudo) {
        // For protected directories: copy to /tmp first, then sudo mv
        std::string tmp_path = "/tmp/" + filename;

        // Step 1: Copy to /tmp
        std::string scp_cmd = buildSCPCommand(local_path, tmp_path);
        auto result = g_systemCommand.execute(scp_cmd);

        if (!result.success) {
            std::cerr << getLogPrefix() << " Copy to /tmp failed: " << result.error << std::endl;
            return false;
        }

        // Step 2: Get remote directory path
        std::string remote_dir = std::filesystem::path(remote_path).parent_path().string();

        // Step 3: Create remote directory if needed (with sudo)
        std::string mkdir_cmd = "echo '" + m_password + "' | sudo -S mkdir -p " + remote_dir;
        std::string ssh_mkdir = buildSSHCommand(mkdir_cmd);
        g_systemCommand.execute(ssh_mkdir);

        // Step 4: Move file with sudo
        std::string mv_cmd = "echo '" + m_password + "' | sudo -S mv " + tmp_path + " " + remote_path;
        std::string ssh_mv = buildSSHCommand(mv_cmd);
        result = g_systemCommand.execute(ssh_mv);

        if (result.success) {
            std::cout << getLogPrefix() << " File copied successfully (sudo)!" << std::endl;
            return true;
        } else {
            std::cerr << getLogPrefix() << " sudo mv failed: " << result.error << std::endl;
            return false;
        }
    } else {
        // Direct copy without sudo
        std::string remote_dir = std::filesystem::path(remote_path).parent_path().string();

        // Create target directory first
        std::string mkdir_cmd = buildSSHCommand("mkdir -p " + remote_dir);
        g_systemCommand.execute(mkdir_cmd);

        // Copy file
        std::string scp_cmd = buildSCPCommand(local_path, remote_path);
        auto result = g_systemCommand.execute(scp_cmd);

        if (result.success) {
            std::cout << getLogPrefix() << " File copied successfully!" << std::endl;
            return true;
        } else {
            std::cerr << getLogPrefix() << " Copy failed: " << result.error << std::endl;
            return false;
        }
    }
}

bool SSHDeployer::fetchFile(const std::string& remote_path, const std::string& local_path) {
    std::cout << getLogPrefix() << " Fetching " << remote_path << " -> " << local_path << std::endl;

    // Create local directory if needed
    std::filesystem::path local_dir = std::filesystem::path(local_path).parent_path();
    if (!local_dir.empty() && !std::filesystem::exists(local_dir)) {
        std::filesystem::create_directories(local_dir);
        std::cout << getLogPrefix() << " Created local directory: " << local_dir.string() << std::endl;
    }

    // Build SCP command to fetch from remote
    std::string scp_cmd = "sshpass -p '" + m_password + "' "
                          "scp -o StrictHostKeyChecking=no "
                          "-o ConnectTimeout=30 "
                          + m_username + "@" + m_host + ":" + remote_path + " "
                          + local_path;

    auto result = g_systemCommand.execute(scp_cmd);

    if (result.success) {
        std::cout << getLogPrefix() << " File fetched successfully!" << std::endl;
        return true;
    } else {
        std::cerr << getLogPrefix() << " File fetch failed: " << result.error << std::endl;
        return false;
    }
}

bool SSHDeployer::deployBuildRunAndFetchLog(const std::string& local_source_dir,
                                             const std::string& app_name,
                                             const std::string& run_args,
                                             const std::string& local_log_path,
                                             int timeout_seconds) {
    std::cout << getLogPrefix() << " ========================================" << std::endl;
    std::cout << getLogPrefix() << " Deploy, Build, Run & Fetch Log Pipeline" << std::endl;
    std::cout << getLogPrefix() << " ========================================" << std::endl;

    // Step 1: Resolve source path
    std::string source_path;
    if (std::filesystem::exists(local_source_dir)) {
        source_path = local_source_dir;
    } else {
        // Try from source root
        source_path = getSourceRoot() + "/" + local_source_dir;
        if (!std::filesystem::exists(source_path)) {
            std::cerr << getLogPrefix() << " Source directory not found: " << local_source_dir << std::endl;
            return false;
        }
    }

    std::string folder_name = std::filesystem::path(source_path).filename().string();
    std::string executable_name = app_name.empty() ? folder_name : app_name;
    std::string remote_project_path = m_remote_directory + "/" + folder_name;
    std::string remote_log_path = "/tmp/" + executable_name + ".log";

    std::cout << getLogPrefix() << " Source: " << source_path << std::endl;
    std::cout << getLogPrefix() << " Remote path: " << remote_project_path << std::endl;
    std::cout << getLogPrefix() << " Executable: " << executable_name << std::endl;
    std::cout << getLogPrefix() << " Remote log: " << remote_log_path << std::endl;
    std::cout << getLogPrefix() << " Local log: " << local_log_path << std::endl;

    // Step 2: Test connection
    std::cout << getLogPrefix() << " Step 1/5: Testing connection..." << std::endl;
    if (!testConnection()) {
        return false;
    }

    // Step 3: Copy source directory
    std::cout << getLogPrefix() << " Step 2/5: Copying source code..." << std::endl;
    if (!copyDirectory(source_path)) {
        std::cerr << getLogPrefix() << " Failed to copy source directory" << std::endl;
        return false;
    }

    // Step 4: Build
    std::cout << getLogPrefix() << " Step 3/5: Building on remote server..." << std::endl;
    if (!build(folder_name, executable_name, BuildSystem::AUTO)) {
        std::cerr << getLogPrefix() << " Build failed" << std::endl;
        return false;
    }

    // Step 5: Run with output redirected to log file (foreground, wait for completion)
    std::cout << getLogPrefix() << " Step 4/5: Running application..." << std::endl;

    // Find executable
    std::string check_cmd = "test -f " + remote_project_path + "/" + executable_name + " && echo 'found'";
    std::string ssh_check = buildSSHCommand(check_cmd);
    auto check_result = g_systemCommand.execute(ssh_check);

    std::string executable_path;
    if (check_result.output.find("found") != std::string::npos) {
        executable_path = remote_project_path + "/" + executable_name;
    } else {
        // Try with _app suffix
        check_cmd = "test -f " + remote_project_path + "/" + folder_name + "_app && echo 'found'";
        ssh_check = buildSSHCommand(check_cmd);
        check_result = g_systemCommand.execute(ssh_check);
        if (check_result.output.find("found") != std::string::npos) {
            executable_path = remote_project_path + "/" + folder_name + "_app";
            executable_name = folder_name + "_app";
            remote_log_path = "/tmp/" + executable_name + ".log";
        } else {
            std::cerr << getLogPrefix() << " Executable not found!" << std::endl;
            return false;
        }
    }

    // Build run command with sudo and output to log file
    std::string run_command = "cd " + remote_project_path + " && "
                              "echo '" + m_password + "' | sudo -S " + executable_path;
    if (!run_args.empty()) {
        run_command += " " + run_args;
    }
    run_command += " 2>&1 | tee " + remote_log_path;

    std::string ssh_run = buildSSHCommand(run_command);

    // Execute with timeout (convert seconds to milliseconds)
    int timeout_ms = timeout_seconds > 0 ? timeout_seconds * 1000 : 120000;
    auto run_result = g_systemCommand.execute(ssh_run, timeout_ms);

    // Show output
    if (!run_result.output.empty()) {
        std::cout << getLogPrefix() << " Application output:\n" << run_result.output << std::endl;
    }

    if (!run_result.success) {
        std::cerr << getLogPrefix() << " Application execution had issues: " << run_result.error << std::endl;
        // Continue to fetch log even if there were issues
    }

    // Step 6: Fetch log file
    std::cout << getLogPrefix() << " Step 5/5: Fetching log file..." << std::endl;
    if (!fetchFile(remote_log_path, local_log_path)) {
        std::cerr << getLogPrefix() << " Warning: Could not fetch log file" << std::endl;
        // Not a fatal error - application may have completed successfully
    }

    std::cout << getLogPrefix() << " ========================================" << std::endl;
    std::cout << getLogPrefix() << " Pipeline completed!" << std::endl;
    std::cout << getLogPrefix() << " Log saved to: " << local_log_path << std::endl;
    std::cout << getLogPrefix() << " ========================================" << std::endl;

    return true;
}

// ==================== Command Execution ====================

bool SSHDeployer::execute(const std::string& command, std::string* output, bool use_sudo) {
    std::string actual_command = command;
    if (use_sudo) {
        // echo password | sudo -S command
        actual_command = "echo '" + m_password + "' | sudo -S " + command;
    }

    std::cout << getLogPrefix() << " Executing: " << command;
    if (use_sudo) std::cout << " (with sudo)";
    std::cout << std::endl;

    std::string ssh_cmd = buildSSHCommand(actual_command);
    auto result = g_systemCommand.execute(ssh_cmd, 120000); // 2 minute timeout

    if (output) {
        *output = result.output;
    }

    if (result.success) {
        if (!result.output.empty()) {
            std::cout << getLogPrefix() << " Output:\n" << result.output << std::endl;
        }
        return true;
    } else {
        // Show both output and error for debugging
        if (!result.output.empty()) {
            std::cerr << getLogPrefix() << " Output:\n" << result.output << std::endl;
        }
        if (!result.error.empty()) {
            std::cerr << getLogPrefix() << " Error: " << result.error << std::endl;
        }
        return false;
    }
}

bool SSHDeployer::executeBackground(const std::string& command) {
    std::cout << getLogPrefix() << " Executing in background: " << command << std::endl;

    std::string bg_command = "nohup " + command + " > /dev/null 2>&1 &";
    std::string ssh_cmd = buildSSHCommand(bg_command);
    auto result = g_systemCommand.execute(ssh_cmd);

    if (result.success) {
        std::cout << getLogPrefix() << " Background process started!" << std::endl;
        return true;
    } else {
        std::cerr << getLogPrefix() << " Failed to start background process" << std::endl;
        return false;
    }
}

bool SSHDeployer::executeInteractive(const std::string& command, bool use_sudo) {
    std::string actual_command = command;
    if (use_sudo) {
        // Use sudo with password via stdin
        actual_command = "echo '" + m_password + "' | sudo -S " + command;
    }

    std::cout << getLogPrefix() << " Executing interactively: " << command;
    if (use_sudo) std::cout << " (with sudo)";
    std::cout << std::endl;

    // Build SSH command with -t flag for pseudo-terminal allocation
    // -t forces PTY allocation even when stdin is not a terminal
    // This allows interactive programs (getchar, fgets, etc.) to work
    std::string ssh_cmd = "sshpass -p '" + m_password + "' "
                          "ssh -t -o StrictHostKeyChecking=no "
                          "-o ConnectTimeout=10 "
                          + m_username + "@" + m_host + " "
                          "\"" + actual_command + "\"";

    // Use system() for true interactive execution
    // This connects stdin/stdout directly to the terminal
    int ret = system(ssh_cmd.c_str());

    if (ret == 0) {
        std::cout << getLogPrefix() << " Interactive command completed successfully" << std::endl;
        return true;
    } else {
        std::cerr << getLogPrefix() << " Interactive command failed with exit code: " << ret << std::endl;
        return false;
    }
}

bool SSHDeployer::run(const std::string& app_name, const std::string& args) {
    std::string full_path = m_remote_directory + "/" + app_name;
    std::string command = full_path;

    if (!args.empty()) {
        command += " " + args;
    }

    return execute(command);
}

// ==================== Build & Deploy ====================

BuildSystem SSHDeployer::detectBuildSystem(const std::string& project_path) {
    std::cout << getLogPrefix() << " Detecting build system for: " << project_path << std::endl;

    // Check for CMakeLists.txt
    std::string check_cmake = buildSSHCommand("test -f " + project_path + "/CMakeLists.txt && echo 'CMAKE'");
    auto result = g_systemCommand.execute(check_cmake);
    if (result.success && result.output.find("CMAKE") != std::string::npos) {
        std::cout << getLogPrefix() << " Detected: CMake project" << std::endl;
        return BuildSystem::CMAKE;
    }

    // Check for Makefile
    std::string check_makefile = buildSSHCommand("test -f " + project_path + "/Makefile && echo 'MAKEFILE'");
    result = g_systemCommand.execute(check_makefile);
    if (result.success && result.output.find("MAKEFILE") != std::string::npos) {
        std::cout << getLogPrefix() << " Detected: Makefile project" << std::endl;
        return BuildSystem::MAKEFILE;
    }

    std::cerr << getLogPrefix() << " No build system detected!" << std::endl;
    return BuildSystem::AUTO;
}

bool SSHDeployer::buildWithCMake(const std::string& project_path, const std::string& output_name) {
    std::string build_dir = project_path + "/build";

    // Create build directory
    std::cout << getLogPrefix() << " Creating build directory..." << std::endl;
    std::string mkdir_cmd = buildSSHCommand("mkdir -p " + build_dir);
    auto result = g_systemCommand.execute(mkdir_cmd);
    if (!result.success) {
        std::cerr << getLogPrefix() << " Failed to create build directory" << std::endl;
        return false;
    }

    // Run CMake
    std::cout << getLogPrefix() << " Running cmake..." << std::endl;
    std::string cmake_cmd = buildSSHCommand("cd " + build_dir + " && cmake ..");
    result = g_systemCommand.execute(cmake_cmd, 60000); // 60 second timeout
    if (!result.success) {
        std::cerr << getLogPrefix() << " CMake failed: " << result.error << std::endl;
        std::cerr << getLogPrefix() << " Output: " << result.output << std::endl;
        return false;
    }
    std::cout << getLogPrefix() << " CMake output:\n" << result.output << std::endl;

    // Run Make
    std::cout << getLogPrefix() << " Running make..." << std::endl;
    std::string make_cmd = buildSSHCommand("cd " + build_dir + " && make -j$(nproc)");
    result = g_systemCommand.execute(make_cmd, 120000); // 120 second timeout
    if (!result.success) {
        std::cerr << getLogPrefix() << " Make failed: " << result.error << std::endl;
        std::cerr << getLogPrefix() << " Output: " << result.output << std::endl;
        return false;
    }
    std::cout << getLogPrefix() << " Make output:\n" << result.output << std::endl;

    return true;
}

bool SSHDeployer::buildWithMakefile(const std::string& project_path,
                                     const std::string& output_name,
                                     const std::string& make_args) {
    // For Makefile projects (like DPDK), build directly in source directory
    std::cout << getLogPrefix() << " Building with Makefile..." << std::endl;

    // Clean first (optional but recommended)
    std::cout << getLogPrefix() << " Cleaning previous build..." << std::endl;
    std::string clean_cmd = buildSSHCommand("cd " + project_path + " && make clean 2>/dev/null || true");
    g_systemCommand.execute(clean_cmd, 30000);

    // Build with make
    std::string make_cmd = "cd " + project_path + " && make -j$(nproc)";
    if (!make_args.empty()) {
        make_cmd += " " + make_args;
    }

    std::cout << getLogPrefix() << " Running make..." << std::endl;
    std::string ssh_make = buildSSHCommand(make_cmd);
    auto result = g_systemCommand.execute(ssh_make, 180000); // 3 minute timeout for DPDK

    if (!result.success) {
        std::cerr << getLogPrefix() << " Make failed: " << result.error << std::endl;
        std::cerr << getLogPrefix() << " Output: " << result.output << std::endl;
        return false;
    }
    std::cout << getLogPrefix() << " Make output:\n" << result.output << std::endl;

    return true;
}

bool SSHDeployer::build(const std::string& project_dir,
                         const std::string& output_name,
                         BuildSystem build_system,
                         const std::string& make_args) {
    std::string full_project_path = m_remote_directory + "/" + project_dir;

    std::cout << getLogPrefix() << " Building project: " << full_project_path << std::endl;

    // Auto-detect build system if needed
    BuildSystem actual_build_system = build_system;
    if (build_system == BuildSystem::AUTO) {
        actual_build_system = detectBuildSystem(full_project_path);
        if (actual_build_system == BuildSystem::AUTO) {
            std::cerr << getLogPrefix() << " Could not detect build system!" << std::endl;
            return false;
        }
    }

    bool success = false;
    switch (actual_build_system) {
        case BuildSystem::CMAKE:
            success = buildWithCMake(full_project_path, output_name);
            break;
        case BuildSystem::MAKEFILE:
            success = buildWithMakefile(full_project_path, output_name, make_args);
            break;
        default:
            std::cerr << getLogPrefix() << " Unknown build system!" << std::endl;
            return false;
    }

    if (success) {
        std::cout << getLogPrefix() << " Build completed successfully!" << std::endl;
    }
    return success;
}

bool SSHDeployer::deployAndBuild(const std::string& local_source_dir,
                                  const std::string& app_name,
                                  bool run_after_build,
                                  bool use_sudo,
                                  BuildSystem build_system,
                                  const std::string& run_args,
                                  const std::string& make_args,
                                  bool run_in_background) {
    // Auto-resolve path: if not absolute, prepend source root
    std::string resolved_path = local_source_dir;
    if (!local_source_dir.empty() && local_source_dir[0] != '/') {
        resolved_path = getSourceRoot() + "/" + local_source_dir;
    }

    // Use folder name as app_name if not provided
    std::string actual_app_name = app_name;
    if (actual_app_name.empty()) {
        actual_app_name = std::filesystem::path(resolved_path).filename().string();
    }

    std::cout << "\n========================================" << std::endl;
    std::cout << getLogPrefix() << " Starting Deploy & Build Pipeline" << std::endl;
    std::cout << getLogPrefix() << " Target: " << m_username << "@" << m_host << std::endl;
    std::cout << getLogPrefix() << " Source: " << resolved_path << std::endl;
    if (use_sudo) std::cout << getLogPrefix() << " sudo mode enabled" << std::endl;
    std::cout << "========================================" << std::endl;

    // 1. Test connection
    std::cout << "\n[Step 1/4] Testing connection..." << std::endl;
    if (!testConnection()) {
        std::cerr << getLogPrefix() << " Pipeline failed: Connection error" << std::endl;
        return false;
    }

    // 2. Copy source code
    std::cout << "\n[Step 2/4] Copying source code..." << std::endl;
    if (!copyDirectory(resolved_path, actual_app_name)) {
        std::cerr << getLogPrefix() << " Pipeline failed: Copy error" << std::endl;
        return false;
    }

    // 3. Build - detect build system first for later use
    std::cout << "\n[Step 3/4] Building on remote server..." << std::endl;
    std::string full_project_path = m_remote_directory + "/" + actual_app_name;

    BuildSystem actual_build_system = build_system;
    if (build_system == BuildSystem::AUTO) {
        actual_build_system = detectBuildSystem(full_project_path);
    }

    if (!build(actual_app_name, actual_app_name, actual_build_system, make_args)) {
        std::cerr << getLogPrefix() << " Pipeline failed: Build error" << std::endl;
        return false;
    }

    // 4. Run (optional)
    if (run_after_build) {
        std::cout << "\n[Step 4/4] Running application";
        if (run_in_background) {
            std::cout << " (background mode)";
        }
        std::cout << "..." << std::endl;

        // Executable path depends on build system:
        // - CMake: project_dir/build/app_name
        // - Makefile: project_dir/app_name (DPDK uses dpdk_app)
        std::string executable_path;
        std::string executable_name = actual_app_name;

        if (actual_build_system == BuildSystem::MAKEFILE) {
            // For DPDK-style Makefile projects, check for dpdk_app or app_name
            std::string check_dpdk = buildSSHCommand("test -f " + full_project_path + "/dpdk_app && echo 'EXISTS'");
            auto result = g_systemCommand.execute(check_dpdk);
            if (result.success && result.output.find("EXISTS") != std::string::npos) {
                executable_name = "dpdk_app";
            }
            executable_path = full_project_path + "/" + executable_name;
        } else {
            // CMake projects have build directory
            executable_path = full_project_path + "/build/" + executable_name;
        }

        // Build run command with arguments
        std::string run_command = executable_path;
        if (!run_args.empty()) {
            run_command += " " + run_args;
        }

        if (run_in_background) {
            // For long-running applications like DPDK, run in background
            std::string bg_command = run_command;
            if (use_sudo) {
                bg_command = "echo '" + m_password + "' | sudo -S nohup " + run_command + " > /tmp/" + executable_name + ".log 2>&1 &";
            } else {
                bg_command = "nohup " + run_command + " > /tmp/" + executable_name + ".log 2>&1 &";
            }

            std::string ssh_cmd = buildSSHCommand(bg_command);
            auto result = g_systemCommand.execute(ssh_cmd);

            if (result.success) {
                std::cout << getLogPrefix() << " Application started in background!" << std::endl;
                std::cout << getLogPrefix() << " Log file: /tmp/" << executable_name << ".log" << std::endl;
            } else {
                std::cerr << getLogPrefix() << " Failed to start background process" << std::endl;
                return false;
            }
        } else {
            // Run in foreground (blocks until application exits)
            if (!execute(run_command, nullptr, use_sudo)) {
                std::cerr << getLogPrefix() << " Pipeline failed: Execution error" << std::endl;
                return false;
            }
        }
    } else {
        std::cout << "\n[Step 4/4] Skipping execution (run_after_build=false)" << std::endl;
    }

    std::cout << "\n========================================" << std::endl;
    std::cout << getLogPrefix() << " Pipeline completed successfully!" << std::endl;
    std::cout << "========================================\n" << std::endl;

    return true;
}

bool SSHDeployer::stopApplication(const std::string& app_name, bool use_sudo) {
    std::cout << getLogPrefix() << " Stopping application: " << app_name << std::endl;

    // Combine sudo auth + kill in single command to avoid credential expiry
    // Use shell script approach for reliability
    std::string kill_script;
    if (use_sudo) {
        // Single command: auth sudo, then kill with SIGTERM, wait, then SIGKILL if needed
        kill_script = "echo '" + m_password + "' | sudo -S -v 2>/dev/null && "
                      "sudo pkill -TERM -f " + app_name + " 2>/dev/null; "
                      "sleep 1; "
                      "sudo pkill -9 -f " + app_name + " 2>/dev/null; "
                      "echo KILL_DONE";
    } else {
        kill_script = "pkill -TERM -f " + app_name + " 2>/dev/null; "
                      "sleep 1; "
                      "pkill -9 -f " + app_name + " 2>/dev/null; "
                      "echo KILL_DONE";
    }

    std::string ssh_cmd = buildSSHCommand(kill_script);
    std::cout << getLogPrefix() << " Executing kill command..." << std::endl;
    auto result = g_systemCommand.execute(ssh_cmd);

    // Debug output
    std::cout << getLogPrefix() << " Kill result: " << (result.success ? "OK" : "FAIL")
              << " output: " << result.output << std::endl;

    // Wait a moment
    usleep(500000);  // 500ms

    // Verify process is stopped
    if (isApplicationRunning(app_name)) {
        std::cerr << getLogPrefix() << " WARNING: Process might still be running!" << std::endl;

        // Last resort: try killall
        std::string killall_cmd = use_sudo
            ? "echo '" + m_password + "' | sudo -S killall -9 " + app_name + " 2>/dev/null || true"
            : "killall -9 " + app_name + " 2>/dev/null || true";

        ssh_cmd = buildSSHCommand(killall_cmd);
        g_systemCommand.execute(ssh_cmd);
        usleep(500000);

        if (isApplicationRunning(app_name)) {
            std::cerr << getLogPrefix() << " FAILED to stop " << app_name << std::endl;
            return false;
        }
    }

    std::cout << getLogPrefix() << " Application stopped successfully" << std::endl;
    return true;
}

bool SSHDeployer::isApplicationRunning(const std::string& app_name) {
    // Use pgrep to check if process exists, also show PID for debugging
    std::string check_cmd = "pgrep -f '" + app_name + "' && echo 'PROC_FOUND' || echo 'PROC_NOT_FOUND'";
    std::string ssh_cmd = buildSSHCommand(check_cmd);

    auto result = g_systemCommand.execute(ssh_cmd);

    // Debug: show raw output
    std::cout << getLogPrefix() << " [DEBUG] pgrep output: '" << result.output << "'" << std::endl;

    bool running = result.output.find("PROC_FOUND") != std::string::npos
                   && result.output.find("PROC_NOT_FOUND") == std::string::npos;

    std::cout << getLogPrefix() << " Application '" << app_name << "' is "
              << (running ? "RUNNING" : "NOT RUNNING") << std::endl;

    return running;
}
