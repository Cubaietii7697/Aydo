#include <cstdlib>
#include <iostream>
#include <random>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>
#include <windows.h>

constexpr std::string_view BANNER = R"(
                                                                                         
                                                            dddddddd                 
               AAA                                          d::::::d                 
              A:::A                                         d::::::d                 
             A:::::A                                        d::::::d                 
            A:::::::A                                       d:::::d                  
           A:::::::::A    yyyyyyy           yyyyyyy ddddddddd:::::d    ooooooooooo   
          A:::::A:::::A    y:::::y         y:::::ydd::::::::::::::d  oo:::::::::::oo 
         A:::::A A:::::A    y:::::y       y:::::yd::::::::::::::::d o:::::::::::::::o
        A:::::A   A:::::A    y:::::y     y:::::yd:::::::ddddd:::::d o:::::ooooo:::::o
       A:::::A     A:::::A    y:::::y   y:::::y d::::::d    d:::::d o::::o     o::::o
      A:::::AAAAAAAAA:::::A    y:::::y y:::::y  d:::::d     d:::::d o::::o     o::::o
     A:::::::::::::::::::::A    y:::::y:::::y   d:::::d     d:::::d o::::o     o::::o
    A:::::AAAAAAAAAAAAA:::::A    y:::::::::y    d:::::d     d:::::d o::::o     o::::o
   A:::::A             A:::::A    y:::::::y     d::::::ddddd::::::ddo:::::ooooo:::::o
  A:::::A               A:::::A    y:::::y       d:::::::::::::::::do:::::::::::::::o
 A:::::A                 A:::::A  y:::::y         d:::::::::ddd::::d oo:::::::::::oo 
AAAAAAA                   AAAAAAAy:::::y           ddddddddd   ddddd   ooooooooooo   
                                y:::::y                                              
                               y:::::y                                               
                              y:::::y                                                
                             y:::::y                                                 
                            yyyyyyy                                                  
                                                                                     
                                                                                     
)";

constexpr std::string_view VM_RUN_PATH = R"("C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe")";
constexpr std::string_view ANALYSIS_VM_PATH = R"("D:\veeeertoooaaalll\SANDBOX1\SANDBOX1.vmx")";
constexpr std::string_view SANDBOXES_DIRECTORY_PATH = R"(D:\veeeertoooaaalll\copy.me.here.plz)";
constexpr unsigned int ID_LENGTH = 10;

static void printBanner(bool isClosing = false) {
    std::string bannerStr(BANNER);
    std::vector<std::string> lines;
    std::stringstream ss(bannerStr);
    std::string line;

    while (std::getline(ss, line)) {
        lines.push_back(line);
    }

    if (isClosing) {
        for (size_t i = lines.size() - 1; i < lines.size(); i--) {
            system("cls");

            for (size_t j = 0; j <= i; j++) {
                std::cout << lines[j] << std::endl;
            }

            Sleep(50);
        }
        system("cls");
    } else {
        for (size_t i = 0; i < lines.size(); i++) {
            system("cls");

            for (size_t j = 0; j <= i; j++) {
                std::cout << lines[j] << std::endl;
            }

            Sleep(50);
        }
    }
}

static void executeAndWait(const std::string &command) {
    STARTUPINFOA si = {sizeof(STARTUPINFOA)};
    PROCESS_INFORMATION pi;

    std::string cmdCopy = command;

    if (CreateProcessA(
            nullptr,
            &cmdCopy[0],
            nullptr,
            nullptr,
            FALSE,
            0,
            nullptr,
            nullptr,
            &si,
            &pi)) {
        WaitForSingleObject(pi.hProcess, INFINITE);

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        std::cerr << "Failed to execute command: " << command << std::endl;
        std::cerr << "Error: " << GetLastError() << std::endl;
    }
}

static std::string generateId(const std::string &prefix, const unsigned int length) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 9);

    std::string id;
    for (int i = 0; i < length; i++) {
        id += std::to_string(dis(gen));
    }

    return prefix + id;
}

int main() {
    // Important
    printBanner();

    std::string analysisVmPath = std::string(ANALYSIS_VM_PATH);
    std::string sandboxesDirectoryPath = std::string(SANDBOXES_DIRECTORY_PATH);
    std::string vmRunPath = std::string(VM_RUN_PATH);

    std::string id = generateId("sandbox_", ID_LENGTH);

    std::cout << "Generated ID: " << id << std::endl;

    std::string sandboxPath = sandboxesDirectoryPath + "\\" + id + "\\" + id + ".vmx";

    std::string vmRunCommand = vmRunPath + " clone " + analysisVmPath + " " + sandboxPath + " linked -cloneName=" + id;
    executeAndWait(vmRunCommand);

    std::string vmRunCommand2 = vmRunPath + " start " + sandboxPath;
    executeAndWait(vmRunCommand2);

    // Important
    printBanner(true);

    return EXIT_SUCCESS;
}