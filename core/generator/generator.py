"""
BIFROST SDK — C++ External Boilerplate Generator
Parses JSON dumps and generates a complete Visual Studio C++ project.
"""

import os
import json
import uuid

class CppBoilerplateGenerator:
    def __init__(self, project_name: str, output_dir: str, sdk_data: dict, logger_callback=None):
        self.project_name = project_name.replace(" ", "_")
        self.output_dir = os.path.join(output_dir, self.project_name)
        self.sdk_data = sdk_data
        self.log = logger_callback or print
        
        # Unique VS GUIDs
        self.project_guid = str(uuid.uuid4()).upper()

    def generate(self) -> bool:
        self.log(f"[*] Initializing Boilerplate Generator for '{self.project_name}'...")
        try:
            os.makedirs(self.output_dir, exist_ok=True)
            self._generate_sln()
            self._generate_vcxproj()
            self._generate_main_cpp()
            self._generate_memory_h()
            self._generate_driver_h()
            self._generate_offsets_h()
            self._generate_ida_script()
            self.log(f"[+] Successfully generated Visual Studio project at: {self.output_dir}")
            return True
        except Exception as e:
            self.log(f"[-] Generation failed: {e}")
            return False

    def _generate_sln(self):
        sln_content = f"""
Microsoft Visual Studio Solution File, Format Version 12.00
# Visual Studio Version 17
VisualStudioVersion = 17.0.31903.59
MinimumVisualStudioVersion = 10.0.40219.1
Project("{{8BC9CEB8-8B4A-11D0-8D11-00A0C91BC942}}") = "{self.project_name}", "{self.project_name}.vcxproj", "{{{self.project_guid}}}"
EndProject
Global
	GlobalSection(SolutionConfigurationPlatforms) = preSolution
		Debug|x64 = Debug|x64
		Release|x64 = Release|x64
	EndGlobalSection
	GlobalSection(ProjectConfigurationPlatforms) = postSolution
		{{{self.project_guid}}}.Debug|x64.ActiveCfg = Debug|x64
		{{{self.project_guid}}}.Debug|x64.Build.0 = Debug|x64
		{{{self.project_guid}}}.Release|x64.ActiveCfg = Release|x64
		{{{self.project_guid}}}.Release|x64.Build.0 = Release|x64
	EndGlobalSection
EndGlobal
"""
        with open(os.path.join(self.output_dir, f"{self.project_name}.sln"), "w") as f:
            f.write(sln_content.strip())
        self.log("[+] Generated Solution File (.sln)")

    def _generate_vcxproj(self):
        proj_content = f"""<?xml version="1.0" encoding="utf-8"?>
<Project DefaultTargets="Build" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <ItemGroup Label="ProjectConfigurations">
    <ProjectConfiguration Include="Debug|x64">
      <Configuration>Debug</Configuration>
      <Platform>x64</Platform>
    </ProjectConfiguration>
    <ProjectConfiguration Include="Release|x64">
      <Configuration>Release</Configuration>
      <Platform>x64</Platform>
    </ProjectConfiguration>
  </ItemGroup>
  <PropertyGroup Label="Globals">
    <VCProjectVersion>17.0</VCProjectVersion>
    <ProjectGuid>{{{self.project_guid}}}</ProjectGuid>
    <Keyword>Win32Proj</Keyword>
    <RootNamespace>{self.project_name}</RootNamespace>
    <WindowsTargetPlatformVersion>10.0</WindowsTargetPlatformVersion>
  </PropertyGroup>
  <Import Project="$(VCTargetsPath)\\Microsoft.Cpp.Default.props" />
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Debug|x64'" Label="Configuration">
    <ConfigurationType>Application</ConfigurationType>
    <UseDebugLibraries>true</UseDebugLibraries>
    <PlatformToolset>v143</PlatformToolset>
    <CharacterSet>Unicode</CharacterSet>
  </PropertyGroup>
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Release|x64'" Label="Configuration">
    <ConfigurationType>Application</ConfigurationType>
    <UseDebugLibraries>false</UseDebugLibraries>
    <PlatformToolset>v143</PlatformToolset>
    <WholeProgramOptimization>true</WholeProgramOptimization>
    <CharacterSet>Unicode</CharacterSet>
  </PropertyGroup>
  <Import Project="$(VCTargetsPath)\\Microsoft.Cpp.props" />
  <ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Debug|x64'">
    <ClCompile>
      <WarningLevel>Level3</WarningLevel>
      <PreprocessorDefinitions>_DEBUG;_CONSOLE;%(PreprocessorDefinitions)</PreprocessorDefinitions>
      <LanguageStandard>stdcpp20</LanguageStandard>
    </ClCompile>
    <Link>
      <SubSystem>Console</SubSystem>
      <GenerateDebugInformation>true</GenerateDebugInformation>
    </Link>
  </ItemDefinitionGroup>
  <ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Release|x64'">
    <ClCompile>
      <WarningLevel>Level3</WarningLevel>
      <FunctionLevelLinking>true</FunctionLevelLinking>
      <IntrinsicFunctions>true</IntrinsicFunctions>
      <PreprocessorDefinitions>NDEBUG;_CONSOLE;%(PreprocessorDefinitions)</PreprocessorDefinitions>
      <LanguageStandard>stdcpp20</LanguageStandard>
    </ClCompile>
    <Link>
      <SubSystem>Console</SubSystem>
      <EnableCOMDATFolding>true</EnableCOMDATFolding>
      <OptimizeReferences>true</OptimizeReferences>
      <GenerateDebugInformation>true</GenerateDebugInformation>
    </Link>
  </ItemDefinitionGroup>
  <ItemGroup>
    <ClCompile Include="main.cpp" />
  </ItemGroup>
  <ItemGroup>
    <ClInclude Include="memory.h" />
    <ClInclude Include="driver.h" />
    <ClInclude Include="offsets.h" />
  </ItemGroup>
  <Import Project="$(VCTargetsPath)\\Microsoft.Cpp.targets" />
</Project>"""
        with open(os.path.join(self.output_dir, f"{self.project_name}.vcxproj"), "w") as f:
            f.write(proj_content.strip())
        self.log("[+] Generated VCXProj File (.vcxproj)")

    def _generate_main_cpp(self):
        cpp_content = f"""#include <iostream>
#include <thread>
#include "memory.h"
#include "driver.h"
#include "offsets.h"

int main() {{
    std::cout << "[*] Starting {self.project_name} - Generated by BIFROST SDK" << std::endl;
    
    // Initialize Memory Reader
    Memory mem("target_game.exe"); // UPDATE THIS TO YOUR TARGET GAME!
    
    if (!mem.GetProcessId()) {{
        std::cout << "[-] Failed to attach to process. Make sure it is running." << std::endl;
        std::cin.get();
        return 1;
    }}
    
    std::cout << "[+] Attached to process PID: " << mem.GetProcessId() << std::endl;
    uintptr_t baseAddr = mem.GetModuleBase("target_game.exe");
    std::cout << "[+] Base Address: 0x" << std::hex << baseAddr << std::dec << std::endl;
    
    Driver drv(mem.GetProcessId());
    if (drv.IsLoaded()) {{
        std::cout << "[+] Driver loaded! Using stealth kernel reads." << std::endl;
    }} else {{
        std::cout << "[!] Driver not found. Falling back to ReadProcessMemory." << std::endl;
    }}
    
    // Cheat Loop
    while (true) {{
        // Example usage:
        // uintptr_t localPlayer = drv.IsLoaded() ? drv.Read<uintptr_t>(baseAddr + Offsets::LocalPlayer) : mem.Read<uintptr_t>(baseAddr + Offsets::LocalPlayer);
        // int health = drv.IsLoaded() ? drv.Read<int>(localPlayer + Offsets::Health) : mem.Read<int>(localPlayer + Offsets::Health);
        
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }}

    return 0;
}}
"""
        with open(os.path.join(self.output_dir, "main.cpp"), "w") as f:
            f.write(cpp_content.strip())
        self.log("[+] Generated main.cpp (External Cheat Loop)")

    def _generate_memory_h(self):
        mem_content = """#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <string>

class Memory {
private:
    DWORD processId = 0;
    HANDLE hProcess = nullptr;

public:
    Memory(const std::string& processName) {
        PROCESSENTRY32 entry;
        entry.dwSize = sizeof(PROCESSENTRY32);
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

        if (Process32First(snapshot, &entry)) {
            do {
                if (processName.compare(entry.szExeFile) == 0) {
                    processId = entry.th32ProcessID;
                    hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processId);
                    break;
                }
            } while (Process32Next(snapshot, &entry));
        }
        CloseHandle(snapshot);
    }

    ~Memory() {
        if (hProcess) CloseHandle(hProcess);
    }

    DWORD GetProcessId() const { return processId; }

    uintptr_t GetModuleBase(const std::string& moduleName) {
        uintptr_t moduleBase = 0;
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
        if (snapshot != INVALID_HANDLE_VALUE) {
            MODULEENTRY32 moduleEntry;
            moduleEntry.dwSize = sizeof(MODULEENTRY32);
            if (Module32First(snapshot, &moduleEntry)) {
                do {
                    if (moduleName.compare(moduleEntry.szModule) == 0) {
                        moduleBase = (uintptr_t)moduleEntry.modBaseAddr;
                        break;
                    }
                } while (Module32Next(snapshot, &moduleEntry));
            }
            CloseHandle(snapshot);
        }
        return moduleBase;
    }

    template <typename T>
    T Read(uintptr_t address) {
        T value{};
        ReadProcessMemory(hProcess, (LPCVOID)address, &value, sizeof(T), nullptr);
        return value;
    }

    template <typename T>
    bool Write(uintptr_t address, const T& value) {
        SIZE_T bytesWritten;
        return WriteProcessMemory(hProcess, (LPVOID)address, &value, sizeof(T), &bytesWritten) && bytesWritten == sizeof(T);
    }
};
"""
        with open(os.path.join(self.output_dir, "memory.h"), "w") as f:
            f.write(mem_content.strip())
        self.log("[+] Generated memory.h (ReadProcessMemory Wrapper)")

    def _generate_driver_h(self):
        driver_content = """#pragma once
#include <Windows.h>
#include <iostream>

#define IOCTL_READ_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WRITE_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

struct READ_MEMORY_REQUEST {
    ULONG ProcessId;
    ULONGLONG Address;
    ULONGLONG Buffer;
    ULONGLONG Size;
};

struct WRITE_MEMORY_REQUEST {
    ULONG ProcessId;
    ULONGLONG Address;
    ULONGLONG Buffer;
    ULONGLONG Size;
};

class Driver {
private:
    HANDLE hDriver;
    ULONG processId;
    
public:
    Driver(ULONG pid) : processId(pid) {
        hDriver = CreateFileA("\\\\\\\\.\\\\BifrostDriver", GENERIC_READ | GENERIC_WRITE, 
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
            
        if (hDriver == INVALID_HANDLE_VALUE) {
            // Driver not loaded
        }
    }
    
    ~Driver() {
        if (hDriver != INVALID_HANDLE_VALUE) CloseHandle(hDriver);
    }
    
    bool IsLoaded() const { return hDriver != INVALID_HANDLE_VALUE; }
    
    template <typename T>
    T Read(uintptr_t address) {
        T value{};
        if (!IsLoaded()) return value;
        
        READ_MEMORY_REQUEST req = {0};
        req.ProcessId = processId;
        req.Address = address;
        req.Buffer = (ULONGLONG)&value;
        req.Size = sizeof(T);
        
        DWORD bytesReturned = 0;
        DeviceIoControl(hDriver, IOCTL_READ_MEMORY, &req, sizeof(req), &req, sizeof(req), &bytesReturned, nullptr);
        return value;
    }

    template <typename T>
    bool Write(uintptr_t address, const T& value) {
        if (!IsLoaded()) return false;
        
        WRITE_MEMORY_REQUEST req = {0};
        req.ProcessId = processId;
        req.Address = address;
        req.Buffer = (ULONGLONG)&value;
        req.Size = sizeof(T);
        
        DWORD bytesReturned = 0;
        return DeviceIoControl(hDriver, IOCTL_WRITE_MEMORY, &req, sizeof(req), &req, sizeof(req), &bytesReturned, nullptr);
    }
};
"""
        with open(os.path.join(self.output_dir, "driver.h"), "w") as f:
            f.write(driver_content.strip())
        self.log("[+] Generated driver.h (Kernel Driver Interface)")

    def _generate_offsets_h(self):
        classes = self.sdk_data.get("classes", [])
        
        lines = []
        lines.append("#pragma once")
        lines.append("// Auto-generated by BIFROST SDK")
        lines.append("#include <cstddef>\n")
        lines.append("namespace Offsets {")
        
        for cls in classes:
            class_name = cls.get("name", "UnknownClass").replace(" ", "_").replace("::", "_")
            lines.append(f"    namespace {class_name} {{")
            for field in cls.get("fields", []):
                fname = field.get("name", "UnknownField")
                offset = field.get("offset", 0)
                # Ignore fields with no offset to avoid clutter
                if offset > 0:
                    lines.append(f"        constexpr std::ptrdiff_t {fname} = 0x{offset:X};")
            lines.append("    }")
            
        lines.append("}")
        
        with open(os.path.join(self.output_dir, "offsets.h"), "w") as f:
            f.write("\n".join(lines))
        self.log("[+] Generated offsets.h (Mapped SDK Offsets)")

    def _generate_ida_script(self):
        classes = self.sdk_data.get("classes", [])
        
        lines = []
        lines.append('import idc')
        lines.append('import idaapi')
        lines.append('import idautils\n')
        lines.append('def main():')
        lines.append('    print("Applying BIFROST SDK offsets to IDA...")')
        lines.append('    image_base = idaapi.get_imagebase()')
        
        for cls in classes:
            class_name = cls.get("name", "UnknownClass").replace(" ", "_").replace("::", "_")
            for field in cls.get("fields", []):
                fname = field.get("name", "UnknownField")
                offset = field.get("offset", 0)
                if offset > 0:
                    lines.append(f'    idc.set_name(image_base + 0x{offset:X}, "{class_name}_{fname}", idc.SN_NOWARN)')
        
        lines.append('\n    print("Done!")')
        lines.append('\nif __name__ == "__main__":')
        lines.append('    main()')
        
        with open(os.path.join(self.output_dir, "ida_script.py"), "w") as f:
            f.write("\n".join(lines))
        self.log("[+] Generated ida_script.py (IDA Pro Automation)")

