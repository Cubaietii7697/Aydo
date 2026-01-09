#pragma once

#include <string>
#include <unordered_map>
#include "YaraScoringSystem.hpp"

namespace YaraRuleConstants {

// Default rule score configurations
// Maps rule name prefixes to their scores and threat levels (every yara rule has a prefix - its category)
static const std::unordered_map<std::string, std::pair<int, ThreatLevel>> DEFAULT_RULE_SCORES = {
    // Critical - Confirmed malware signatures (immediate kill)
    {"malware_", {100, ThreatLevel::Critical}},
    {"trojan_", {100, ThreatLevel::Critical}},
    {"ransomware_", {100, ThreatLevel::Critical}},
    {"backdoor_", {100, ThreatLevel::Critical}},
    {"rootkit_", {100, ThreatLevel::Critical}},
    {"worm_", {100, ThreatLevel::Critical}},
    {"virus_", {100, ThreatLevel::Critical}},
    {"apt_", {100, ThreatLevel::Critical}},

    // High - Known exploit/attack patterns
    {"exploit_", {80, ThreatLevel::High}},
    {"shellcode_", {80, ThreatLevel::High}},
    {"meterpreter_", {90, ThreatLevel::High}},
    {"cobalt_", {90, ThreatLevel::High}},
    {"mimikatz_", {90, ThreatLevel::High}},

    // Medium - Suspicious patterns that need context
    {"suspicious_", {40, ThreatLevel::Medium}},
    {"packer_", {30, ThreatLevel::Medium}},
    {"obfuscated_", {35, ThreatLevel::Medium}},
    {"encrypted_", {25, ThreatLevel::Medium}},
    {"antivm_", {45, ThreatLevel::Medium}},
    {"antidebug_", {40, ThreatLevel::Medium}},

    // Low - Indicators that may be legitimate
    {"indicator_", {15, ThreatLevel::Low}},
    {"heuristic_", {20, ThreatLevel::Low}},

    // Info - Generic PE/Binary characteristics (0-1 points)
    // These are present in virtually all Windows binaries
    {"ispe", {0, ThreatLevel::Info}},             // IsPE64, IsPE32, IsPE, etc.
    {"is_pe", {0, ThreatLevel::Info}},            // Alternative naming
    {"pe_", {0, ThreatLevel::Info}},              // PE-related generic rules
    {"isdebug", {0, ThreatLevel::Info}},          // HasDebugData, IsDebug, etc.
    {"iswindows", {0, ThreatLevel::Info}},        // IsWindowsGUI, IsConsole, etc.
    {"isconsole", {0, ThreatLevel::Info}},        // Console applications
    {"isgui", {0, ThreatLevel::Info}},            // GUI applications
    {"hasrich", {0, ThreatLevel::Info}},          // HasRichSignature (Microsoft compiler)
    {"richsignature", {0, ThreatLevel::Info}},    // Rich signature variants
    {"isbeyond", {0, ThreatLevel::Info}},         // IsBeyondImageSize
    {"hasdebug", {0, ThreatLevel::Info}},         // HasDebugData variants
    {"microsoft_visual", {0, ThreatLevel::Info}}, // Microsoft Visual C++ indicators
    {"visual_cpp", {0, ThreatLevel::Info}},       // Visual C++ patterns
    {"msvc", {0, ThreatLevel::Info}},             // MSVC compiler artifacts

    // Info - Cryptographic/Math patterns (1-2 points)
    // Common in legitimate software
    {"crc32", {1, ThreatLevel::Info}},            // CRC32 checksums
    {"crc_", {1, ThreatLevel::Info}},             // CRC variants
    {"big_numbers", {1, ThreatLevel::Info}},      // Big number constants
    {"bignumbers", {1, ThreatLevel::Info}},       // Alternative naming
    {"crypto_constants", {1, ThreatLevel::Info}}, // Crypto constants
    {"math_constants", {1, ThreatLevel::Info}},   // Math constants
    {"aes_", {2, ThreatLevel::Info}},             // AES encryption (legitimate use)
    {"rsa_", {2, ThreatLevel::Info}},             // RSA encryption (legitimate use)
    {"sha", {1, ThreatLevel::Info}},              // SHA hashing
    {"md5", {1, ThreatLevel::Info}},              // MD5 hashing

    // Info - Exception handling and debugging (0-2 points)
    // Standard Windows programming patterns
    {"seh_", {1, ThreatLevel::Info}},              // Structured Exception Handling
    {"seh__", {1, ThreatLevel::Info}},             // SEH variants
    {"exception", {1, ThreatLevel::Info}},         // Exception handling
    {"debugger", {2, ThreatLevel::Info}},          // Debugger detection (can be legitimate)
    {"debuggercheck", {2, ThreatLevel::Info}},     // Debugger check variants
    {"debuggerexception", {2, ThreatLevel::Info}}, // Debugger exceptions
    {"queryinfo", {1, ThreatLevel::Info}},         // Query information APIs
    {"consolectrl", {1, ThreatLevel::Info}},       // Console control

    // Info - Synchronization primitives (0-1 points)
    // Normal Windows programming
    {"win_mutex", {0, ThreatLevel::Info}},        // Mutex usage
    {"mutex", {0, ThreatLevel::Info}},            // Mutex variants
    {"semaphore", {0, ThreatLevel::Info}},        // Semaphores
    {"event_", {0, ThreatLevel::Info}},           // Event objects
    {"critical_section", {0, ThreatLevel::Info}}, // Critical sections

    // Info - Standard Windows APIs (1-3 points)
    {"capability_", {1, ThreatLevel::Info}},
    {"capa_", {1, ThreatLevel::Info}},
    {"can_", {1, ThreatLevel::Info}},
    {"has_", {0, ThreatLevel::Info}},
    {"uses_", {1, ThreatLevel::Info}},
    {"contains_", {0, ThreatLevel::Info}},
    {"create_service", {3, ThreatLevel::Info}}, // Service creation (higher score)
    {"network_", {2, ThreatLevel::Info}},       // Network operations
    {"socket_", {2, ThreatLevel::Info}},        // Socket operations
    {"http_", {2, ThreatLevel::Info}},          // HTTP operations
    {"registry_", {2, ThreatLevel::Info}},      // Registry access
    {"file_", {1, ThreatLevel::Info}},          // File operations
    {"process_", {2, ThreatLevel::Info}},       // Process operations
    {"thread_", {1, ThreatLevel::Info}},        // Thread operations
    {"memory_", {1, ThreatLevel::Info}},        // Memory operations
    {"dll_", {1, ThreatLevel::Info}},           // DLL operations
    {"import_", {0, ThreatLevel::Info}},        // Import table entries
    {"export_", {0, ThreatLevel::Info}},        // Export table entries

    // Info - Compiler and linker artifacts (0 points)
    {"linker_", {0, ThreatLevel::Info}},    // Linker information
    {"compiler_", {0, ThreatLevel::Info}},  // Compiler information
    {"build_", {0, ThreatLevel::Info}},     // Build information
    {"version_", {0, ThreatLevel::Info}},   // Version information
    {"resource_", {0, ThreatLevel::Info}},  // Resource section
    {"section_", {0, ThreatLevel::Info}},   // PE sections
    {"timestamp_", {0, ThreatLevel::Info}}, // Timestamps
};

} // namespace YaraRuleConstants
