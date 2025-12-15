#pragma once

#include <unordered_map>
#include <string>
#include "YaraScoringSystem.hpp"

namespace YaraRuleConstants {

// Default rule score configurations
// Maps rule name prefixes to their scores and threat levels
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

    // Info - Capabilities (not malicious by themselves)
    {"capability_", {5, ThreatLevel::Info}},
    {"capa_", {5, ThreatLevel::Info}},
    {"can_", {5, ThreatLevel::Info}},
    {"has_", {3, ThreatLevel::Info}},
    {"uses_", {3, ThreatLevel::Info}},
    {"create_service", {5, ThreatLevel::Info}},
    {"network_", {8, ThreatLevel::Info}},
    {"registry_", {5, ThreatLevel::Info}},
    {"file_", {3, ThreatLevel::Info}},
    {"process_", {5, ThreatLevel::Info}},
};

} // namespace YaraRuleConstants
