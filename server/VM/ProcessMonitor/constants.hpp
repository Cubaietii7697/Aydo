#pragma once

#include <string>

namespace Constants {
const int WAIT_TIME = 500;
const int DEFAULT_TIME_S = 60;
const int MS_TO_S = 1000;
const int MAX_WAIT_TIME_MS = 5000;
const int MIN_WAIT_TIME_MS = 50;
constexpr int GUID_SIZE = 64;
constexpr int JSON_INDENT_WIDTH = 2;
constexpr int IPPROTO_TCP = 6;
constexpr int IPPROTO_UDP = 17;
constexpr int HOST_MAX_NAME = 256;

struct Mapping {
  std::string dst;
  std::vector<std::string> src;
  bool lower = false;
};
inline const std::vector<Mapping> RULES = {
    {"Computer", {"Computer", "host"}},
    {"ProcessName", {"ProcessName", "ImageFileName", "ImageName", "name"}},
    {"Image", {"Image", "ImagePath", "ProcessPath", "path"}},
    {"RemoteAddresses", {"RemoteAddresses", "RemoteAddress", "DestAddress", "DestinationIp", "dst"}},
    {"RemotePorts", {"RemotePorts", "RemotePort", "DestPort", "DestinationPort", "dport"}},
    {"IpAddress", {"IpAddress", "RemoteIP", "DestinationIp", "dst"}},
    {"ObjectName", {"ObjectName", "FileName", "FilePath", "path"}},
    {"Operation", {"Operation", "IrpOp", "op"}},
    {"Status", {"Status", "NtStatus", "ReturnValue", "status"}},
    {"domain_in_lowercase_xxx", {"domain_in_lowercase_xxx", "TargetDomainName", "TargetServerName", "DomainName"}, true},
    {"param1_lower", {"param1_lower", "Param1", "param1"}, true}};
} // namespace Constants
