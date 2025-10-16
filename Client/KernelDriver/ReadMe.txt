========================================================================
    AydoKernelDriver Project Overview
========================================================================

This file contains a summary of what you will find in each of the files 
that make up your project.

AydoKernelDriver.vcxproj
    The main Visual Studio project file. 
    Defines platforms, configurations, build settings, and driver type.

AydoKernelDriver.vcxproj.filters
    Defines how files are grouped in the Visual Studio Solution Explorer.

-----------------------------------------------------------------------
Header Files (include & shared definitions)
-----------------------------------------------------------------------

Driver.h
    Common driver definitions. Shared declarations for DriverEntry, 
    DriverUnload, and general driver-level callbacks.

Device.h
    Interfaces and declarations related to WDFDEVICE initialization 
    and device objects.

Public.h
    Header file intended to be shared with user-mode applications 
    (IOCTL codes, device name, symbolic links, etc).

Queue.h
    Contains definitions for I/O queues (request dispatching). 
    Currently only the header remains; WDFQUEUE logic moved elsewhere.

ioctl.hpp
    C++ header for IOCTL request handling and dispatch table.

request_handler.hpp
    Defines the RequestHandler interface and implementations for 
    handling specific IOCTL requests.

request_types.hpp
    Enumerations and structures describing request types used 
    throughout the driver.

logger.hpp
    Logging helper macros (AYDO_INFO, AYDO_ERROR, etc).
    Abstracts WPP or other kernel-safe logging mechanisms.

utils.hpp
    Utility functions and declarations used across the driver.

-----------------------------------------------------------------------
Source Files
-----------------------------------------------------------------------

driver.c
    DriverEntry, DriverUnload, and EvtDeviceAdd implementation. 
    This is the entry point of the driver.

ioctl.cpp
    Implements IOCTL handling: translates user-mode requests and 
    dispatches them to the appropriate request handler.

logger.cpp
    Implementation of logging utilities defined in logger.hpp.

request_handler.cpp
    Implements the RequestHandler logic for specific IOCTL codes.

utils.cpp
    Implementation of helper functions declared in utils.hpp 
    (device/queue initialization, kernel exports resolution, etc).

-----------------------------------------------------------------------
Other
-----------------------------------------------------------------------

AydoKernelDriver.inf
    INF file used to install the driver.

ReadMe.txt
    This file. Project structure overview.

-----------------------------------------------------------------------

Learn more about Kernel Mode Driver Framework here:
http://msdn.microsoft.com/en-us/library/ff544296(v=VS.85).aspx

========================================================================
