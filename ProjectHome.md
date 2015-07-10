# Introduction #
Agentuino is a lightweight Simple Network Management Protocol (SNMP) Agent library for the Arduino platforms supporting Version 1.

The current code base is synchronous (blocking) for the time being and is currently in Alpha stages.  This means that the system won't execute any other code until the request is processed and sends a response to the calling SNMP Manager.

The software supports the following;
  * PDU Types
    1. GET-Request
    1. SET-Request
    1. Response
  * Syntax Types
    1. Null
    1. Boolean
    1. Bits (WIP)
    1. Octet-String
    1. Object-Identifier (WIP)
    1. Integer and Integer32
    1. Counter and Counter64
    1. Gauge
    1. Time-Ticks
    1. IP-Address
    1. Opaque
    1. Network-Service-Access-Point (NSAP) Address

Asynchronous (non-blocking) and Trap modifications are intended in the near future.  Keep checking for updates and feedback is welcome.

`*`WIP - Work In Progress.

# Limitations #
Agentuino's limitation is dependent on the amount of SRAM available.

  * Maximum Community Names (Get/Set) Length: 20 bytes
  * Maximum Object-Identifier Length: 64 bytes
  * Maximum Value Length: 64 bytes
  * Maximum Packet Length: 153 bytes

The library definitions can be easily modified should additional SRAM be available.

# Getting Started #
For developers who are not familiar with SNMP it is recommended to read the SNMP Primer from wiki (http://code.google.com/p/agentuino/wiki/SNMPPrimer).

## Arduino Hardware ##
Developers require the following hardware;
  * Arduino Processor Board
    1. SRAM 2k or higher
    1. Flash Memory 30k or higher
  * Arduino Ethernet Shield
    * WizNet chip or chip that supports UDP and the standard Ethernet library

## Arduino Software ##
Developers require the following software dependencies;
  * Arduino IDE 0019 or higher ( http://arduino.cc/en/Main/Software );
  * Ethernet Library ( default with 0019 or higher );
  * SPI Library ( default with 0019 or higher );
  * Streaming Library ( http://arduiniana.org/libraries/streaming/ );
  * Flash Library ( http://arduiniana.org/libraries/flash/ );
  * MemoryFree Library ( http://www.arduino.cc/playground/Code/AvailableMemory ); and of course;
  * Agentuino Library.

If the Arduino IDE is running be sure to close and restart it.  Once the IDE is restarted go to File->Examples->Agentuino->Agent to load the example Agent sketch.  Edit the sketch file to reflect your network settings, compile, and upload the sketch to your Arduino platform.

## SNMP Manager ##
Developers require the following software, or equivalent, to test against Agentuino;
  * Linux Environment
    * Net-Snmp (http://net-snmp.sourceforge.net/); or
    * tkmib MIB Browser (Ubuntu or Debian)
  * Windows Environment
    * Net-Snmp (http://net-snmp.sourceforge.net/); or
    * iReasoning MIB Browser (http://ireasoning.com/mibbrowser.shtml)

### Net-Snmp Get-Request ###
Open a command prompt or console and type the following (edit the host address, e.g. Agentuino IP Address, as needed);
```
snmpget -v 1 -r 1 -c public 192.168.2.64 sysUpTime.0
```
The command should respond with the following output;
```
DISMAN-EVENT-MIB::sysUpTimeInstance = Timeticks: (1471800) 4:05:18.00
```

### Net-Snmp Set-Request ###
Open a command prompt or console and type the following (edit the host address, e.g. Agentuino IP Address, as needed);
```
snmpset -v 1 -r 1 -c public 192.168.2.64 sysName.0 s NewName
```
The command should respond with the following output;
```
SNMPv2-MIB::sysName.0 = STRING: NewName
```

Let's test the updated sysName with a Get-Request.  Open a command prompt or console and type the following (edit the host address, e.g. Agentuino IP Address, as needed);
```
snmpget -v 1 -r 1 -c public 192.168.2.64 sysName.0
```
The command should respond with the following output;
```
SNMPv2-MIB::sysName.0 = STRING: NewName
```

# Agentuino Library #
Additional information on the Agentuino Library can be found here (http://code.google.com/p/agentuino/wiki/AgentuinoLibrary).

# Reporting Bugs #
Should a bug be found please create an issue ticket (http://code.google.com/p/agentuino/issues/list) to ensure that the problem is tracked and resolved.

# Submitting Enhancements #
If you would like to contribute please contact listed owners or post your comments in the Arduino forum (http://www.arduino.cc/cgi-bin/yabb2/YaBB.pl?num=1282881635).