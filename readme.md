This document is very much a work in progress.  This instructions are not necessarily correct.

SETTING UP THE ENVIRONMENT
==========================

1) Download and install the Arduino environment for your operating system.
   The following URL links to a page that tells you how to do this.

   http://arduino.cc/en/Guide/HomePage

   For Debian, you can just do an "apt-get install arduino".

2) Install the latest version of the Ethernet library, containing asynchronous
   sockets (Asocket).
   a) Download the zip archive "Ethernet.zip" from
      http://code.google.com/p/kegger/
   b) Unzip the downloaded archive file, called "Ethernet.zip", so the directory
      "Ethernet" overwrites the corresponding directory in the directory where Arduino
      keeps its libraries.

3) Install the "Streaming" library, which is not distributed as standard with the 
   Arduino software.  The streaming library is not used by Agentuino itself, but is
   used by the demonstration application.
   a) Download the library archive (a zip file) from
      http://arduiniana.org/libraries/streaming/
   b) Unzip the downloaded zip archive into a directory called "Streaming", within
      the directory where Arduino keeps its libraries (/usr/share/arduino/libraries
       on Linux).

4) Install the MemoryFree.h library.
   a) The source code is in the Arduino Playground:
      http://www.arduino.cc/playground/Code/AvailableMemory
   b) Make a directory "MemoryFree" in the directory where Arduino keeps its libraries.
   c) In this new directory, create a file "MemoryFree.h", containing the code from
      the section labelled "MemoryFree.h:" on the playground web page.
   d) Also create a file "MemoryFree.cpp", in the same directory, containing the code
      from the section labelled "MemoryFree.cpp:" on the playground web page.
   e) Create a subdirectory called "examples", inside the "MemoryFree" directory.
   f) Create a subdirectory called "FreeMemory", inside the "examples" directory.
   g) In this new "FreeMemory" directory, create a file "FreeMemory.pde", containing
      the code from the section labelled "Example sketch:" on the playground web page.


INSTALLING AGENTINO LIBRARY FROM SVN
====================================

5) Check out the agentuino svn repository

      svn checkout http://agentuino.googlecode.com/svn/trunk/ Agentuino

6) Install the library, by linking your Agentuino development directory to be a sub
   directory of the directory where Arduino keeps its libraries
   (/usr/share/arduino/libraries on Linux).

7) You can now develop, in your home directory, as a regular user.  The Arduino
   environment doesn't seem to like writing sketches to the library example
   directories, claiming they are read-only, when they are not.  Hence you will have to
   use a different text editor to edit the code.  Compile and uploas it from with the
   arduino environment, as for any other example sketch.

Alternatively, you can checkout the Agentuino directory directly into the libraries directory, but you are then working outside your home directory.


INSTALLING AND RUNNING THE SAMPLE AGENTINO SKETCH
=================================================

Run the sample Agentuino sketch by selecting the menu entry
File>Examples>Agentuino>Agent, from within the arduino environment, and uploading it


TESTING THE SAMPLE SNMP AGENT
=============================

8) Install the snmpget tool from net-snmp (in Debian "apt-get install snmp")

9) Customise the IP in the Agentuino example sketch.

10) Upload the Agentuino example sketch.

11) Run an SNMP query, for example:
      snmpget -v 1 -c public 192.168.1.100 1.3.6.1.2.1.1.4.0 
    The community string, IP address and OID must match the values in the source code
    of the Agentuino example sketch.
