# Introduction #

# Definitions #

## SNMP\_DEFAULT\_PORT ##
Sets the agent's default port for incoming requests (161).

## SNMP\_MIN\_OID\_LEN ##
Sets the minimum object-identifier length (2).

## SNMP\_MAX\_OID\_LEN ##
Sets the maximum object-identifier length (64).

## SNMP\_MAX\_NAME\_LEN ##
Sets the maximum community get/set name length (20).

## SNMP\_MAX\_VALUE\_LEN ##
Sets the maximum PDU value length (64).

## SNMP\_MAX\_PACKET\_LEN ##
Sets the maximum object-identifier length (SNMP\_MAX\_VALUE\_LEN + SNMP\_MAX\_OID\_LEN + 25).

# Enumerators #

## ASN\_BER\_BASE\_TYPES ##
Enumerated PDU BER base types supported.

## SNMP\_PDU\_TYPES ##
Enumerated PDU types supported.

## SNMP\_TRAP\_TYPES ##
Enumerated Trap types supported.

## SNMP\_ERR\_CODES ##
Enumerated SNMP related error codes.

## SNMP\_API\_STAT\_CODES ##
Enumerated library Application Programmer Interface status codes.

## SNMP\_SYNTAXES ##
Enumerated PDU syntaxes supported.

# Structures #

## SNMP\_OID ##

### Properties ###

#### byte data`[`SNMP\_MAX\_OID\_LEN`]` ####
Object-Identifier's data byte array.

#### size\_t size ####
Size of the Object-Identifier's data byte array.

### Functions & Subroutines ###

#### void toString(char `*`buffer) ####
The toString subroutine converts the Object-Identifier contained in the data byte array , should it's size be greater than zero, and stores it into the supplied buffer argument.

See Arguments section for argument definitions.

##### Arguments #####

###### buffer ######
Buffer where the Object-Identifier is stored.

## SNMP\_VALUE ##

### Properties ###

#### byte data`[`SNMP\_MAX\_VALUE\_LEN`]` ####
SNMP value byte array.

#### size\_t size ####
SNMP value's size.

#### SNMP\_SYNTAXES syntax ####
SNMP value's syntax type.

See SNMP\_SYNTAXES enumerator for additional information.

#### byte i ####
Used internally for encoding/decoding functions and should not be used in implementation code.

### Functions & Subroutines ###

#### void clear(void) ####
The clear subroutine clear's the value byte array and sets the size to 0.

#### SNMP\_ERR\_CODES decode(char `*`value, size\_t max\_size) ####
##### Arguments #####
###### value ######
###### max\_size ######

##### Returns #####
See SNMP\_ERR\_CODES enumerator for additional information.

#### SNMP\_ERR\_CODES decode(int32\_t `*`value) ####
##### Arguments #####
###### value ######

##### Returns #####
See SNMP\_ERR\_CODES enumerator for additional information.

#### SNMP\_ERR\_CODES decode(uint32\_t `*`value) ####
##### Arguments #####
###### value ######

##### Returns #####
See SNMP\_ERR\_CODES enumerator for additional information.

#### SNMP\_ERR\_CODES encode(SNMP\_SYNTAXES syn, const char `*`value) ####
##### Arguments #####
###### syn ######
###### value ######

##### Returns #####
See SNMP\_ERR\_CODES enumerator for additional information.

#### SNMP\_ERR\_CODES encode(SNMP\_SYNTAXES syn, const int32\_t value) ####
##### Arguments #####
###### syn ######
###### value ######

##### Returns #####
See SNMP\_ERR\_CODES enumerator for additional information.

#### SNMP\_ERR\_CODES encode(SNMP\_SYNTAXES syn, const uint32\_t value) ####
##### Arguments #####
###### syn ######
###### value ######

##### Returns #####
See SNMP\_ERR\_CODES enumerator for additional information.

# Class Constructors #
None.

# Class Functions & Subroutines #

## SNMP\_API\_STAT\_CODES begin() ##
The begin function initializes the Agent and should be placed in the "setup()" function of the implementation sketch file.  This function sets the Agent to default values for the Get (public) and Set (private) Community Names, and 161 for the port to process incoming requests.

See Returns section for function return information.

### Returns ###
See SNMP\_API\_STAT\_CODES enumerator for additional information.

## SNMP\_API\_STAT\_CODES begin(char `*`getCommName, char `*`setCommName, uint16\_t port) ##
The begin function initializes the Agent based on supplied arguments and should be placed in the "setup()" subroutine of the implementation sketch file.

See Arguments section for argument definitions.

See Returns section for function return information.

### Arguments ###

#### getCommName ####
Get community name.

#### setCommName ####
Set community name.

#### port ####
Agent's port to accept incoming requests.

### Returns ###
See SNMP\_API\_STAT\_CODES enumerator for additional information.

## void listen(void) ##
The listen subroutine executes a delegate subroutine (pointer to a subroutine) when the Ethernet detects a byte in the receive buffer.  The listen subroutine should be placed in the "loop()" subroutine of the implementation sketch file.

See onPduReceive subroutine for additional information on delegate subroutine implementation.

## SNMP\_API\_STAT\_CODES requestPdu(SNMP\_PDU `*`pdu) ##

### Arguments ###

#### pdu ####

### Returns ###
See SNMP\_API\_STAT\_CODES enumerator for additional information.

## SNMP\_API\_STAT\_CODES responsePdu(SNMP\_PDU `*`pdu) ##

### Arguments ###

#### pdu ####

### Returns ###
See SNMP\_API\_STAT\_CODES enumerator for additional information.

## void onPduReceive(onPduReceiveCallback pduReceived) ##

### Arguments ###

#### pduReceived ####

## void freePdu(SNMP\_PDU `*`pdu) ##

### Arguments ###

#### pdu ####