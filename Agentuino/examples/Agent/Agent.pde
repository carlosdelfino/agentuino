/**
* Agentuino SNMP Agent Library Prototyping...
*
* Copyright 2010 Eric C. Gionet <lavco_eg@hotmail.com>
*
*/
#include <Streaming.h>         // Include the Streaming library
#include <Ethernet.h>          // Include the Ethernet library
#include <MemoryFree.h>
#include <Agentuino.h> 
//
static byte mac[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED };
static byte ip[] = { 192, 168, 2, 64 };
static byte gateway[] = { 192, 168, 2, 1 };
static byte subnet[] = { 255, 255, 255, 0 };
//
//
// RFC1213-MIB OIDs
static char sysDescr[] PROGMEM      = "1.3.6.1.2.1.1.1.0";  // read-only  (DisplayString)
static char sysObjectID[] PROGMEM   = "1.3.6.1.2.1.1.2.0";  // read-only  (ObjectIdentifier)
static char sysUpTime[] PROGMEM     = "1.3.6.1.2.1.1.3.0";  // read-only  (TimeTicks)
static char sysContact[] PROGMEM    = "1.3.6.1.2.1.1.4.0";  // read-write (DisplayString)
static char sysName[] PROGMEM       = "1.3.6.1.2.1.1.5.0";  // read-write (DisplayString)
static char sysLocation[] PROGMEM   = "1.3.6.1.2.1.1.6.0";  // read-write (DisplayString)
static char sysServices[] PROGMEM   = "1.3.6.1.2.1.1.7.0";  // read-only  (Integer)
//
//
/* RFC1213 local values */
static char locDescr[] PROGMEM      = "Agentuino, a light-weight SNMP Agent.";  // read-only (static)
static char locObjectID[] PROGMEM   = "1.3.6.1.3.2009.0";                       // read-only (static)
static long locUpTime               = 0;                                        // RTC is needed for this unless the NTP Time library is used
static char locContact[20]          = "Eric Gionet";
static char locName[20]             = "Agentuino";
static char locLocation[20]         = "Nova Scotia, CA";
static short locServices PROGMEM    = 7;                                        // read-only (static)

Agentuino agent = Agentuino();

SNMP_SESSION session;
char oidString[SNMP_MAX_OID_LEN];
SNMP_API_STAT_CODES status;

void pduReceived()
{
  SNMP_PDU pdu;
  //
  Serial << "UDP Packet Received Start.." << " RAM:" << freeMemory() << endl;
  //
  status = agent.requestPdu(&pdu);
  //
  Serial << "Status: " << status << endl;
  //
  if ( pdu.type == SNMP_PDU_GET || pdu.type == SNMP_PDU_GET_NEXT 
    && pdu.error == SNMP_ERR_NO_ERROR && status == SNMP_API_STAT_SUCCESS) {
    //
    pdu.OID.toString(oidString);
    //
    Serial << "OID: " << oidString << endl;
    //
    if ( strcmp_P(oidString, sysDescr) == 0 ) {
      // response packet - locDescr
      pdu.type = SNMP_PDU_RESPONSE;
      pdu.VALUE.encode(SNMP_SYNTAX_OCTETS, locDescr);
      //
      Serial << "sysDescr..." << locDescr << " " << pdu.VALUE.size << endl;
    } else if ( strcmp_P(oidString, sysName) == 0 ) {
      // response packet - locName
      pdu.type = SNMP_PDU_RESPONSE;
      pdu.VALUE.encode(SNMP_SYNTAX_OCTETS, locName);
      //
      Serial << "sysName..." << locName << " " << pdu.VALUE.size << endl;
    } else if ( strcmp_P(oidString, sysContact) == 0 ) {
      // response packet - locContact
      pdu.type = SNMP_PDU_RESPONSE;
      pdu.VALUE.encode(SNMP_SYNTAX_OCTETS, locContact);
      //
      Serial << "sysContact..." << locContact << " " << pdu.VALUE.size << endl;
    } else if ( strcmp_P(oidString, sysLocation) == 0 ) {
      // response packet - locLocation
      pdu.type = SNMP_PDU_RESPONSE;
      pdu.VALUE.encode(SNMP_SYNTAX_OCTETS, locLocation);
      //
      Serial << "sysLocation..." << locLocation << " " << pdu.VALUE.size << endl;
    } else {
      // oid does not exist
      //
      // response packet - object not found
      pdu.type = SNMP_PDU_RESPONSE;
      pdu.error = SNMP_ERR_NO_SUCH_NAME;
    }
    //
    agent.responsePdu(&pdu);
  }
  //
  agent.freePdu(&pdu);
  //
  Serial << "UDP Packet Received End.." << " RAM:" << freeMemory() << endl;
}

void setup()
{
  Serial.begin(9600);
  Ethernet.begin(mac, ip);
  //
  session.getCommName = "public";
  session.setCommName = "private";
  session.port = 161;
  //
  status = agent.initSession(&session);
  //
  if ( status == SNMP_API_STAT_SUCCESS ) {
    //
    agent.onPduReceive(pduReceived);
    //
    delay(10);
    //
    Serial << "SNMP Agent Initalized..." << endl;
    //
    return;
  }
  //
  delay(10);
  //
  Serial << "SNMP Agent Initalization Problem..." << status << endl;
}

void loop()
{
  agent.listen();
}
