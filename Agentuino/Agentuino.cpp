/*
  Agentuino.cpp - An Arduino library for a lightweight SNMP Agent.
  Copyright (C) 2010 Eric C. Gionet <lavco_eg@hotmail.com>
  All rights reserved.

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

//
// sketch_aug23a
//

#include "Agentuino.h"
#include "ASocket.h"

Agentuino::Agentuino()
{
	_socket = ASocket();
}

unsigned char Agentuino::initSession(SNMP_SESSION *session)
{
	session->setSize = strlen(session->setCommName);
	session->getSize = strlen(session->getCommName);
	_session = session;
	_socket.initUDP(session->port);
}

void Agentuino::listen(void)
{
	if ( _socket.available() && _callback != NULL ) (*_callback)();
}

unsigned char Agentuino::requestPdu(SNMP_PDU *request)
{
	unsigned char error;
	char *community;
	// sequence length
	byte seqLen;
	// version
	byte verLen, verEnd;
	// community string
	byte comLen, comEnd;
	// pdu
	byte pduTyp, pduLen;
	byte ridLen, ridEnd;
	byte errLen, errEnd;
	byte eriLen, eriEnd;
	byte vblTyp, vblLen;
	byte vbiTyp, vbiLen;
	byte obiLen, obiEnd;
	byte valTyp, valLen, valEnd;
	byte i;
	//
	//
	_socket.beginRecvUDP(_dstIp, &_dstPort);
	//
	/*
	Serial.print(_dstIp[0], DEC);
	Serial.print(".");
	Serial.print(_dstIp[1], DEC);
	Serial.print(".");
	Serial.print(_dstIp[2], DEC);
	Serial.print(".");
	Serial.print(_dstIp[3], DEC);
	Serial.print(" ");
	Serial.print(_dstPort);
	Serial.println();
	*/
	//
	_packetPos = 0;
	//
	// set packet size
	_packetSize = _socket.available();
	//
	// validate packet
	if ( _packetSize > 0 && _packetSize <= SNMP_MAX_PACKET_LEN ) {
		// allocate byte array based on packet size
		_packet = (byte *)malloc(sizeof(byte)*_packetSize);
		//
		// read socket buffer and set packet byte array
		_socket.read(_packet, _packetSize);
		//
		for ( i = 0; i < _packetSize; i++ ) {
			Serial.print(i, DEC);
			Serial.print(" - ");
			Serial.print(_packet[i], HEX);
			Serial.print(" - ");
			Serial.print(_packet[i], DEC);
			Serial.print(" - ");
			Serial.print(_packet[i]);
			Serial.println();
		}
		//
		// packet check 1
		if ( _packet[_packetPos + 1] != 0x30 ) error = 1;
		//
		// sequence length
		seqLen = _packet[_packetPos + 2];
		// version
		verLen = _packet[_packetPos + 4];
		verEnd = _packetPos + 4 + verLen;
		// community string
		comLen = _packet[verEnd + 2];
		comEnd = verEnd + 2 + comLen;
		// pdu
		pduTyp = _packet[comEnd + 1];
		pduLen = _packet[comEnd + 2];
		ridLen = _packet[comEnd + 4];
		ridEnd = comEnd + 4 + ridLen;
		errLen = _packet[ridEnd + 2];
		errEnd = ridEnd + 2 + errLen;
		eriLen = _packet[errEnd + 2];
		eriEnd = errEnd + 2 + eriLen;
		vblTyp = _packet[eriEnd + 1];
		vblLen = _packet[eriEnd + 2];
		vbiTyp = _packet[eriEnd + 3];
		vbiLen = _packet[eriEnd + 4];
		obiLen = _packet[eriEnd + 6];
		obiEnd = eriEnd + obiLen + 6;
		valTyp = _packet[obiEnd + 1];
		valLen = _packet[obiEnd + 2];
		valEnd = obiEnd + 2 + valLen;
	} else {
		// invalid packet
		Serial.println("Invalid Packet...");
		return 1;
	}
	//
	// extract version  ??? this is wrong as with error, errorIndex
	request->version = 0;
	for ( i = 0; i < verLen; i++ ) {
		request->version = (request->version << 8) | _packet[_packetPos + 5 + i];
	}
	//
	// pdu-type
	request->type = (SNMP_PDU_TYPES)pduTyp;
	_dstType = request->type;
	//
	// extract and compare community name
	// allocate char array based on community size
	community = (char *)malloc(sizeof(char)*comLen);
	for ( i = 0; i < comLen; i++ ) {
		community[i] = _packet[verEnd + 3 + i];
	}
	// terminate as a string
	community[comLen] = '\0';
	//
	// validate community name
	if ( request->type == SNMP_PDU_SET ) {
		if ( strcmp(_session->setCommName, community) != 0 ) error = 2;
	} else {
		if ( strcmp(_session->getCommName, community) != 0 ) error = 2;
	}
	//
	free(community);
	//
	// extract reqiest-id ??? 0x00 0x00 0x00 0x01 (4-byte int aka int32)
	request->requestId = 0;
	for ( i = 0; i < ridLen; i++ ) {
		request->requestId = (request->requestId << 8) | _packet[comEnd + 5 + i];
	}
	//
	// extract error  ?? should be long
	request->error = 0;
	for ( i = 0; i < errLen; i++ ) {
		request->error = (request->error << 8) | _packet[ridEnd + 3 + i];
	}
	//
	// extract error-index  ?? should be long
	request->errorIndex = 0;
	for ( i = 0; i < eriLen; i++ ) {
		request->errorIndex = (request->errorIndex << 8) | _packet[errEnd + 3 + i];
	}
	//
	// extract and contruct object-identifier
	request->OID.oid = (byte *)malloc(sizeof(byte)*obiLen);
	request->OID.size = obiLen;
	for ( i = 0; i < obiLen; i++ ) {
		request->OID.oid[i] = _packet[eriEnd + 7 + i];
	}
	//
	// value-type
	request->VALUE.syntax = (SNMP_SYNTAXES)valTyp;
	//
	// value-size
	request->VALUE.size = valLen;
	//
	// extract value
	// allocate char array based on oid size
	request->VALUE.value = (byte *)malloc(sizeof(byte)*valLen);
	for ( i = 0; i < valLen; i++ ) {
		request->VALUE.value[i] = _packet[obiEnd + 3 + i];
	}
}

unsigned char Agentuino::responsePdu(SNMP_PDU *pdu)
{
	int32_u u;
	byte i;
	//
	//snmplen = 29 + comlen + miblen - 1;  //Length of entire SNMP packet
	// 21
	_packetPos = 0;  // 20?
	_packetSize = 23 + sizeof(pdu->requestId) + sizeof(pdu->error) + sizeof(pdu->errorIndex) + pdu->OID.size + pdu->VALUE.size;
	if ( _dstType == SNMP_PDU_SET ) {
		_packetSize += _session->setSize;
	} else {
		_packetSize += _session->getSize;
	}
	//
	// allocate byte array based on packet size
	//_packet = (byte *)malloc(sizeof(byte)*SNMP_MAX_PACKET_LEN);
	_packet = (byte *)malloc(sizeof(byte)*_packetSize);
	//
	_packet[_packetPos++] = (byte)SNMP_SYNTAX_SEQUENCE;	// type
	_packet[_packetPos++] = (byte)_packetSize - 2;		// length
	//
	// SNMP version
	_packet[_packetPos++] = (byte)SNMP_SYNTAX_INT;	// type
	_packet[_packetPos++] = 0x01;			// length
	_packet[_packetPos++] = 0x00;			// value
	//
	// SNMP community string
	_packet[_packetPos++] = (byte)SNMP_SYNTAX_OCTETS;	// type
	_packet[_packetPos++] = (byte)_session->getSize;	// length
	for ( i = 0; i < _session->getSize; i++ ) {
		_packet[_packetPos++] = (byte)_session->getCommName[i];
	}
	//
	// SNMP PDU
	_packet[_packetPos++] = (byte)pdu->type;
	_packet[_packetPos++] = (byte)( sizeof(pdu->requestId) + sizeof(pdu->error) + sizeof(pdu->errorIndex) + pdu->OID.size + pdu->VALUE.size + 14 );
	//
	// Request ID (size always 4 e.g. 4-byte int)
	_packet[_packetPos++] = (byte)SNMP_SYNTAX_INT;	// type
	_packet[_packetPos++] = (byte)sizeof(pdu->requestId);
	//for ( i = 0; i < sizeof(pdu->requestId); i++ ) {
	//	_packet[_packetPos++] = 0x00;
	//}
	u.int32_t = pdu->requestId;
	_packet[_packetPos++] = u.data[3];
	_packet[_packetPos++] = u.data[2];
	_packet[_packetPos++] = u.data[1];
	_packet[_packetPos++] = u.data[0];
	//
	Serial.print("RequestId: ");
	Serial.print(pdu->requestId);
	Serial.println();
	//
	// Error (size always 4 e.g. 4-byte int)
	_packet[_packetPos++] = (byte)SNMP_SYNTAX_INT;	// type
	_packet[_packetPos++] = (byte)sizeof(pdu->error);
	//for ( i = 0; i < sizeof(pdu->error); i++ ) {
	//	_packet[_packetPos++] = 0x00;
	//}
	u.int32_t = pdu->error;
	_packet[_packetPos++] = u.data[3];
	_packet[_packetPos++] = u.data[2];
	_packet[_packetPos++] = u.data[1];
	_packet[_packetPos++] = u.data[0];
	//
	// Error Index (size always 4 e.g. 4-byte int)
	_packet[_packetPos++] = (byte)SNMP_SYNTAX_INT;	// type
	_packet[_packetPos++] = (byte)sizeof(pdu->errorIndex);
	//for ( i = 0; i < sizeof(pdu->errorIndex); i++ ) {
	//	_packet[_packetPos++] = 0x00;
	//}
	u.int32_t = pdu->errorIndex;
	_packet[_packetPos++] = u.data[3];
	_packet[_packetPos++] = u.data[2];
	_packet[_packetPos++] = u.data[1];
	_packet[_packetPos++] = u.data[0];
	//
	// Varbind List
	_packet[_packetPos++] = (byte)SNMP_SYNTAX_SEQUENCE;	// type
	_packet[_packetPos++] = (byte)( pdu->OID.size + pdu->VALUE.size + 6 ); //4
	//
	// Varbind
	_packet[_packetPos++] = (byte)SNMP_SYNTAX_SEQUENCE;	// type
	_packet[_packetPos++] = (byte)( pdu->OID.size + pdu->VALUE.size + 4 ); //2
	//
	// ObjectIdentifier
	_packet[_packetPos++] = (byte)SNMP_SYNTAX_OBJECT_IDENTIFIER;	// type
	_packet[_packetPos++] = (byte)(pdu->OID.size);
	for ( i = 0; i < pdu->OID.size; i++ ) {
		_packet[_packetPos++] = pdu->OID.oid[i];
	}
	//
	// Value
	_packet[_packetPos++] = (byte)pdu->VALUE.syntax;	// type
	_packet[_packetPos++] = (byte)(pdu->VALUE.size);
	for ( i = 0; i < pdu->VALUE.size; i++ ) {
		_packet[_packetPos++] = pdu->VALUE.value[i];
	}
	//
	Serial.print("Response Packet...PSize:");
	Serial.print(_packetSize);
	Serial.print(" PPos:");
	Serial.println(_packetPos);
	for ( i = 0; i < _packetPos; i++ ) {
		Serial.print(i, DEC);
		Serial.print(" - ");
		Serial.print(_packet[i], HEX);
		Serial.print(" - ");
		Serial.print(_packet[i], DEC);
		Serial.print(" - ");
		Serial.print(_packet[i]);
		Serial.println();
	}
	//
	_socket.beginPacketUDP(_dstIp, _dstPort);  //???
	_socket.write(_packet, _packetSize);
	_socket.readSkip(_socket.available()); 
	_socket.send();
	//
	free(_packet);
}

void Agentuino::onPduReceive(onPduReceiveCallback pduReceived)
{
	_callback = pduReceived;
}

void Agentuino::freePdu(SNMP_PDU *pdu)
{
	free(pdu->OID.oid);
	//free(pdu->OID.buffer);
	free(pdu->VALUE.value);
	free(pdu);
}

void Agentuino::closeSession(SNMP_SESSION *session)
{
	free(session->getCommName);
	free(session->setCommName);
	free(session->ip);
	free(session);
}
