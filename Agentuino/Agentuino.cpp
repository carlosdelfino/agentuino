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
	_packet = NULL;
	_session = NULL;
	_socket = ASocket();
}

SNMP_API_STAT_CODES Agentuino::initSession(SNMP_SESSION *session)
{
	// set community name set/get sizes
	session->setSize = strlen(session->setCommName);
	session->getSize = strlen(session->getCommName);
	//
	// validate get/set community name sizes
	if ( session->setSize > SNMP_MAX_NAME_LEN || session->getSize > SNMP_MAX_NAME_LEN ) {
		return SNMP_API_STAT_NAME_TOO_BIG;
	}
	//
	// set session property
	_session = session;
	//
	// validate session port number
	if ( session->port == NULL || session->port == 0 ) session->port = SNMP_DEFAULT_PORT;
	//
	// init UDP socket
	_socket.initUDP(session->port);
	//
	return SNMP_API_STAT_SUCCESS;
}

void Agentuino::listen(void)
{
	// if bytes available in receive buffer
	// and pointer to a function (delegate function)
	// isn't null, trigger the function
	if ( _socket.available() && _callback != NULL ) (*_callback)();
}


SNMP_API_STAT_CODES Agentuino::requestPdu(SNMP_PDU *pdu)
{
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
	// get UDP packet header
	_socket.beginRecvUDP(_dstIp, &_dstPort);
	//
	// set packet packet size
	_packetSize = _socket.available();
	//
	// validate packet
	if ( _packetSize != 0 && _packetSize > SNMP_MAX_PACKET_LEN ) {
		// free DPU receive buffer
		_socket.readSkip(_socket.available());
		//
		SNMP_FREE(_packet);

		return SNMP_API_STAT_PACKET_TOO_BIG;
	}
	//
	// allocate byte array based on packet size
	if ( (_packet = (byte *)malloc(sizeof(byte)*_packetSize)) == NULL ) {
		// free DPU receive buffer
		_socket.readSkip(_socket.available());
		//
		SNMP_FREE(_packet);

		return SNMP_API_STAT_MALLOC_ERR;
	}
	//
	// read socket buffer and set packet byte array
	_socket.read(_packet, _packetSize);
	//
	// packet check 1
	if ( _packet[0] != 0x30 ) {
		// free DPU receive buffer
		_socket.readSkip(_socket.available());
		//
		SNMP_FREE(_packet);

		return SNMP_API_STAT_PACKET_INVALID;
	}
	//
	// sequence length
	seqLen = _packet[1];
	// version
	verLen = _packet[3];
	verEnd = 3 + verLen;
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
	//
	// extract version
	pdu->version = 0;
	for ( i = 0; i < verLen; i++ ) {
		pdu->version = (pdu->version << 8) | _packet[5 + i];
	}
	//
	// pdu-type
	pdu->type = (SNMP_PDU_TYPES)pduTyp;
	_dstType = pdu->type;
	//
	// validate community size
	if ( comLen > SNMP_MAX_NAME_LEN ) {
		// free DPU receive buffer
		_socket.readSkip(_socket.available());
		//
		// set pdu error
		pdu->error = SNMP_ERR_TOO_BIG;
		//
		SNMP_FREE(_packet);

		return SNMP_API_STAT_NAME_TOO_BIG;
	}
	//
	// extract and compare community name
	// allocate char array based on community size
	if ( (community = (char *)malloc(sizeof(char)*comLen)) == NULL ) {
		// free DPU receive buffer
		_socket.readSkip(_socket.available());
		//
		SNMP_FREE(_packet);

		return SNMP_API_STAT_MALLOC_ERR;
	}
	//
	for ( i = 0; i < comLen; i++ ) {
		community[i] = _packet[verEnd + 3 + i];
	}
	// terminate as a string
	community[comLen] = '\0';
	//
	// validate community name
	if ( pdu->type == SNMP_PDU_SET ) {
		if ( strcmp(_session->setCommName, community) != 0 )
			// set pdu error
			pdu->error = SNMP_ERR_NO_SUCH_NAME;
	} else {
		if ( strcmp(_session->getCommName, community) != 0 )
			// set pdu error
			pdu->error = SNMP_ERR_NO_SUCH_NAME;
	}
	//
	// free community buffer
	SNMP_FREE(community);
	//
	// extract reqiest-id 0x00 0x00 0x00 0x01 (4-byte int aka int32)
	pdu->requestId = 0;
	for ( i = 0; i < ridLen; i++ ) {
		pdu->requestId = (pdu->requestId << 8) | _packet[comEnd + 5 + i];
	}
	//
	// extract error 
	pdu->error = SNMP_ERR_NO_ERROR;
	int32_t err = 0;
	for ( i = 0; i < errLen; i++ ) {
		err = (err << 8) | _packet[ridEnd + 3 + i];
	}
	pdu->error = (SNMP_ERR_CODES)err;
	//
	// extract error-index 
	pdu->errorIndex = 0;
	for ( i = 0; i < eriLen; i++ ) {
		pdu->errorIndex = (pdu->errorIndex << 8) | _packet[errEnd + 3 + i];
	}
	//
	//
	// validate object-identifier size
	if ( obiLen > SNMP_MAX_OID_LEN ) {
		// free DPU receive buffer
		_socket.readSkip(_socket.available());
		//
		// set pdu error
		pdu->error = SNMP_ERR_TOO_BIG;
		//
		SNMP_FREE(_packet);

		return SNMP_API_STAT_OID_TOO_BIG;
	}
	//
	// extract and contruct object-identifier
	/*
	if ( (pdu->OID.oid = (byte *)malloc(sizeof(byte)*obiLen)) == NULL ) {
		// free DPU receive buffer
		_socket.readSkip(_socket.available());
		//
		SNMP_FREE(_packet);

		return SNMP_API_STAT_MALLOC_ERR;
	}
	*/
	memset(pdu->OID.oid, 0, SNMP_MAX_OID_LEN);
	pdu->OID.size = obiLen;
	for ( i = 0; i < obiLen; i++ ) {
		pdu->OID.oid[i] = _packet[eriEnd + 7 + i];
	}
	//
	// value-type
	pdu->VALUE.syntax = (SNMP_SYNTAXES)valTyp;
	//
	// validate value size
	if ( obiLen > SNMP_MAX_VALUE_LEN ) {
		// free DPU receive buffer
		_socket.readSkip(_socket.available());
		//
		// set pdu error
		pdu->error = SNMP_ERR_TOO_BIG;
		//
		SNMP_FREE(_packet);

		return SNMP_API_STAT_VALUE_TOO_BIG;
	}
	//
	// value-size
	pdu->VALUE.size = valLen;
	//
	// extract value
	// allocate char array based on oid size
	/*
	if( (pdu->VALUE.value = (byte *)malloc(sizeof(byte)*valLen)) == NULL ) {
		// free DPU receive buffer
		_socket.readSkip(_socket.available());
		//
		SNMP_FREE(_packet);

		return SNMP_API_STAT_MALLOC_ERR;
	}
	*/
	memset(pdu->VALUE.value, 0, SNMP_MAX_VALUE_LEN);
	for ( i = 0; i < valLen; i++ ) {
		pdu->VALUE.value[i] = _packet[obiEnd + 3 + i];
	}
	//
	// free DPU receive buffer
	_socket.readSkip(_socket.available());
	//
	SNMP_FREE(_packet);
	//
	return SNMP_API_STAT_SUCCESS;
}

SNMP_API_STAT_CODES Agentuino::responsePdu(SNMP_PDU *pdu)
{
	int32_u u;
	byte i;
	//
	// Length of entire SNMP packet
	_packetPos = 0;  // 23
	_packetSize = 25 + sizeof(pdu->requestId) + sizeof(pdu->error) + sizeof(pdu->errorIndex) + pdu->OID.size + pdu->VALUE.size;
	//
	if ( _dstType == SNMP_PDU_SET ) {
		_packetSize += _session->setSize;
	} else {
		_packetSize += _session->getSize;
	}
	//
	// allocate byte array based on packet size
	if ( (_packet = (byte *)malloc(sizeof(byte)*_packetSize)) == NULL ) {
		// free DPU receive buffer
		_socket.readSkip(_socket.available());
		//
		SNMP_FREE(_packet);

		return SNMP_API_STAT_MALLOC_ERR;
	}
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
	if ( _dstType == SNMP_PDU_SET ) {
		_packet[_packetPos++] = (byte)_session->setSize;	// length
		for ( i = 0; i < _session->setSize; i++ ) {
			_packet[_packetPos++] = (byte)_session->setCommName[i];
		}
	} else {
		_packet[_packetPos++] = (byte)_session->getSize;	// length
		for ( i = 0; i < _session->getSize; i++ ) {
			_packet[_packetPos++] = (byte)_session->getCommName[i];
		}
	}
	//
	// SNMP PDU
	_packet[_packetPos++] = (byte)pdu->type;
	_packet[_packetPos++] = (byte)( sizeof(pdu->requestId) + sizeof((int32_t)pdu->error) + sizeof(pdu->errorIndex) + pdu->OID.size + pdu->VALUE.size + 14 );
	//
	// Request ID (size always 4 e.g. 4-byte int)
	_packet[_packetPos++] = (byte)SNMP_SYNTAX_INT;	// type
	_packet[_packetPos++] = (byte)sizeof(pdu->requestId);
	u.int32 = pdu->requestId;
	_packet[_packetPos++] = u.data[3];
	_packet[_packetPos++] = u.data[2];
	_packet[_packetPos++] = u.data[1];
	_packet[_packetPos++] = u.data[0];
	//
	// Error (size always 4 e.g. 4-byte int)
	_packet[_packetPos++] = (byte)SNMP_SYNTAX_INT;	// type
	_packet[_packetPos++] = (byte)sizeof((int32_t)pdu->error);
	u.int32 = pdu->error;
	_packet[_packetPos++] = u.data[3];
	_packet[_packetPos++] = u.data[2];
	_packet[_packetPos++] = u.data[1];
	_packet[_packetPos++] = u.data[0];
	//
	// Error Index (size always 4 e.g. 4-byte int)
	_packet[_packetPos++] = (byte)SNMP_SYNTAX_INT;	// type
	_packet[_packetPos++] = (byte)sizeof(pdu->errorIndex);
	u.int32 = pdu->errorIndex;
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
	_socket.beginPacketUDP(_dstIp, _dstPort); 
	_socket.write(_packet, _packetSize);
	_socket.readSkip(_socket.available()); 
	_socket.send();
	//
	SNMP_FREE(_packet);
	//
	return SNMP_API_STAT_SUCCESS;
}



void Agentuino::onPduReceive(onPduReceiveCallback pduReceived)
{
	_callback = pduReceived;
}

void Agentuino::freePdu(SNMP_PDU *pdu)
{
	//SNMP_FREE(pdu->OID.oid);
	//SNMP_FREE(pdu->VALUE.value);
	memset(pdu->OID.oid, 0, SNMP_MAX_OID_LEN);
	memset(pdu->VALUE.value, 0, SNMP_MAX_VALUE_LEN);
	free((char *) pdu);
}

void Agentuino::closeSession(SNMP_SESSION *session)
{
	free((char *) session);
}
