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

#ifndef Agentuino_h
#define Agentuino_h

#define SNMP_DEFAULT_PORT	161
#define SNMP_MIN_OID_LEN	2
#define SNMP_MAX_OID_LEN	64 // 128
#define SNMP_MAX_NAME_LEN	20
#define SNMP_MAX_VALUE_LEN      64  // 128 ??? should limit this
#define SNMP_MAX_PACKET_LEN     SNMP_MAX_VALUE_LEN + SNMP_MAX_OID_LEN  //???
#define SNMP_FREE(s)   do { if (s) { free((void *)s); s=NULL; } } while(0)
//Frees a pointer only if it is !NULL and sets its value to NULL. 

#include "WProgram.h"
#include "ASocket.h"

extern "C" {
	// callback function
	typedef void (*onPduReceiveCallback)(void);
}

typedef long long int64_t;
//typedef unsigned long unsigned long uint64_t;
//typedef long int32_t;
//typedef unsigned long uint32_t;
//typedef unsigned char uint8_t;
//typedef short int16_t;
//typedef unsigned short uint16_t;

typedef enum ASN_BER_BASE_TYPES {
	//   ASN/BER base types
	ASN_BER_BASE_UNIVERSAL 	 = 0x0,
	ASN_BER_BASE_APPLICATION = 0x40,
	ASN_BER_BASE_CONTEXT 	 = 0x80,
	ASN_BER_BASE_PUBLIC 	 = 0xC0,
	ASN_BER_BASE_PRIMITIVE 	 = 0x0,
	ASN_BER_BASE_CONSTRUCTOR = 0x20
};

typedef enum SNMP_PDU_TYPES {
	// PDU choices
	SNMP_PDU_GET	  = ASN_BER_BASE_CONTEXT | ASN_BER_BASE_CONSTRUCTOR | 0,
	SNMP_PDU_GET_NEXT = ASN_BER_BASE_CONTEXT | ASN_BER_BASE_CONSTRUCTOR | 1,
	SNMP_PDU_RESPONSE = ASN_BER_BASE_CONTEXT | ASN_BER_BASE_CONSTRUCTOR | 2,
	SNMP_PDU_SET	  = ASN_BER_BASE_CONTEXT | ASN_BER_BASE_CONSTRUCTOR | 3,
	SNMP_PDU_TRAP	  = ASN_BER_BASE_CONTEXT | ASN_BER_BASE_CONSTRUCTOR | 4
};

typedef enum SNMP_TRAP_TYPES {
	//   Trap generic types:
	SNMP_TRAP_COLD_START 	      = 0,
	SNMP_TRAP_WARM_START 	      = 1,
	SNMP_TRAP_LINK_DOWN 	      = 2,
	SNMP_TRAP_LINK_UP 	      = 3,
	SNMP_TRAP_AUTHENTICATION_FAIL = 4,
	SNMP_TRAP_EGP_NEIGHBORLOSS    = 5,
	SNMP_TRAP_ENTERPRISE_SPECIFIC = 6
};

typedef enum SNMP_ERR_CODES {
	SNMP_ERR_NO_ERROR 	  		= 0,
	SNMP_ERR_TOO_BIG 	  		= 1,
	SNMP_ERR_NO_SUCH_NAME 			= 2,
	SNMP_ERR_BAD_VALUE 	  		= 3,
	SNMP_ERR_READ_ONLY 	  		= 4,
	SNMP_ERR_GEN_ERROR 	  		= 5
/*
	SNMP_ERR_NO_ACCESS	  		= 6,
	SNMP_ERR_WRONG_TYPE   		SNMP_API_STAT_NAME_TOO_BIG,	= 7,
	SNMP_ERR_WRONG_LENGTH 			= 8,
	SNMP_ERR_WRONG_ENCODING			= 9,
	SNMP_ERR_WRONG_VALUE			= 10,
	SNMP_ERR_NO_CREATION			= 11,
	SNMP_ERR_INCONSISTANT_VALUE 		= 12,
	SNMP_ERR_RESOURCE_UNAVAILABLE		= 13,
	SNMP_ERR_COMMIT_FAILED			= 14,
	SNMP_ERR_UNDO_FAILED			= 15,
	SNMP_ERR_AUTHORIZATION_ERROR		= 16,
	SNMP_ERR_NOT_WRITABLE			= 17,
	SNMP_ERR_INCONSISTEN_NAME		= 18
*/
};

typedef enum SNMP_API_STAT_CODES {
	SNMP_API_STAT_SUCCESS = 0,
	SNMP_API_STAT_MALLOC_ERR = 1,
	SNMP_API_STAT_NAME_TOO_BIG = 2,
	SNMP_API_STAT_OID_TOO_BIG = 3,
	SNMP_API_STAT_VALUE_TOO_BIG = 4,
	SNMP_API_STAT_PACKET_INVALID = 5,
	SNMP_API_STAT_PACKET_TOO_BIG = 6
};

typedef enum SNMP_SYNTAXES {
	//   SNMP ObjectSyntax values
	SNMP_SYNTAX_SEQUENCE 	       = ASN_BER_BASE_UNIVERSAL | ASN_BER_BASE_CONSTRUCTOR | 0x10,
	//   These values are used in the "syntax" member of VALUEs
	SNMP_SYNTAX_BOOL 	       = ASN_BER_BASE_UNIVERSAL | ASN_BER_BASE_PRIMITIVE | 1,
	SNMP_SYNTAX_INT 	       = ASN_BER_BASE_UNIVERSAL | ASN_BER_BASE_PRIMITIVE | 2,
	SNMP_SYNTAX_BITS 	       = ASN_BER_BASE_UNIVERSAL | ASN_BER_BASE_PRIMITIVE | 3,
	SNMP_SYNTAX_OCTETS 	       = ASN_BER_BASE_UNIVERSAL | ASN_BER_BASE_PRIMITIVE | 4,
	SNMP_SYNTAX_NULL 	       = ASN_BER_BASE_UNIVERSAL | ASN_BER_BASE_PRIMITIVE | 5,
	SNMP_SYNTAX_OBJECT_IDENTIFIER  = ASN_BER_BASE_UNIVERSAL | ASN_BER_BASE_PRIMITIVE | 6,
	SNMP_SYNTAX_INT32 	       = SNMP_SYNTAX_INT,
	SNMP_SYNTAX_IP_ADDRESS         = ASN_BER_BASE_APPLICATION | ASN_BER_BASE_PRIMITIVE | 0,
	SNMP_SYNTAX_COUNTER 	       = ASN_BER_BASE_APPLICATION | ASN_BER_BASE_PRIMITIVE | 1,
	SNMP_SYNTAX_GAUGE 	       = ASN_BER_BASE_APPLICATION | ASN_BER_BASE_PRIMITIVE | 2,
	SNMP_SYNTAX_TIME_TICKS         = ASN_BER_BASE_APPLICATION | ASN_BER_BASE_PRIMITIVE | 3,
	SNMP_SYNTAX_OPAQUE 	       = ASN_BER_BASE_APPLICATION | ASN_BER_BASE_PRIMITIVE | 4,
	SNMP_SYNTAX_NSAPADDR 	       = ASN_BER_BASE_APPLICATION | ASN_BER_BASE_PRIMITIVE | 5,
	SNMP_SYNTAX_COUNTER64 	       = ASN_BER_BASE_APPLICATION | ASN_BER_BASE_PRIMITIVE | 6,
	SNMP_SYNTAX_UINT32 	       = ASN_BER_BASE_APPLICATION | ASN_BER_BASE_PRIMITIVE | 7,
};

typedef struct SNMP_OID {
	//byte *oid;
	byte oid[SNMP_MAX_OID_LEN];
	size_t size;
	//char *buffer;
	void toString(char *buffer) {
		buffer[0] = '1';
		buffer[1] = '.';
		buffer[2] = '3';
		buffer[3] = '\0';
		//
		// tmp buffer - short (Int16)
		char *buff = (char *)malloc(sizeof(char)*16);
		short mibVal;
		//
		for ( byte i = 1; i < size; i++ ) {
			mibVal = (short)oid[i];
			if ( mibVal > 128 ) {
				mibVal = (mibVal/128)*128 + (short)oid[i + 1];
				i++;
			}
			//
			itoa(mibVal, buff, 10);
			strcat(buffer, ".");
			strcat(buffer, buff);
		}
		// free buff
		//free(buff);
		SNMP_FREE(buff);
	};
	/*
	char *toString() {
		// don't realocate if its already sized
		if ( sizeof(buffer) == 0 ) {
			buffer = (char *)malloc(sizeof(char)*SNMP_MAX_OID_LEN);
		}
		buffer[0] = '1';
		buffer[1] = '.';
		buffer[2]SNMP response packet = '3';
		buffer[3] = '\0';
		//
		// tmp buffer - short (Int16)
		char *buff = (char *)malloc(sizeof(char)*16);
		short mibVal;
		//
		for ( byte i = 1; i < oidSize; i++ ) {
			mibVal = (short)oid[i];
			if ( mibVal > 128 ) {
				mibVal = (mibVal/128)*128 + (short)oid[i + 1];
				i++;
			}
			//
			itoa(mibVal, buff, 10);
			strcat(buffer, ".");
			strcat(buffer, buff);
		}
		// free buff
		free(buff);
		//
		return buffer;
	}
	*/
};

typedef struct SNMP_VALUE {
	//byte *value;
	byte value[SNMP_MAX_VALUE_LEN];
	size_t size;
	SNMP_SYNTAXES syntax;
	// union ???
	void encode(SNMP_SYNTAXES syn, const char *val) {
		byte i;
		//free(value);
		//SNMP_FREE(value);
		memset(value, 0, SNMP_MAX_VALUE_LEN);
		syntax = syn;
		if ( syn == SNMP_SYNTAX_OCTETS ) {
			size = strlen(val);
			//value = (byte *)malloc(sizeof(byte)*size);
			for ( i = 0; i < size; i++ ) {
				value[i] = (byte)val[i];
			}
		}
	}
	void encode(SNMP_SYNTAXES syn, int *val) {
	}
	void encode(SNMP_SYNTAXES syn, bool *val) {
	}
};

typedef struct SNMP_PDU {
	SNMP_PDU_TYPES type;
	int32_t version;
	int32_t requestId;
	SNMP_ERR_CODES error;
	int32_t errorIndex;
	SNMP_OID OID;
	SNMP_VALUE VALUE;
};

typedef struct SNMP_SESSION {
	char *getCommName;
	size_t getSize;
	char *setCommName;
	size_t setSize;
	uint16_t port;
};

typedef union int32_u {
	int32_t int32;
	byte data[4];
};

typedef union int16_u {
	int16_t int16;
	byte data[2];
};

class Agentuino {
public:
	// Constructor(s)
	Agentuino();

	// Agent functions
	SNMP_API_STAT_CODES initSession(SNMP_SESSION *session);
	void listen(void);
	SNMP_API_STAT_CODES requestPdu(SNMP_PDU *pdu);
	SNMP_API_STAT_CODES responsePdu(SNMP_PDU *pdu);
	void onPduReceive(onPduReceiveCallback pduReceived);
	void freePdu(SNMP_PDU *pdu);
	void closeSession(SNMP_SESSION *session);

	// Helper functions

private:
	byte *_packet;
	uint16_t _packetSize;
	uint16_t _packetPos;
	ASocket _socket;
	SNMP_PDU_TYPES _dstType;
	uint8_t _dstIp[4];
	uint16_t _dstPort;
	SNMP_SESSION *_session;
	onPduReceiveCallback _callback;
};

#endif
