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
#define SNMP_MAX_PACKET_LEN     SNMP_MAX_VALUE_LEN + SNMP_MAX_OID_LEN + 25  //???
#define SNMP_FREE(s)   do { if (s) { free((void *)s); s=NULL; } } while(0)
//Frees a pointer only if it is !NULL and sets its value to NULL. 

#include "WProgram.h"
#include "Udp.h"

extern "C" {
	// callback function
	typedef void (*onPduReceiveCallback)(void);
}

//typedef long long int64_t;
typedef unsigned long long uint64_t;
//typedef long int32_t;
//typedef unsigned long uint32_t;
//typedef unsigned char uint8_t;
//typedef short int16_t;
//typedef unsigned short uint16_t;


typedef union uint64_u {
	uint64_t uint64;
	byte data[8];
};

typedef union int32_u {
	int32_t int32;
	byte data[4];
};

typedef union uint32_u {
	uint32_t uint32;
	byte data[4];
};

typedef union int16_u {
	int16_t int16;
	byte data[2];
};

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
	SNMP_ERR_GEN_ERROR 	  		= 5,

	SNMP_ERR_NO_ACCESS	  		= 6,
	SNMP_ERR_WRONG_TYPE   			= 7,
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

//
// http://oreilly.com/catalog/esnmp/chapter/ch02.html Table 2-1: SMIv1 Datatypes

typedef enum SNMP_SYNTAXES {
	//   SNMP ObjectSyntax values
	SNMP_SYNTAX_SEQUENCE 	       = ASN_BER_BASE_UNIVERSAL | ASN_BER_BASE_CONSTRUCTOR | 0x10,
	//   These values are used in the "syntax" member of VALUEs
	SNMP_SYNTAX_BOOL 	       = ASN_BER_BASE_UNIVERSAL | ASN_BER_BASE_PRIMITIVE | 1,
	SNMP_SYNTAX_INT 	       = ASN_BER_BASE_UNIVERSAL | ASN_BER_BASE_PRIMITIVE | 2,
	SNMP_SYNTAX_BITS 	       = ASN_BER_BASE_UNIVERSAL | ASN_BER_BASE_PRIMITIVE | 3,
	SNMP_SYNTAX_OCTETS 	       = ASN_BER_BASE_UNIVERSAL | ASN_BER_BASE_PRIMITIVE | 4,
	SNMP_SYNTAX_NULL 	       = ASN_BER_BASE_UNIVERSAL | ASN_BER_BASE_PRIMITIVE | 5,
	SNMP_SYNTAX_OID		       = ASN_BER_BASE_UNIVERSAL | ASN_BER_BASE_PRIMITIVE | 6,
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
	byte data[SNMP_MAX_OID_LEN];
	size_t size;
	//
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
			mibVal = (short)data[i];
			if ( mibVal > 128 ) {
				mibVal = (mibVal/128)*128 + (short)data[i + 1];
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
};

typedef struct SNMP_VALUE {
	byte data[SNMP_MAX_VALUE_LEN];
	size_t size;
	SNMP_SYNTAXES syntax;
	//
	byte i; // for encoding/decoding functions
	//
	// clear's buffer and sets size to 0
	void clear(void) {
		memset(data, 0, SNMP_MAX_VALUE_LEN);
		size = 0;
	}
	//
	//
	// ASN.1 decoding functions
	//
	// decode's a string from an octet string, opaque syntax
	// decode object-identifier here??
	SNMP_ERR_CODES decode(char *value, size_t max_size) {
		if ( syntax == SNMP_SYNTAX_OCTETS || syntax == SNMP_SYNTAX_OPAQUE ) {
			if ( strlen(value) - 1 < max_size ) {
				for ( i = 0; i < size; i++ ) {
					value[i] = (char)data[i];
				}
				value[size] = '\0';
				return SNMP_ERR_NO_ERROR;
			} else {
				clear();	
				return SNMP_ERR_TOO_BIG;
			}
		} else {
			clear();
			return SNMP_ERR_WRONG_TYPE;
		}
	}
	//
	// decode's an int16 from int syntax
	SNMP_ERR_CODES decode(int16_t *value) {
		if ( syntax == SNMP_SYNTAX_INT ) {
			int16_u tmp;
			tmp.data[1] = data[0];
			tmp.data[0] = data[1];
			*value = tmp.int16;
			return SNMP_ERR_NO_ERROR;
		} else {
			clear();
			return SNMP_ERR_WRONG_TYPE;
		}
	}
	//
	// decode's an int32 from int or int32 syntax
	SNMP_ERR_CODES decode(int32_t *value) {
		if ( syntax == SNMP_SYNTAX_INT || syntax == SNMP_SYNTAX_INT32 ) {
			int32_u tmp;
			tmp.data[3] = data[0];
			tmp.data[2] = data[1];
			tmp.data[1] = data[2];
			tmp.data[0] = data[3];
			*value = tmp.int32;
			return SNMP_ERR_NO_ERROR;
		} else {
			clear();
			return SNMP_ERR_WRONG_TYPE;
		}
	}
	//
	// decode's an uint32 from uint32, counter, time-ticks, gauge syntax
	SNMP_ERR_CODES decode(uint32_t *value) {
		if ( syntax == SNMP_SYNTAX_COUNTER || syntax == SNMP_SYNTAX_TIME_TICKS
			|| syntax == SNMP_SYNTAX_GAUGE || syntax == SNMP_SYNTAX_UINT32 ) {
			uint32_u tmp;
			tmp.data[3] = data[0];
			tmp.data[2] = data[1];
			tmp.data[1] = data[2];
			tmp.data[0] = data[3];
			*value = tmp.uint32;
			return SNMP_ERR_NO_ERROR;
		} else {
			clear();
			return SNMP_ERR_WRONG_TYPE;
		}
	}
	//
	// decode's an ip-address byte array from ip-address, NSAP-address syntax
	SNMP_ERR_CODES decode(byte *value) {
		memset(data, 0, SNMP_MAX_VALUE_LEN);
		if ( syntax == SNMP_SYNTAX_IP_ADDRESS || syntax == SNMP_SYNTAX_NSAPADDR ) {
			if ( sizeof(value) > 4 ) {
				clear();
				return SNMP_ERR_TOO_BIG;
			} else {
				size = 4;
				data[0] = value[3];
				data[1] = value[2];
				data[2] = value[1];
				data[3] = value[0];
				return SNMP_ERR_NO_ERROR;
			}
		} else {
			clear();
			return SNMP_ERR_WRONG_TYPE;
		}
	}
	//
	// decode's a boolean from boolean syntax
	SNMP_ERR_CODES decode(bool *value) {
		if ( syntax == SNMP_SYNTAX_BOOL ) {
			*value = (data[0] != 0);
			return SNMP_ERR_NO_ERROR;
		} else {
			clear();
			return SNMP_ERR_WRONG_TYPE;
		}
	}
	//
	//
	// ASN.1 encoding functions
	//
	// encode's a octet string to a string, opaque syntax
	// encode object-identifier here??
	SNMP_ERR_CODES encode(SNMP_SYNTAXES syn, const char *value) {
		memset(data, 0, SNMP_MAX_VALUE_LEN);
		if ( syn == SNMP_SYNTAX_OCTETS || syn == SNMP_SYNTAX_OPAQUE ) {
			if ( strlen(value) - 1 < SNMP_MAX_VALUE_LEN ) {
				syntax = syn;
				size = strlen(value);
				for ( i = 0; i < size; i++ ) {
					data[i] = (byte)value[i];
				}
				return SNMP_ERR_NO_ERROR;
			} else {
				clear();	
				return SNMP_ERR_TOO_BIG;
			}
		} else {
			clear();
			return SNMP_ERR_WRONG_TYPE;
		}
	}
	//
	// encode's an int16 to int syntax
	SNMP_ERR_CODES encode(SNMP_SYNTAXES syn, const int16_t value) {
		memset(data, 0, SNMP_MAX_VALUE_LEN);
		if ( syn == SNMP_SYNTAX_INT || syn == SNMP_SYNTAX_OPAQUE ) {
			int16_u tmp;
			size = 2;
			syntax = syn;
			tmp.int16 = value;
			data[0] = tmp.data[1];
			data[1] = tmp.data[0];
			return SNMP_ERR_NO_ERROR;
		} else {
			clear();
			return SNMP_ERR_WRONG_TYPE;
		}
	}
	//
	// encode's an int32 to int32 syntax
	SNMP_ERR_CODES encode(SNMP_SYNTAXES syn, const int32_t value) {
		memset(data, 0, SNMP_MAX_VALUE_LEN);
		if ( syn == SNMP_SYNTAX_INT || syn == SNMP_SYNTAX_INT32 
			|| syn == SNMP_SYNTAX_OPAQUE ) {
			int32_u tmp;
			size = 4;
			syntax = syn;
			tmp.int32 = value;
			data[0] = tmp.data[3];
			data[1] = tmp.data[2];
			data[2] = tmp.data[1];
			data[3] = tmp.data[0];
			return SNMP_ERR_NO_ERROR;
		} else {
			clear();
			return SNMP_ERR_WRONG_TYPE;
		}
	}
	//
	// encode's an uint32 to uint32, counter, time-ticks, gauge syntax
	SNMP_ERR_CODES encode(SNMP_SYNTAXES syn, const uint32_t value) {
		memset(data, 0, SNMP_MAX_VALUE_LEN);
		if ( syn == SNMP_SYNTAX_COUNTER || syn == SNMP_SYNTAX_TIME_TICKS
			|| syn == SNMP_SYNTAX_GAUGE || syn == SNMP_SYNTAX_UINT32 
			|| syn == SNMP_SYNTAX_OPAQUE ) {
			uint32_u tmp;
			size = 4;
			syntax = syn;
			tmp.uint32 = value;
			data[0] = tmp.data[3];
			data[1] = tmp.data[2];
			data[2] = tmp.data[1];
			data[3] = tmp.data[0];
			return SNMP_ERR_NO_ERROR;
		} else {
			clear();
			return SNMP_ERR_WRONG_TYPE;
		}
	}
	//
	// encode's an ip-address byte array to ip-address, NSAP-address syntax
	SNMP_ERR_CODES encode(SNMP_SYNTAXES syn, const byte *value) {
		memset(data, 0, SNMP_MAX_VALUE_LEN);
		if ( syn == SNMP_SYNTAX_IP_ADDRESS || syn == SNMP_SYNTAX_NSAPADDR 
			|| syn == SNMP_SYNTAX_OPAQUE ) {
			if ( sizeof(value) > 4 ) {
				clear();
				return SNMP_ERR_TOO_BIG;
			} else {
				size = 4;
				syntax = syn;
				data[0] = value[3];
				data[1] = value[2];
				data[2] = value[1];
				data[3] = value[0];
				return SNMP_ERR_NO_ERROR;
			}
		} else {
			clear();
			return SNMP_ERR_WRONG_TYPE;
		}
	}
	//
	// encode's a boolean to boolean syntax
	SNMP_ERR_CODES encode(SNMP_SYNTAXES syn, const bool value) {
		memset(data, 0, SNMP_MAX_VALUE_LEN);
		if ( syn == SNMP_SYNTAX_BOOL || syn == SNMP_SYNTAX_OPAQUE ) {
			size = 1;
			syntax = syn;
			data[0] = value ? 0xff : 0;
			return SNMP_ERR_NO_ERROR;
		} else {
			clear();
			return SNMP_ERR_WRONG_TYPE;
		}
	}
	//
	// encode's an uint64 to counter64 syntax
	SNMP_ERR_CODES encode(SNMP_SYNTAXES syn, const uint64_t value) {
		memset(data, 0, SNMP_MAX_VALUE_LEN);
		if ( syn == SNMP_SYNTAX_COUNTER64 || syn == SNMP_SYNTAX_OPAQUE ) {
			uint64_u tmp;
			size = 8;
			syntax = syn;
			tmp.uint64 = value;
			data[0] = tmp.data[7];
			data[1] = tmp.data[6];
			data[2] = tmp.data[5];
			data[3] = tmp.data[4];
			data[4] = tmp.data[3];
			data[5] = tmp.data[2];
			data[6] = tmp.data[1];
			data[7] = tmp.data[0];
			return SNMP_ERR_NO_ERROR;
		} else {
			clear();
			return SNMP_ERR_WRONG_TYPE;
		}
	}
	//
	// encode's a null syntax
	SNMP_ERR_CODES encode(SNMP_SYNTAXES syn) {
		clear();
		if ( syn == SNMP_SYNTAX_NULL || syn == SNMP_SYNTAX_OPAQUE ) {
			size = 0;
			syntax = syn;
			return SNMP_ERR_NO_ERROR;
		} else {
			return SNMP_ERR_WRONG_TYPE;
		}
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

class AgentuinoClass {
public:
	// Agent functions
	SNMP_API_STAT_CODES begin();
	SNMP_API_STAT_CODES begin(char *getCommName, char *setCommName, uint16_t port);
	void listen(void);
	SNMP_API_STAT_CODES requestPdu(SNMP_PDU *pdu);
	SNMP_API_STAT_CODES responsePdu(SNMP_PDU *pdu);
	void onPduReceive(onPduReceiveCallback pduReceived);
	void freePdu(SNMP_PDU *pdu);

	// Helper functions

private:
	byte _packet[SNMP_MAX_PACKET_LEN];
	uint16_t _packetSize;
	uint16_t _packetPos;
	SNMP_PDU_TYPES _dstType;
	uint8_t _dstIp[4];
	uint16_t _dstPort;
	char *_getCommName;
	size_t _getSize;
	char *_setCommName;
	size_t _setSize;
	onPduReceiveCallback _callback;
};

extern AgentuinoClass Agentuino;

#endif
