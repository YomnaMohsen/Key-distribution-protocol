/* Process model C++ form file: manet_dispatcher_cluster.pr.cpp */
/* Portions of this file copyright 1986-2008 by OPNET Technologies, Inc. */



/* This variable carries the header into the object file */
const char manet_dispatcher_cluster_pr_cpp [] = "MIL_3_Tfile_Hdr_ 145A 30A modeler 7 5AC0FC05 5AC0FC05 1 hp-PC hp 0 0 none none 0 0 none 0 0 0 0 0 0 0 0 1e80 8                                                                                                                                                                                                                                                                                                                                                                                                                 ";
#include <string.h>



/* OPNET system definitions */
#include <opnet.h>



/* Header Block */

/** Include files.					**/
#include <ip_higher_layer_proto_reg_sup.h>
#include <ip_rte_v4.h>
#include <ip_rte_support.h>
#include <ip_addr_v4.h>
#include <manet.h>
#include <oms_dist_support.h>
#include <oms_pr.h>
#include <oms_tan.h>
#include <oms_log_support.h>
#include <oms_sim_attr_cache.h>

#include<iostream>
//new


using namespace std;
#define uchar unsigned char // 8-bit byte
#define uint unsigned long // 32-bit word


/* Transition Macros				*/
#define		SELF_INTERRUPT 		(OPC_INTRPT_SELF == intrpt_type)
#define		STREAM_INTERRUPT 	(OPC_INTRPT_STRM == intrpt_type)

////////////////////////////////////////////////////////////////////////////////

//msg type
// msg sent from global node to head
#define    head    1 

// msg sent from head
#define     key     2     
//msg sent from head for hash_auth
#define    auth_hash     3

//msg sent from member head hash_Nid
#define    re_hashed     4
//msg sent from  head to send encrypted  ckeys if hashed nid is true
#define    re_keys    5
// msg sent from member with decrypted ckey
//#define    re_deckey  6// we replace it  bcz key sent re_encrypted
# define re_reenckey 6 
#define    re_symkey  7
#define    re_encsymkey 8 
# define  malc  9
# define recev 10
# define over_head 11
# define comer_msg 12

	



uchar in[]={0x00, 0x11 ,0x22 ,0x33,0x44 ,0x55 ,0x66 ,0x77,0x88 ,0x99,0xaa,0xbb,0xcc ,0xdd,0xee,0xff};
	
uchar keyin[]={0x00,0x01, 0x02 ,0x03 ,0x04 ,0x05 ,0x06,0x07,0x08,0x09 ,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
// Prg_List* symkey;// to store key for head

//uchar sub_nid[16]={0x2b,0x7e, 0x15 ,0x16 ,0x28 ,0xae ,0xd2,0xa6,0xab,0xf7 ,0x15,0x88,0x09,0xcf,0x4f,0x3c};
 //uchar sub_nid[16]={0x00,0x01, 0x02 ,0x03 ,0x04 ,0x05 ,0x06,0x07,0x08,0x09 ,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};


 
//sha 256 def
//********************************************************************************

uchar Nid[]={"6033e41017ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4aabbccddeeff01234567891eff8996778"};
//{"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"};
// output of 256 bits


#define DBL_INT_ADD(a,b,c) if (a > 0xffffffff - (c)) ++b; a += c;//? b for blocks
#define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))

#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))


typedef struct {
   uchar data[64];//block in bytes
   unsigned int datalen;
   unsigned int bitlen[2];
   unsigned int state[8];
} SHA256_CTX;

unsigned int k[64] = {
   0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
   0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
   0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
   0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
   0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
   0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
   0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
   0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

//^^^^^^^^^^^^^^^^^^^*******************************************^^^^^^^^^^^^^^^^^^^^^^

//AES def


#define KE_ROTWORD(x) ( ((x) << 8) | ((x) >> 24) )
const uchar aes_sbox[16][16] = {
   0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
   0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
   0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
   0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
   0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
   0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
   0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
   0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
   0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
   0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
   0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
   0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
   0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
   0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
   0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
   0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16
};


const uchar aes_invsbox[16][16] = {
   0x52,0x09,0x6A,0xD5,0x30,0x36,0xA5,0x38,0xBF,0x40,0xA3,0x9E,0x81,0xF3,0xD7,0xFB,
   0x7C,0xE3,0x39,0x82,0x9B,0x2F,0xFF,0x87,0x34,0x8E,0x43,0x44,0xC4,0xDE,0xE9,0xCB,
   0x54,0x7B,0x94,0x32,0xA6,0xC2,0x23,0x3D,0xEE,0x4C,0x95,0x0B,0x42,0xFA,0xC3,0x4E,
   0x08,0x2E,0xA1,0x66,0x28,0xD9,0x24,0xB2,0x76,0x5B,0xA2,0x49,0x6D,0x8B,0xD1,0x25,
   0x72,0xF8,0xF6,0x64,0x86,0x68,0x98,0x16,0xD4,0xA4,0x5C,0xCC,0x5D,0x65,0xB6,0x92,
   0x6C,0x70,0x48,0x50,0xFD,0xED,0xB9,0xDA,0x5E,0x15,0x46,0x57,0xA7,0x8D,0x9D,0x84,
   0x90,0xD8,0xAB,0x00,0x8C,0xBC,0xD3,0x0A,0xF7,0xE4,0x58,0x05,0xB8,0xB3,0x45,0x06,
   0xD0,0x2C,0x1E,0x8F,0xCA,0x3F,0x0F,0x02,0xC1,0xAF,0xBD,0x03,0x01,0x13,0x8A,0x6B,
   0x3A,0x91,0x11,0x41,0x4F,0x67,0xDC,0xEA,0x97,0xF2,0xCF,0xCE,0xF0,0xB4,0xE6,0x73,
   0x96,0xAC,0x74,0x22,0xE7,0xAD,0x35,0x85,0xE2,0xF9,0x37,0xE8,0x1C,0x75,0xDF,0x6E,
   0x47,0xF1,0x1A,0x71,0x1D,0x29,0xC5,0x89,0x6F,0xB7,0x62,0x0E,0xAA,0x18,0xBE,0x1B,
   0xFC,0x56,0x3E,0x4B,0xC6,0xD2,0x79,0x20,0x9A,0xDB,0xC0,0xFE,0x78,0xCD,0x5A,0xF4,
   0x1F,0xDD,0xA8,0x33,0x88,0x07,0xC7,0x31,0xB1,0x12,0x10,0x59,0x27,0x80,0xEC,0x5F,
   0x60,0x51,0x7F,0xA9,0x19,0xB5,0x4A,0x0D,0x2D,0xE5,0x7A,0x9F,0x93,0xC9,0x9C,0xEF,
   0xA0,0xE0,0x3B,0x4D,0xAE,0x2A,0xF5,0xB0,0xC8,0xEB,0xBB,0x3C,0x83,0x53,0x99,0x61,
   0x17,0x2B,0x04,0x7E,0xBA,0x77,0xD6,0x26,0xE1,0x69,0x14,0x63,0x55,0x21,0x0C,0x7D
};

uchar gf_mul[256][6] = {
   {0x00,0x00,0x00,0x00,0x00,0x00},{0x02,0x03,0x09,0x0b,0x0d,0x0e},
   {0x04,0x06,0x12,0x16,0x1a,0x1c},{0x06,0x05,0x1b,0x1d,0x17,0x12},
   {0x08,0x0c,0x24,0x2c,0x34,0x38},{0x0a,0x0f,0x2d,0x27,0x39,0x36},
   {0x0c,0x0a,0x36,0x3a,0x2e,0x24},{0x0e,0x09,0x3f,0x31,0x23,0x2a},
   {0x10,0x18,0x48,0x58,0x68,0x70},{0x12,0x1b,0x41,0x53,0x65,0x7e},
   {0x14,0x1e,0x5a,0x4e,0x72,0x6c},{0x16,0x1d,0x53,0x45,0x7f,0x62},
   {0x18,0x14,0x6c,0x74,0x5c,0x48},{0x1a,0x17,0x65,0x7f,0x51,0x46},
   {0x1c,0x12,0x7e,0x62,0x46,0x54},{0x1e,0x11,0x77,0x69,0x4b,0x5a},
   {0x20,0x30,0x90,0xb0,0xd0,0xe0},{0x22,0x33,0x99,0xbb,0xdd,0xee},
   {0x24,0x36,0x82,0xa6,0xca,0xfc},{0x26,0x35,0x8b,0xad,0xc7,0xf2},
   {0x28,0x3c,0xb4,0x9c,0xe4,0xd8},{0x2a,0x3f,0xbd,0x97,0xe9,0xd6},
   {0x2c,0x3a,0xa6,0x8a,0xfe,0xc4},{0x2e,0x39,0xaf,0x81,0xf3,0xca},
   {0x30,0x28,0xd8,0xe8,0xb8,0x90},{0x32,0x2b,0xd1,0xe3,0xb5,0x9e},
   {0x34,0x2e,0xca,0xfe,0xa2,0x8c},{0x36,0x2d,0xc3,0xf5,0xaf,0x82},
   {0x38,0x24,0xfc,0xc4,0x8c,0xa8},{0x3a,0x27,0xf5,0xcf,0x81,0xa6},
   {0x3c,0x22,0xee,0xd2,0x96,0xb4},{0x3e,0x21,0xe7,0xd9,0x9b,0xba},
   {0x40,0x60,0x3b,0x7b,0xbb,0xdb},{0x42,0x63,0x32,0x70,0xb6,0xd5},
   {0x44,0x66,0x29,0x6d,0xa1,0xc7},{0x46,0x65,0x20,0x66,0xac,0xc9},
   {0x48,0x6c,0x1f,0x57,0x8f,0xe3},{0x4a,0x6f,0x16,0x5c,0x82,0xed},
   {0x4c,0x6a,0x0d,0x41,0x95,0xff},{0x4e,0x69,0x04,0x4a,0x98,0xf1},
   {0x50,0x78,0x73,0x23,0xd3,0xab},{0x52,0x7b,0x7a,0x28,0xde,0xa5},
   {0x54,0x7e,0x61,0x35,0xc9,0xb7},{0x56,0x7d,0x68,0x3e,0xc4,0xb9},
   {0x58,0x74,0x57,0x0f,0xe7,0x93},{0x5a,0x77,0x5e,0x04,0xea,0x9d},
   {0x5c,0x72,0x45,0x19,0xfd,0x8f},{0x5e,0x71,0x4c,0x12,0xf0,0x81},
   {0x60,0x50,0xab,0xcb,0x6b,0x3b},{0x62,0x53,0xa2,0xc0,0x66,0x35},
   {0x64,0x56,0xb9,0xdd,0x71,0x27},{0x66,0x55,0xb0,0xd6,0x7c,0x29},
   {0x68,0x5c,0x8f,0xe7,0x5f,0x03},{0x6a,0x5f,0x86,0xec,0x52,0x0d},
   {0x6c,0x5a,0x9d,0xf1,0x45,0x1f},{0x6e,0x59,0x94,0xfa,0x48,0x11},
   {0x70,0x48,0xe3,0x93,0x03,0x4b},{0x72,0x4b,0xea,0x98,0x0e,0x45},
   {0x74,0x4e,0xf1,0x85,0x19,0x57},{0x76,0x4d,0xf8,0x8e,0x14,0x59},
   {0x78,0x44,0xc7,0xbf,0x37,0x73},{0x7a,0x47,0xce,0xb4,0x3a,0x7d},
   {0x7c,0x42,0xd5,0xa9,0x2d,0x6f},{0x7e,0x41,0xdc,0xa2,0x20,0x61},
   {0x80,0xc0,0x76,0xf6,0x6d,0xad},{0x82,0xc3,0x7f,0xfd,0x60,0xa3},
   {0x84,0xc6,0x64,0xe0,0x77,0xb1},{0x86,0xc5,0x6d,0xeb,0x7a,0xbf},
   {0x88,0xcc,0x52,0xda,0x59,0x95},{0x8a,0xcf,0x5b,0xd1,0x54,0x9b},
   {0x8c,0xca,0x40,0xcc,0x43,0x89},{0x8e,0xc9,0x49,0xc7,0x4e,0x87},
   {0x90,0xd8,0x3e,0xae,0x05,0xdd},{0x92,0xdb,0x37,0xa5,0x08,0xd3},
   {0x94,0xde,0x2c,0xb8,0x1f,0xc1},{0x96,0xdd,0x25,0xb3,0x12,0xcf},
   {0x98,0xd4,0x1a,0x82,0x31,0xe5},{0x9a,0xd7,0x13,0x89,0x3c,0xeb},
   {0x9c,0xd2,0x08,0x94,0x2b,0xf9},{0x9e,0xd1,0x01,0x9f,0x26,0xf7},
   {0xa0,0xf0,0xe6,0x46,0xbd,0x4d},{0xa2,0xf3,0xef,0x4d,0xb0,0x43},
   {0xa4,0xf6,0xf4,0x50,0xa7,0x51},{0xa6,0xf5,0xfd,0x5b,0xaa,0x5f},
   {0xa8,0xfc,0xc2,0x6a,0x89,0x75},{0xaa,0xff,0xcb,0x61,0x84,0x7b},
   {0xac,0xfa,0xd0,0x7c,0x93,0x69},{0xae,0xf9,0xd9,0x77,0x9e,0x67},
   {0xb0,0xe8,0xae,0x1e,0xd5,0x3d},{0xb2,0xeb,0xa7,0x15,0xd8,0x33},
   {0xb4,0xee,0xbc,0x08,0xcf,0x21},{0xb6,0xed,0xb5,0x03,0xc2,0x2f},
   {0xb8,0xe4,0x8a,0x32,0xe1,0x05},{0xba,0xe7,0x83,0x39,0xec,0x0b},
   {0xbc,0xe2,0x98,0x24,0xfb,0x19},{0xbe,0xe1,0x91,0x2f,0xf6,0x17},
   {0xc0,0xa0,0x4d,0x8d,0xd6,0x76},{0xc2,0xa3,0x44,0x86,0xdb,0x78},
   {0xc4,0xa6,0x5f,0x9b,0xcc,0x6a},{0xc6,0xa5,0x56,0x90,0xc1,0x64},
   {0xc8,0xac,0x69,0xa1,0xe2,0x4e},{0xca,0xaf,0x60,0xaa,0xef,0x40},
   {0xcc,0xaa,0x7b,0xb7,0xf8,0x52},{0xce,0xa9,0x72,0xbc,0xf5,0x5c},
   {0xd0,0xb8,0x05,0xd5,0xbe,0x06},{0xd2,0xbb,0x0c,0xde,0xb3,0x08},
   {0xd4,0xbe,0x17,0xc3,0xa4,0x1a},{0xd6,0xbd,0x1e,0xc8,0xa9,0x14},
   {0xd8,0xb4,0x21,0xf9,0x8a,0x3e},{0xda,0xb7,0x28,0xf2,0x87,0x30},
   {0xdc,0xb2,0x33,0xef,0x90,0x22},{0xde,0xb1,0x3a,0xe4,0x9d,0x2c},
   {0xe0,0x90,0xdd,0x3d,0x06,0x96},{0xe2,0x93,0xd4,0x36,0x0b,0x98},
   {0xe4,0x96,0xcf,0x2b,0x1c,0x8a},{0xe6,0x95,0xc6,0x20,0x11,0x84},
   {0xe8,0x9c,0xf9,0x11,0x32,0xae},{0xea,0x9f,0xf0,0x1a,0x3f,0xa0},
   {0xec,0x9a,0xeb,0x07,0x28,0xb2},{0xee,0x99,0xe2,0x0c,0x25,0xbc},
   {0xf0,0x88,0x95,0x65,0x6e,0xe6},{0xf2,0x8b,0x9c,0x6e,0x63,0xe8},
   {0xf4,0x8e,0x87,0x73,0x74,0xfa},{0xf6,0x8d,0x8e,0x78,0x79,0xf4},
   {0xf8,0x84,0xb1,0x49,0x5a,0xde},{0xfa,0x87,0xb8,0x42,0x57,0xd0},
   {0xfc,0x82,0xa3,0x5f,0x40,0xc2},{0xfe,0x81,0xaa,0x54,0x4d,0xcc},
   {0x1b,0x9b,0xec,0xf7,0xda,0x41},{0x19,0x98,0xe5,0xfc,0xd7,0x4f},
   {0x1f,0x9d,0xfe,0xe1,0xc0,0x5d},{0x1d,0x9e,0xf7,0xea,0xcd,0x53},
   {0x13,0x97,0xc8,0xdb,0xee,0x79},{0x11,0x94,0xc1,0xd0,0xe3,0x77},
   {0x17,0x91,0xda,0xcd,0xf4,0x65},{0x15,0x92,0xd3,0xc6,0xf9,0x6b},
   {0x0b,0x83,0xa4,0xaf,0xb2,0x31},{0x09,0x80,0xad,0xa4,0xbf,0x3f},
   {0x0f,0x85,0xb6,0xb9,0xa8,0x2d},{0x0d,0x86,0xbf,0xb2,0xa5,0x23},
   {0x03,0x8f,0x80,0x83,0x86,0x09},{0x01,0x8c,0x89,0x88,0x8b,0x07},
   {0x07,0x89,0x92,0x95,0x9c,0x15},{0x05,0x8a,0x9b,0x9e,0x91,0x1b},
   {0x3b,0xab,0x7c,0x47,0x0a,0xa1},{0x39,0xa8,0x75,0x4c,0x07,0xaf},
   {0x3f,0xad,0x6e,0x51,0x10,0xbd},{0x3d,0xae,0x67,0x5a,0x1d,0xb3},
   {0x33,0xa7,0x58,0x6b,0x3e,0x99},{0x31,0xa4,0x51,0x60,0x33,0x97},
   {0x37,0xa1,0x4a,0x7d,0x24,0x85},{0x35,0xa2,0x43,0x76,0x29,0x8b},
   {0x2b,0xb3,0x34,0x1f,0x62,0xd1},{0x29,0xb0,0x3d,0x14,0x6f,0xdf},
   {0x2f,0xb5,0x26,0x09,0x78,0xcd},{0x2d,0xb6,0x2f,0x02,0x75,0xc3},
   {0x23,0xbf,0x10,0x33,0x56,0xe9},{0x21,0xbc,0x19,0x38,0x5b,0xe7},
   {0x27,0xb9,0x02,0x25,0x4c,0xf5},{0x25,0xba,0x0b,0x2e,0x41,0xfb},
   {0x5b,0xfb,0xd7,0x8c,0x61,0x9a},{0x59,0xf8,0xde,0x87,0x6c,0x94},
   {0x5f,0xfd,0xc5,0x9a,0x7b,0x86},{0x5d,0xfe,0xcc,0x91,0x76,0x88},
   {0x53,0xf7,0xf3,0xa0,0x55,0xa2},{0x51,0xf4,0xfa,0xab,0x58,0xac},
   {0x57,0xf1,0xe1,0xb6,0x4f,0xbe},{0x55,0xf2,0xe8,0xbd,0x42,0xb0},
   {0x4b,0xe3,0x9f,0xd4,0x09,0xea},{0x49,0xe0,0x96,0xdf,0x04,0xe4},
   {0x4f,0xe5,0x8d,0xc2,0x13,0xf6},{0x4d,0xe6,0x84,0xc9,0x1e,0xf8},
   {0x43,0xef,0xbb,0xf8,0x3d,0xd2},{0x41,0xec,0xb2,0xf3,0x30,0xdc},
   {0x47,0xe9,0xa9,0xee,0x27,0xce},{0x45,0xea,0xa0,0xe5,0x2a,0xc0},
   {0x7b,0xcb,0x47,0x3c,0xb1,0x7a},{0x79,0xc8,0x4e,0x37,0xbc,0x74},
   {0x7f,0xcd,0x55,0x2a,0xab,0x66},{0x7d,0xce,0x5c,0x21,0xa6,0x68},
   {0x73,0xc7,0x63,0x10,0x85,0x42},{0x71,0xc4,0x6a,0x1b,0x88,0x4c},
   {0x77,0xc1,0x71,0x06,0x9f,0x5e},{0x75,0xc2,0x78,0x0d,0x92,0x50},
   {0x6b,0xd3,0x0f,0x64,0xd9,0x0a},{0x69,0xd0,0x06,0x6f,0xd4,0x04},
   {0x6f,0xd5,0x1d,0x72,0xc3,0x16},{0x6d,0xd6,0x14,0x79,0xce,0x18},
   {0x63,0xdf,0x2b,0x48,0xed,0x32},{0x61,0xdc,0x22,0x43,0xe0,0x3c},
   {0x67,0xd9,0x39,0x5e,0xf7,0x2e},{0x65,0xda,0x30,0x55,0xfa,0x20},
   {0x9b,0x5b,0x9a,0x01,0xb7,0xec},{0x99,0x58,0x93,0x0a,0xba,0xe2},
   {0x9f,0x5d,0x88,0x17,0xad,0xf0},{0x9d,0x5e,0x81,0x1c,0xa0,0xfe},
   {0x93,0x57,0xbe,0x2d,0x83,0xd4},{0x91,0x54,0xb7,0x26,0x8e,0xda},
   {0x97,0x51,0xac,0x3b,0x99,0xc8},{0x95,0x52,0xa5,0x30,0x94,0xc6},
   {0x8b,0x43,0xd2,0x59,0xdf,0x9c},{0x89,0x40,0xdb,0x52,0xd2,0x92},
   {0x8f,0x45,0xc0,0x4f,0xc5,0x80},{0x8d,0x46,0xc9,0x44,0xc8,0x8e},
   {0x83,0x4f,0xf6,0x75,0xeb,0xa4},{0x81,0x4c,0xff,0x7e,0xe6,0xaa},
   {0x87,0x49,0xe4,0x63,0xf1,0xb8},{0x85,0x4a,0xed,0x68,0xfc,0xb6},
   {0xbb,0x6b,0x0a,0xb1,0x67,0x0c},{0xb9,0x68,0x03,0xba,0x6a,0x02},
   {0xbf,0x6d,0x18,0xa7,0x7d,0x10},{0xbd,0x6e,0x11,0xac,0x70,0x1e},
   {0xb3,0x67,0x2e,0x9d,0x53,0x34},{0xb1,0x64,0x27,0x96,0x5e,0x3a},
   {0xb7,0x61,0x3c,0x8b,0x49,0x28},{0xb5,0x62,0x35,0x80,0x44,0x26},
   {0xab,0x73,0x42,0xe9,0x0f,0x7c},{0xa9,0x70,0x4b,0xe2,0x02,0x72},
   {0xaf,0x75,0x50,0xff,0x15,0x60},{0xad,0x76,0x59,0xf4,0x18,0x6e},
   {0xa3,0x7f,0x66,0xc5,0x3b,0x44},{0xa1,0x7c,0x6f,0xce,0x36,0x4a},
   {0xa7,0x79,0x74,0xd3,0x21,0x58},{0xa5,0x7a,0x7d,0xd8,0x2c,0x56},
   {0xdb,0x3b,0xa1,0x7a,0x0c,0x37},{0xd9,0x38,0xa8,0x71,0x01,0x39},
   {0xdf,0x3d,0xb3,0x6c,0x16,0x2b},{0xdd,0x3e,0xba,0x67,0x1b,0x25},
   {0xd3,0x37,0x85,0x56,0x38,0x0f},{0xd1,0x34,0x8c,0x5d,0x35,0x01},
   {0xd7,0x31,0x97,0x40,0x22,0x13},{0xd5,0x32,0x9e,0x4b,0x2f,0x1d},
   {0xcb,0x23,0xe9,0x22,0x64,0x47},{0xc9,0x20,0xe0,0x29,0x69,0x49},
   {0xcf,0x25,0xfb,0x34,0x7e,0x5b},{0xcd,0x26,0xf2,0x3f,0x73,0x55},
   {0xc3,0x2f,0xcd,0x0e,0x50,0x7f},{0xc1,0x2c,0xc4,0x05,0x5d,0x71},
   {0xc7,0x29,0xdf,0x18,0x4a,0x63},{0xc5,0x2a,0xd6,0x13,0x47,0x6d},
   {0xfb,0x0b,0x31,0xca,0xdc,0xd7},{0xf9,0x08,0x38,0xc1,0xd1,0xd9},
   {0xff,0x0d,0x23,0xdc,0xc6,0xcb},{0xfd,0x0e,0x2a,0xd7,0xcb,0xc5},
   {0xf3,0x07,0x15,0xe6,0xe8,0xef},{0xf1,0x04,0x1c,0xed,0xe5,0xe1},
   {0xf7,0x01,0x07,0xf0,0xf2,0xf3},{0xf5,0x02,0x0e,0xfb,0xff,0xfd},
   {0xeb,0x13,0x79,0x92,0xb4,0xa7},{0xe9,0x10,0x70,0x99,0xb9,0xa9},
   {0xef,0x15,0x6b,0x84,0xae,0xbb},{0xed,0x16,0x62,0x8f,0xa3,0xb5},
   {0xe3,0x1f,0x5d,0xbe,0x80,0x9f},{0xe1,0x1c,0x54,0xb5,0x8d,0x91},
   {0xe7,0x19,0x4f,0xa8,0x9a,0x83},{0xe5,0x1a,0x46,0xa3,0x97,0x8d}
};




//**********************************************************************************
/* Structure to hold information about a flow	*/
typedef struct ManetT_Flow_Info
	{
	int					row_index;
	OmsT_Dist_Handle	pkt_interarrival_dist_ptr;
	OmsT_Dist_Handle	pkt_size_dist_ptr;
	InetT_Address*		dest_address_ptr;
	double				stop_time;
	} ManetT_Flow_Info;



// def for handling msgs
 struct msg_info
	{
	int type;
	Prg_List * info;
	unsigned char info_arr[16];
	int rand[2];
	
	};


 


 struct coord
{
double xpos;
double ypos;
int Clusterid;
int Nodeid;
bool change;
bool New_comer;

};


 struct comer
	{
	int id;
	bool New;
	
	};

/** Function prototypes.			**/
static void				manet_rpg_sv_init (void);
static void				manet_rpg_register_self (void);
static void				manet_rpg_sent_stats_update (double pkt_size);
static void				manet_rpg_received_stats_update (double pkt_size);
static void				manet_rpg_packet_flow_info_read (void);
static void				manet_rpg_generate_packet (void);
static void				manet_rpg_packet_destroy (Packet*	pkptr);

// /new
void             		send_members(Prg_List * list);
void             		get_keys(Prg_List * list);
void                   authen_hash(comer *c);// from head
static void              re_hash   (Objid id,Prg_List * list);// sent from member to head
void                   	check_hash(Prg_List * hlist,Objid id);
void 					aes_encrypt(Prg_List * in, uchar out[], uint inkey[], int size);
void 					aes_decrypt(uchar in[], uchar out[] , uint inkey[], int keysize);
static void 			send_enc(Objid id);
void 					re_dec_clukey(uchar list[],int rand[],Objid src_id);
void 					check_ckey(uchar list[],int rand[],Objid id);

void store_newsymkeys(Prg_List * list);
void  ann_malc(int id);

void send_newc(Objid id,Prg_List * sym_list);
void send_sym_enc(Objid src_node_objid);//new dr eman
void store_dec_symkey(uchar list[],int rand[]);//new dr eman

void store_symkeys(Prg_List * list);// new comer gets new sym key

// SHA 256 fn

void sha256_transform(SHA256_CTX *ctx, unsigned char data[]);
void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, unsigned char data[],int s,int e);
void sha256_final(SHA256_CTX *ctx, unsigned char hash[]);

//************************************************************************************
//AES fns
void AddRoundKey(uchar state[][4], uint w[]);
static void SubBytes(uchar state[][4]);
void InvSubBytes(uchar state[][4]);
static void ShiftRows(uchar state[][4]);
 void InvShiftRows(uchar state[][4]);
static void MixColumns(uchar state[][4]);
void InvMixColumns(uchar state[][4]);
static uint SubWord(uint word);
static void aes_encrypt(Prg_List * in, uchar out[], uint inkey[], int size);

static void sub_div(int s,int e,uchar nid[]);
void KeyExpansion(uchar inkey[],uint w[],int size);
void printstate(uchar state[][4]);
void random();
void random_16();
void recev_msg(Objid cid);// msg recev by member (as not all members can recevie msg)
void ann_recev(Objid cid);
void ann_comer(Objid cid);
void ann_overhead(Objid src_node,int size);
void packet_destroy (Packet*	pkptr);
//*************************************************************************************

/* End of Header Block */

#if !defined (VOSD_NO_FIN)
#undef	BIN
#undef	BOUT
#define	BIN		FIN_LOCAL_FIELD(_op_last_line_passed) = __LINE__ - _op_block_origin;
#define	BOUT	BIN
#define	BINIT	FIN_LOCAL_FIELD(_op_last_line_passed) = 0; _op_block_origin = __LINE__;
#else
#define	BINIT
#endif /* #if !defined (VOSD_NO_FIN) */



/* State variable definitions */
class manet_dispatcher_cluster_state
	{
	private:
		/* Internal state tracking for FSM */
		FSM_SYS_STATE

	public:
		manet_dispatcher_cluster_state (void);

		/* Destructor contains Termination Block */
		~manet_dispatcher_cluster_state (void);

		/* State Variables */
		Objid	                  		my_objid                                        ;	/* Object identifier of the surrounding module. */
		Objid	                  		my_node_objid                                   ;	/* Object identifier of the surrounding node. */
		Objid	                  		my_subnet_objid                                 ;	/* Object identifier of the surrounding subnet. */
		Stathandle	             		local_packets_received_hndl                     ;	/* Statictic handle for local packet throughput. */
		Stathandle	             		local_bits_received_hndl                        ;	/* Statictic handle for local bit throughput. */
		Stathandle	             		local_delay_hndl                                ;	/* Statictic handle for local end-to-end delay. */
		Stathandle	             		global_packets_received_hndl                    ;	/* Statictic handle for global packet throughput. */
		Stathandle	             		global_bits_received_hndl                       ;	/* Statictic handle for global bit throughput. */
		int	                    		outstrm_to_ip_encap                             ;	/* Index of the stream to ip_encap */
		int	                    		instrm_from_ip_encap                            ;	/* Index of the stream from ip_encap */
		ManetT_Flow_Info*	      		manet_flow_info_array                           ;	/* Information of the different flows */
		int	                    		higher_layer_proto_id                           ;	/* Protocol ID assigned by IP */
		Ici*	                   		ip_encap_req_ici_ptr                            ;	/* ICI to be associated with packets being sent to ip_encap */
		Stathandle	             		local_packets_sent_hndl                         ;
		Stathandle	             		local_bits_sent_hndl                            ;
		Stathandle	             		global_packets_sent_hndl                        ;
		Stathandle	             		global_bits_sent_hndl                           ;
		Stathandle	             		global_delay_hndl                               ;
		IpT_Interface_Info*	    		iface_info_ptr                                  ;	/* IP interface information for this station node */
		double	                 		next_pkt_interarrival                           ;
		Prg_List *	             		cluster_key                                     ;
		Prg_List *	             		symmetric_key                                   ;
		unsigned char	          		outaes[16]                                      ;
		unsigned char	          		ophash[32]                                      ;
		int	                    		total_size                                      ;
		int	                    		count_recev                                     ;
		int	                    		count_comer                                     ;
		bool	                   		misbehave                                       ;
		int	                    		r1                                              ;
		int	                    		r2                                              ;
		Prg_List *	             		rand_list                                       ;
		Prg_List *	             		rand_list_16                                    ;
		Prg_List *	             		inter_list                                      ;

		/* FSM code */
		void manet_dispatcher_cluster (OP_SIM_CONTEXT_ARG_OPT);
		/* Diagnostic Block */
		void _op_manet_dispatcher_cluster_diag (OP_SIM_CONTEXT_ARG_OPT);

#if defined (VOSD_NEW_BAD_ALLOC)
		void * operator new (size_t) throw (VOSD_BAD_ALLOC);
#else
		void * operator new (size_t);
#endif
		void operator delete (void *);

		/* Memory management */
		static VosT_Obtype obtype;
	};

VosT_Obtype manet_dispatcher_cluster_state::obtype = (VosT_Obtype)OPC_NIL;

#define my_objid                		op_sv_ptr->my_objid
#define my_node_objid           		op_sv_ptr->my_node_objid
#define my_subnet_objid         		op_sv_ptr->my_subnet_objid
#define local_packets_received_hndl		op_sv_ptr->local_packets_received_hndl
#define local_bits_received_hndl		op_sv_ptr->local_bits_received_hndl
#define local_delay_hndl        		op_sv_ptr->local_delay_hndl
#define global_packets_received_hndl		op_sv_ptr->global_packets_received_hndl
#define global_bits_received_hndl		op_sv_ptr->global_bits_received_hndl
#define outstrm_to_ip_encap     		op_sv_ptr->outstrm_to_ip_encap
#define instrm_from_ip_encap    		op_sv_ptr->instrm_from_ip_encap
#define manet_flow_info_array   		op_sv_ptr->manet_flow_info_array
#define higher_layer_proto_id   		op_sv_ptr->higher_layer_proto_id
#define ip_encap_req_ici_ptr    		op_sv_ptr->ip_encap_req_ici_ptr
#define local_packets_sent_hndl 		op_sv_ptr->local_packets_sent_hndl
#define local_bits_sent_hndl    		op_sv_ptr->local_bits_sent_hndl
#define global_packets_sent_hndl		op_sv_ptr->global_packets_sent_hndl
#define global_bits_sent_hndl   		op_sv_ptr->global_bits_sent_hndl
#define global_delay_hndl       		op_sv_ptr->global_delay_hndl
#define iface_info_ptr          		op_sv_ptr->iface_info_ptr
#define next_pkt_interarrival   		op_sv_ptr->next_pkt_interarrival
#define cluster_key             		op_sv_ptr->cluster_key
#define symmetric_key           		op_sv_ptr->symmetric_key
#define outaes                  		op_sv_ptr->outaes
#define ophash                  		op_sv_ptr->ophash
#define total_size              		op_sv_ptr->total_size
#define count_recev             		op_sv_ptr->count_recev
#define count_comer             		op_sv_ptr->count_comer
#define misbehave               		op_sv_ptr->misbehave
#define r1                      		op_sv_ptr->r1
#define r2                      		op_sv_ptr->r2
#define rand_list               		op_sv_ptr->rand_list
#define rand_list_16            		op_sv_ptr->rand_list_16
#define inter_list              		op_sv_ptr->inter_list

/* These macro definitions will define a local variable called	*/
/* "op_sv_ptr" in each function containing a FIN statement.	*/
/* This variable points to the state variable data structure,	*/
/* and can be used from a C debugger to display their values.	*/
#undef FIN_PREAMBLE_DEC
#undef FIN_PREAMBLE_CODE
#define FIN_PREAMBLE_DEC	manet_dispatcher_cluster_state *op_sv_ptr;
#define FIN_PREAMBLE_CODE	\
		op_sv_ptr = ((manet_dispatcher_cluster_state *)(OP_SIM_CONTEXT_PTR->_op_mod_state_ptr));


/* Function Block */

#if !defined (VOSD_NO_FIN)
enum { _op_block_origin = __LINE__ + 2};
#endif

static void
manet_rpg_sv_init (void)
	{
	/** initializes all state variables used in this process model.	**/
	FIN (manet_rpg_sv_init ());

	/* Obtain the object identifiers for the surrounding module,	*/
	/* node and subnet.												*/
	my_objid         = op_id_self ();
	my_node_objid    = op_topo_parent (my_objid);
	my_subnet_objid  = op_topo_parent (my_node_objid);

		
	
	/* Create the ici that will be associated with packets being 	*/
	/* sent to IP.													*/
	ip_encap_req_ici_ptr = op_ici_create ("inet_encap_req");
	
	
	/* Register the local and global statictics.					*/
	
	local_packets_sent_hndl  	 = op_stat_reg ("MANET.Traffic Sent (packets/sec)",		OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL);
	local_bits_sent_hndl		 = op_stat_reg ("MANET.Traffic Sent (bits/sec)",		OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL);
	local_packets_received_hndl  = op_stat_reg ("MANET.Traffic Received (packets/sec)",	OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL);
	local_bits_received_hndl	 = op_stat_reg ("MANET.Traffic Received (bits/sec)",	OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL);
	local_delay_hndl             = op_stat_reg ("MANET.Delay (secs)",					OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL); 
	global_delay_hndl            = op_stat_reg ("MANET.Delay (secs)",					OPC_STAT_INDEX_NONE, OPC_STAT_GLOBAL); 
	global_packets_sent_hndl 	 = op_stat_reg ("MANET.Traffic Sent (packets/sec)",		OPC_STAT_INDEX_NONE, OPC_STAT_GLOBAL); 
	global_bits_sent_hndl		 = op_stat_reg ("MANET.Traffic Sent (bits/sec)",		OPC_STAT_INDEX_NONE, OPC_STAT_GLOBAL);
	global_packets_received_hndl = op_stat_reg ("MANET.Traffic Received (packets/sec)",	OPC_STAT_INDEX_NONE, OPC_STAT_GLOBAL); 
	global_bits_received_hndl	 = op_stat_reg ("MANET.Traffic Received (bits/sec)",	OPC_STAT_INDEX_NONE, OPC_STAT_GLOBAL);
	
	FOUT;
	}


static void
manet_rpg_register_self (void)
	{
	char				proc_model_name [128];
	OmsT_Pr_Handle		own_process_record_handle;
	Prohandle			own_prohandle;

	/** Get a higher layer protocol ID from IP and register this 	**/
	/** process in the model-wide process registry to be discovered **/
	/** by the lower layer.											**/
	FIN (rpg_dispatcher_register_self ());

	/* Register RPG as a higher layer protocol over IP layer 		*/
	/* and retrieve an auto-assigned protocol id.					*/
   	higher_layer_proto_id = IpC_Protocol_Unspec;
	Ip_Higher_Layer_Protocol_Register ("rpg", &higher_layer_proto_id);
	
	/* Obtain the process model name and process handle.			*/
	op_ima_obj_attr_get (my_objid, "process model", proc_model_name);
	own_prohandle = op_pro_self ();

	/* Register this process in the model-wide process registry		*/
	own_process_record_handle = (OmsT_Pr_Handle) oms_pr_process_register 
		(my_node_objid, my_objid, own_prohandle, proc_model_name);

	/* Set the protocol attribute to the same string we used in	*/
	/* Ip_Higher_Layer_Protocol_Register. Necessary for ip_encap*/
	/* to discover this process. Set the module object id also.	*/
	oms_pr_attr_set (own_process_record_handle,
					 "protocol", 		OMSC_PR_STRING, "rpg",
					 "module objid",	OMSC_PR_OBJID,	my_objid,
			 		 OPC_NIL);
	FOUT;
	}


static void
manet_rpg_sent_stats_update (double size)
	{
	/** This function updates the local and global statictics		**/
	/** related with packet sending.								**/
	FIN (manet_rpg_sent_stats_update (<args>));

	/* Update the local and global sent statistics.					*/
	op_stat_write (local_bits_sent_hndl,     size);
	op_stat_write (local_bits_sent_hndl,     0.0);
	op_stat_write (local_packets_sent_hndl,  1.0);
	op_stat_write (local_packets_sent_hndl,  0.0);
	op_stat_write (global_bits_sent_hndl,    size);
	op_stat_write (global_bits_sent_hndl,    0.0);
	op_stat_write (global_packets_sent_hndl, 1.0);
	op_stat_write (global_packets_sent_hndl, 0.0);
	
	FOUT;
	}

static void
manet_rpg_received_stats_update (double size)
	{
	/** This function updates the local and global statictics		**/
	/** related with packet sending.								**/
	FIN (manet_rpg_received_stats_update (<args>));

	/* Update the local and global sent statistics.					*/
	op_stat_write (local_bits_received_hndl,     size);
	op_stat_write (local_bits_received_hndl,     0.0);
	op_stat_write (local_packets_received_hndl,  1.0);
	op_stat_write (local_packets_received_hndl,  0.0);
	op_stat_write (global_bits_received_hndl,    size);
	op_stat_write (global_bits_received_hndl,    0.0);
	op_stat_write (global_packets_received_hndl, 1.0);
	op_stat_write (global_packets_received_hndl, 0.0);
	
	FOUT;
	}


static void
manet_rpg_packet_flow_info_read (void)
	{
	int							i, row_count;
	char						temp_str [256];
	char						interarrival_str [256];
	char						pkt_size_str [256];
	char						log_message_str [256];
	Objid						trafgen_params_comp_objid;
	Objid						ith_flow_attr_objid;
	double						start_time;
	InetT_Address*				dest_address_ptr;
	InetT_Address				dest_address;
	static OmsT_Log_Handle		manet_traffic_generation_log_handle;
	static Boolean				manet_traffic_generation_log_handle_not_created = OPC_TRUE;

	/** Read in the attributes for each flow	**/
	FIN (manet_rpg_packet_flow_info_read (void));

	/* Get a handle to the Traffic Generation Parameters compound attribute.*/
	op_ima_obj_attr_get (my_objid, "Traffic Generation Parameters", &trafgen_params_comp_objid);

	/* Obtain the row count 												*/
	row_count = op_topo_child_count (trafgen_params_comp_objid, OPC_OBJTYPE_GENERIC);

	/* If there are no flows specified, exit from the function				*/
	if (row_count == 0)
		{
		FOUT;
		}

	/* Allocate enough memory to hold all the information.					*/
	manet_flow_info_array = (ManetT_Flow_Info*) op_prg_mem_alloc (sizeof (ManetT_Flow_Info) * row_count);

	/* Loop through each row and read in the information specified.			*/
	for (i = 0; i < row_count; i++)
		{
		/* Get the object ID of the associated row for the ith child.		*/
		ith_flow_attr_objid = op_topo_child (trafgen_params_comp_objid, OPC_OBJTYPE_GENERIC, i);

		/* Read in the start time and stop times */
		op_ima_obj_attr_get (ith_flow_attr_objid, "Start Time", &start_time);
		op_ima_obj_attr_get (ith_flow_attr_objid, "Stop Time", &manet_flow_info_array [i].stop_time);

		/* Read in the packet inter-arrival time and packet size 			*/
		op_ima_obj_attr_get (ith_flow_attr_objid, "Packet Inter-Arrival Time", interarrival_str);
		op_ima_obj_attr_get (ith_flow_attr_objid, "Packet Size", pkt_size_str);

		/* Set the distribution handles	*/
		manet_flow_info_array [i].pkt_interarrival_dist_ptr = oms_dist_load_from_string (interarrival_str);
		manet_flow_info_array [i].pkt_size_dist_ptr = oms_dist_load_from_string (pkt_size_str);
	
		/* Read in the destination IP address.								*/
		op_ima_obj_attr_get (ith_flow_attr_objid, "Destination IP Address", temp_str);
		
		if (strcmp (temp_str, "auto assigned"))
			{
			/* Explicit destination address has been assigned	*/
			dest_address = inet_address_create (temp_str, InetC_Addr_Family_Unknown);
			manet_flow_info_array [i].dest_address_ptr = inet_address_create_dynamic (dest_address);
			inet_address_destroy (dest_address);
			}
		else
			{
			/* The destination address is set to auto-assigned	*/
			/* Choose a random destination address				*/
			dest_address_ptr = manet_rte_dest_ip_address_obtain (iface_info_ptr);
			manet_flow_info_array [i].dest_address_ptr = dest_address_ptr;
			if (dest_address_ptr == OPC_NIL)
				{
				/* Write a simulation log		*/
				char					my_node_name [64];
				
				op_ima_obj_attr_get_str (my_node_objid, "name", 64, my_node_name);
				
				if (manet_traffic_generation_log_handle_not_created)
					{
					manet_traffic_generation_log_handle = oms_log_handle_create (OpC_Log_Category_Configuration, "MANET", "Traffic Setup", 32, 0,
						"WARNING:\n"
						"The following list of MANET traffic sources do not have valid destinations:\n\n"
						"Node name						Traffic row index\n"
						"-----------------				--------------------\n",
						"SUGGESTION(S):\n" 
						"Make sure that 1 or more prefixes are available for the MANET source to send its traffic to.\n\n"
						"RESULT(S):\n"
						"No Traffic will be generated at the MANET source.");
					
					manet_traffic_generation_log_handle_not_created = OPC_FALSE;
					}
				
				sprintf (log_message_str, "%s\t\t\t\t\t\t\t%d\n", my_node_name, i);
				oms_log_message_append (manet_traffic_generation_log_handle, log_message_str);
 				}
			}
		
		/* Schedule an interrupt for the start time of this flow.			*/
		/* Use the row index as the interrupt code, so that we can handle	*/
		/* the interrupt correctly.											*/
		op_intrpt_schedule_self (start_time, i);
		}

	FOUT;
	}
static void
manet_rpg_generate_packet (void)
	{
	int				row_num;
	double			schedule_time;
	double			pksize;
	Packet*			pkt_ptr;
	InetT_Address	src_address;
	InetT_Address*	src_addr_ptr;
	InetT_Address*	copy_address_ptr;
	double   tf_scaling_factor = 1;
	
	
	
	/** A packet needs to be generated for a particular flow	**/
	/** Generate the packet of an appropriate size and send it	**/
	/** to IP. Also schedule an event for the next packet		**/
	/** generation time for this flow.							**/
	FIN (manet_rpg_generate_packet (void));
	
	
	
	/* Identify the right packet flow using the interrupt code	*/
	row_num = op_intrpt_code ();
	
	/* If no destination was found, exit						*/
	if (manet_flow_info_array [row_num].dest_address_ptr == OPC_NIL)
		FOUT;
	
	/* Schedule a self interrupt for the next packet generation	*/
	/* time. The netx packet generation time will be the current*/
	/* time + the packet inter-arrival time. The interrupt code	*/
	/* will be the row number.									*/
	tf_scaling_factor = Oms_Sim_Attr_Traffic_Scaling_Get ();
	next_pkt_interarrival = (oms_dist_nonnegative_outcome (manet_flow_info_array [row_num].pkt_interarrival_dist_ptr)) / (tf_scaling_factor);
	schedule_time = op_sim_time () + next_pkt_interarrival;
	
	/* Schedule the next inter-arrival if it is less than the	*/
	/* stop time for the flow									*/
	if ((manet_flow_info_array [row_num].stop_time == -1.0) ||
		(schedule_time < manet_flow_info_array [row_num].stop_time))
		{
		op_intrpt_schedule_self (op_sim_time () + next_pkt_interarrival, row_num);
		}

	/* Create an unformatted packet	*/
	pksize = (double) ceil (oms_dist_outcome (manet_flow_info_array [row_num].pkt_size_dist_ptr));
	
	/* Size of the packet must be a multiple of 8. The extra bits will not be modeled		*/
	pksize = pksize - fmod (pksize, 8.0);

	
	pkt_ptr = op_pk_create (pksize);
	
	
	
	
	/* Update the packet sent statistics	*/
	manet_rpg_sent_stats_update (pksize);
	
	/* Make a copy of the destination address	*/
	/* and set it in the ICI for ip_encap		*/
	copy_address_ptr = manet_flow_info_array [row_num].dest_address_ptr;
	
	/* Set the destination address in the ICI */
	op_ici_attr_set (ip_encap_req_ici_ptr, "dest_addr", copy_address_ptr);
	
	/* Set the source address of this node based on the	*/
	/* IP address family of the destination				*/
	if (inet_address_family_get (copy_address_ptr) == InetC_Addr_Family_v6)
		{
		/* The destination is a IPv6 address	*/
		/* Set the IPv6 source address			*/
		src_address = inet_rte_intf_addr_get (iface_info_ptr, InetC_Addr_Family_v6);
		}
	else
		{
		/* The destination is a IPv4 address	*/
		/* Set the IPv4 source address			*/
		src_address = inet_rte_intf_addr_get (iface_info_ptr, InetC_Addr_Family_v4);
		}
	
	/* Create the source address	*/
	src_addr_ptr = inet_address_create_dynamic (src_address);
	
	/* Set the source address in the ICI	*/
	op_ici_attr_set (ip_encap_req_ici_ptr, "src_addr", src_addr_ptr);

	/* install the ICI */
	op_ici_install (ip_encap_req_ici_ptr);
	
	/* Send the packet to ip_encap	*/
	
	/* Since we are reusing the ici we should use				*/
	/* op_pk_send_forced. Otherwise if two flows generate a 	*/
	/* packet at the same time, the second packet genration will*/
	/* overwrite the ici before the first packet is processed by*/
	/* ip_encap.												*/
	op_pk_send_forced (pkt_ptr, outstrm_to_ip_encap);
	
	
	/* Destroy the temorpary source address	*/
	inet_address_destroy_dynamic (src_addr_ptr);
	
	/* Uninstall the ICI */
	op_ici_install (OPC_NIL);
	
	FOUT;
	}

static void
manet_rpg_packet_destroy (Packet*	pkptr)//new 
	{

	double			delay;
	double			pk_size;
	

	/** Get a packet from IP and destroy it. Destroy	**/
	/** the accompanying ici also.						**/
	FIN (manet_rpg_packet_destroy (Packet*	pkptr));
	
	
	/* Remove the packet from stream	*/
	//pkptr = op_pk_get (instrm_from_ip_encap);
	
	/* Update the "Traffic Received" statistics	*/
	pk_size = (double) op_pk_total_size_get (pkptr);
	
	/* Update the statistics for the packet received	*/
	manet_rpg_received_stats_update (pk_size);
	
	/* Compute the delay	*/
	delay = op_sim_time () - op_pk_creation_time_get (pkptr);
	
	/* Update the "Delay" statistic	*/
	op_stat_write (local_delay_hndl, delay);
	op_stat_write (global_delay_hndl, delay);

	op_ici_destroy (op_intrpt_ici ());
	op_pk_destroy (pkptr);
	
	FOUT;
	}
void packet_destroy(Packet*	pkptr)//new 
	{

	double			delay;
	double			pk_size;
	

	/** Get a packet from IP and destroy it. Destroy	**/
	/** the accompanying ici also.						**/
	FIN (packet_destroy (<args>));
	
	
	/* Remove the packet from stream	*/
	//pkptr = op_pk_get (instrm_from_ip_encap);
	
	/* Update the "Traffic Received" statistics	*/
	pk_size = (double) op_pk_total_size_get (pkptr);
	//cout<<pk_size<<"\n";
	
	/* Update the statistics for the packet received	*/
	//manet_rpg_received_stats_update (pk_size);
	
	/* Compute the delay	*/
	delay = op_sim_time () - op_pk_creation_time_get (pkptr);
	
	/* Update the "Delay" statistic	*/
	op_stat_write (local_delay_hndl, delay);
	op_stat_write (global_delay_hndl, delay);

	//op_ici_destroy (op_intrpt_ici ());
	op_pk_destroy (pkptr);
	
	FOUT;
	}

void send_members (Prg_List * list)	// if node is head
{
	//new
	InetT_Address   dest_address;
	IpT_Interface_Info** my_dest_ip;
	InetT_Address	src_address;
	InetT_Address*	src_addr_ptr;
	InetT_Address*	copy_address_ptr;
	int  /*j,*/co=0;
	Objid procid;
	Packet * pktptr;
	comer * c;
	//new
	uchar  sub_nid[16]={0x00};
	uint exp[44]={0};
	int *x,*y;
	double size;
	// stop
	
	Objid	objid         = op_id_self ();
	Objid	node_objid    = op_topo_parent (objid);

	FIN(send_members (<args>));
		
	//cout<<"in send "<<prg_list_size(list)<<"\n";	 

	for(int i=32;i<prg_list_size(list);i++)
	{
		msg_info *msg=new msg_info();	
			
		msg->type=key;
		
		
		msg->info=prg_list_create();
		prg_list_init(msg->info);

		
		/*for(j=0;j<16;j++)//access  symkey sent from db node
		{
		ch=(unsigned char *)prg_list_access(list,j+16); 
		
		prg_list_insert(msg->info,ch,j);
			//printf("%x",*ch);
		
		}*/
		////////////////////////////////////////////////////////////////////////
		//for new re_enc
		random_16();// generate 2 numbers diff between them is 32
			
		x=(int *)prg_list_access(rand_list_16,0);
		y=(int *)prg_list_access(rand_list_16,1);
		sub_div(*x,*y,sub_nid);
		KeyExpansion(sub_nid,exp,128);
		/*for(int j=0;j<16;j++)
				{
				ch=(uchar *)prg_list_access(symmetric_key,j);// access symkey
				
				printf("%x",*ch);
				
				}*/
		
		aes_encrypt(symmetric_key,outaes,exp,128);
		for(int k=0;k<16;k++)
			{
			msg->info_arr[k]=outaes[k];
		
			//printf("%x",outaes[i]);
			}
		msg->rand[0]=*x;
		msg->rand[1]=*y;
		
		///////////////////////////////////////////////////////////////////////////
		//pktptr=op_pk_create(size);comment
		pktptr=op_pk_create(0);
	
		op_pk_fd_set (pktptr, 0, OPC_FIELD_TYPE_STRUCT, msg, sizeof(msg_info)*8,op_prg_mem_copy_create,op_prg_mem_free,sizeof(msg_info));		
		c=(comer *)prg_list_access(list,i);
		
		if(c->New)
			{
			//cout<<"new comer"<<c->id<<"\n";
			
			authen_hash(c);
			
			}	
		else// if not new comer
		{
		
		
		procid = op_id_from_name(c->id,OPC_OBJTYPE_PROC,"traf_src");
	
		
		my_dest_ip = (IpT_Interface_Info**) op_ima_obj_svar_get(procid , "iface_info_ptr");
		
		if (ip_rte_intf_ip_version_active (*my_dest_ip, InetC_Addr_Family_v6) == OPC_TRUE)  
		{
			
			dest_address = inet_rte_intf_addr_get (*my_dest_ip, InetC_Addr_Family_v6);
			
		}
	else
		{
			
			dest_address = inet_rte_intf_addr_get (*my_dest_ip, InetC_Addr_Family_v4);
			//cout<<dest_address.address.ipv4_addr<<"\n";
			}
	
		copy_address_ptr = &dest_address;
	

	op_ici_attr_set (ip_encap_req_ici_ptr, "dest_addr", copy_address_ptr);
	
	
	if (inet_address_family_get (copy_address_ptr) == InetC_Addr_Family_v6)
		{
		
		src_address = inet_rte_intf_addr_get (iface_info_ptr, InetC_Addr_Family_v6);
		}
	else

		{
		
		src_address = inet_rte_intf_addr_get (iface_info_ptr, InetC_Addr_Family_v4);
		}
	
	
		src_addr_ptr = inet_address_create_dynamic (src_address);
		op_ici_attr_set (ip_encap_req_ici_ptr, "src_addr", src_addr_ptr);
		op_ici_install (ip_encap_req_ici_ptr);
	
		op_pk_send_forced (pktptr,outstrm_to_ip_encap);
		
		//op_pk_deliver(pktptr,procid,0);
	size=(32*3)+(16*8);
	manet_rpg_sent_stats_update (size);
		inet_address_destroy_dynamic (src_addr_ptr);
	
	
			op_ici_install (OPC_NIL);
	
		}

		}
	
	//cout<<"count"<<count_recev<<"\n";
	//count_recev=0;
		FOUT;
		
	
}
 void get_keys(Prg_List * list)// if node is member
	{
	
	
	FIN (get_keys (args<>));
	
	unsigned char * ch;

	Objid my_id         = op_id_self ();
	Objid node_objid    = op_topo_parent (my_objid);
	//cout<<"in get"<<"\n";

	for(int i=0;i<16;i++)
	{
	ch=(unsigned char *)prg_list_access(list,i);
	prg_list_insert(symmetric_key,ch,i);// store symm only
	//printf("%x",*ch);
	}
	//cout<<"\n";
	
	
	
	
	
	/*if(node_objid==2)
		{
		cout<<"in get key"<<" ";
	for(int l=16;l<prg_list_size(list);l++)
			{
			ch=(uchar *)prg_list_access(list,l);
					printf("%x",*ch);
			}
			cout<<"\n";
			}*/
		
	//cout<<node_objid<<"  "<<"stored"<<"\n";
	//size=32/*+(16*8)*/+(16*8);comment
				
			//manet_rpg_received_stats_update (size);comment
				
			
	FOUT;
	
	
	}
 
void authen_hash(comer * c)// take new comer struct to send to them request for auth
{
	Objid procid;
	Packet *pkt;
	int *x;
	
	msg_info * msg;
	double size;
	Objid	objid         = op_id_self ();
	Objid	node_objid    = op_topo_parent (objid);
	InetT_Address   dest_address;
	IpT_Interface_Info** my_dest_ip;
	InetT_Address	src_address;
	InetT_Address*	src_addr_ptr;
	InetT_Address*	copy_address_ptr;
	FIN(authen_hash(<args>));
	msg=new msg_info();
	msg->type=auth_hash;
	msg->info=prg_list_create();
	random();
	//cout<<"in head "<<node_objid<<"\n";
		x=(int *)prg_list_access(rand_list,0);
		prg_list_insert(msg->info,x,0);
		x=(int *)prg_list_access(rand_list,1);
		prg_list_insert(msg->info,x,1);
	size=32*3;		
	
	pkt=op_pk_create(0);
	procid = op_id_from_name(c->id,OPC_OBJTYPE_PROC,"traf_src");
	op_pk_fd_set (pkt, 0, OPC_FIELD_TYPE_STRUCT, msg, sizeof(msg_info)*8,op_prg_mem_copy_create,op_prg_mem_free,sizeof(msg_info));
		procid = op_id_from_name(c->id,OPC_OBJTYPE_PROC,"traf_src");
		
		my_dest_ip = (IpT_Interface_Info**) op_ima_obj_svar_get(procid , "iface_info_ptr");
		
		if (ip_rte_intf_ip_version_active (*my_dest_ip, InetC_Addr_Family_v6) == OPC_TRUE)  
		{
			
			dest_address = inet_rte_intf_addr_get (*my_dest_ip, InetC_Addr_Family_v6);
			
		}
	else
		{
			
			dest_address = inet_rte_intf_addr_get (*my_dest_ip, InetC_Addr_Family_v4);
			//cout<<dest_address.address.ipv4_addr<<"\n";
			}
	
		copy_address_ptr = &dest_address;
	

	op_ici_attr_set (ip_encap_req_ici_ptr, "dest_addr", copy_address_ptr);
	
	
	if (inet_address_family_get (copy_address_ptr) == InetC_Addr_Family_v6)
		{
		
		src_address = inet_rte_intf_addr_get (iface_info_ptr, InetC_Addr_Family_v6);
		}
	else

		{
		
		src_address = inet_rte_intf_addr_get (iface_info_ptr, InetC_Addr_Family_v4);
		}
	
	
		src_addr_ptr = inet_address_create_dynamic (src_address);
		op_ici_attr_set (ip_encap_req_ici_ptr, "src_addr", src_addr_ptr);
		op_ici_install (ip_encap_req_ici_ptr);
	
		op_pk_send_forced (pkt,outstrm_to_ip_encap);
		//op_pk_deliver(pkt,procid,0);
		manet_rpg_sent_stats_update (size);
		inet_address_destroy_dynamic (src_addr_ptr);
		op_ici_install (OPC_NIL);						 		

	FOUT;
	 
}

void re_hash(Objid id,Prg_List * list)// member reply auth hash to head
	{
		
	Packet * pkt;
	Objid procid;
	unsigned char * ch;
	
	SHA256_CTX * ctx;
	msg_info * msg;
	int *x,*y;
	FIN(re_hash(<args>));
	Objid	objid         = op_id_self ();
	Objid	node_objid    = op_topo_parent (objid);

	msg=new msg_info;
	msg->info=prg_list_create();
	prg_list_init(msg->info);
	ctx=new SHA256_CTX();
	sha256_init(ctx);
	
	x=(int*)prg_list_access(list,0);
	y=(int*)prg_list_access(list,1);
	//cout<<"in re hash"<<node_objid<<"\n";//" "<<*x<<" "<<*y<<
   sha256_update(ctx,Nid,*x,*y+1);
   sha256_final(ctx,ophash);
	for(int i=0;i<32;i++)// copy hashed value into list
		{
		//ch=new unsigned char;
		ch=&ophash[i];
		prg_list_insert(msg->info,ch,i);
		}
		

		prg_list_insert(msg->info,x,32);
		prg_list_insert(msg->info,y,33);
		
	
		msg->type=re_hashed;
		pkt=op_pk_create(0);
		procid = op_id_from_name(id,OPC_OBJTYPE_PROC,"traf_src");
		
		op_pk_fd_set (pkt, 0, OPC_FIELD_TYPE_STRUCT, msg, sizeof(msg_info)*8,op_prg_mem_copy_create,op_prg_mem_free,sizeof(msg_info));
	
	
		op_pk_deliver(pkt,procid,0);
			manet_rpg_sent_stats_update (32.0+(32.0*8.0));
	 
	FOUT;
	
	}


void check_hash(Prg_List* hlist,Objid id)// head check sent hashed value
	{
	
		
	bool hashval=true;

	unsigned char *ch;
	SHA256_CTX * ctx;
	int *x,*y;
		FIN (check_hash(<args>));
	Objid	objid         = op_id_self ();
	Objid	node_objid    = op_topo_parent (objid);  
	char nam[20];
	ctx=new SHA256_CTX();
	sha256_init(ctx);
	x=(int*)prg_list_access(hlist,32);
	y=(int*)prg_list_access(hlist,33);
	//cout<<"in check hash  "<<node_objid<<"\n";
   sha256_update(ctx,Nid,*x,*y+1);
   sha256_final(ctx,ophash);
	
	
		
		//cout<<*x<<" "<<*y<<"\n";
		
		/*for(int i=0;i<32;i++)// 
		{
		
		printf("%x",ophash[i]);
		}
			
		cout<<"\n";*/
	for(int i=0;i<32;i++)
			{
			ch=(unsigned char *)prg_list_access(hlist,i);
			if(ophash[i]==*ch)
				
				continue;
			else
				{
				hashval=false;
				//cout<<"malicheck "<<id<<"\n";
				break;	
				
				}
			
			}
	if(hashval)
		{
		//cout<<"true "<<"\n";
		send_enc(id);
		 
		}
			
else
	{
	ann_malc(id);
	op_ima_obj_attr_get (id,"name" , nam);
	//cout<<"error"<<id<<nam<<"\n";
	}
	FOUT;

	}
void send_enc(Objid src_node_objid)
	{
	
	Packet * pkt;
	Objid procid;
	msg_info * msg;
	uchar  sub_nid[16]={0x00};
	uint exp[44]={0};
	int *x,*y;
	double size;
	
	FIN(send_enc(<args>));
	
	msg=new msg_info();
	
	random_16();// generate 2 numbers diff between them is 32
			
	x=(int *)prg_list_access(rand_list_16,0);
	y=(int *)prg_list_access(rand_list_16,1);
		//cout<<" random in send enc"<<*x<<"  "<<*y<<"\n";
		sub_div(*x,*y,sub_nid);
		KeyExpansion(sub_nid,exp,128);
		aes_encrypt(cluster_key,outaes,exp,128);
	//cout<<" enc clkey in send enc"<<"\n";
		for(int i=0;i<16;i++)
			{
			msg->info_arr[i]=outaes[i];
		
	//		printf("%x",outaes[i]);
			}
			//cout<<"\n";
	//cout<<"\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\"<<"\n";*/
		msg->rand[0]=*x;
		msg->rand[1]=*y;
		msg->type=re_keys;
		pkt=op_pk_create(0);
		procid = op_id_from_name(src_node_objid,OPC_OBJTYPE_PROC,"traf_src");
		
		op_pk_fd_set (pkt, 0, OPC_FIELD_TYPE_STRUCT, msg, sizeof(msg_info)*8,op_prg_mem_copy_create,op_prg_mem_free,sizeof(msg_info));
		
	
		//cout<<"encsize"<<"  "<<enc_size<<"\n";
	
		//cout<<"total after send enc "<<total_size<<"\n";
		size=(32*3)+(16*8);
		op_pk_deliver(pkt,procid,0);
			manet_rpg_sent_stats_update (size);
		FOUT;
		
	}

//neww dr eman
void send_sym_enc(Objid src_node_objid)
	{
	
	Packet * pkt;
	Objid procid;
	unsigned char * ch;
	msg_info * msg;
	uchar  sub_nid[16]={0x00};
	uint exp[44]={0};
	int *x,*y;
	double size;
	
	FIN(send_sym_enc(<args>));
	
	msg=new msg_info();
	//msg->info=prg_list_create();
	//prg_list_init(msg->info);
	random_16();// generate 2 numbers diff between them is 32
			
	x=(int *)prg_list_access(rand_list_16,0);
	y=(int *)prg_list_access(rand_list_16,1);
	//cout<<"org sym"<<"\n";
	for(int j=0;j<16;j++)//access symkey sent from db node
		{
		ch=(unsigned char *)prg_list_access(symmetric_key,j); 
		
		//printf("%x",*ch);
		
		}
		//cout<<"\n";
		sub_div(*x,*y,sub_nid);
		KeyExpansion(sub_nid,exp,128);
		aes_encrypt(symmetric_key,outaes,exp,128);
		//cout<<"enc sym"<<"\n";
		for(int i=0;i<16;i++)
			{
			msg->info_arr[i]=outaes[i];
		
			//printf("%x",outaes[i]);
			}
			//cout<<"\n";
	
	/*for(int j=0;j<16;j++)//access symkey sent from db node
		{
		 
		
		//printf("%x",outaes[j]);
		
		}*/
		//cout<<"\n";
		msg->rand[0]=*x;
		msg->rand[1]=*y;
		msg->type=re_encsymkey;
		pkt=op_pk_create(0);
		procid = op_id_from_name(src_node_objid,OPC_OBJTYPE_PROC,"traf_src");
		
		op_pk_fd_set (pkt, 0, OPC_FIELD_TYPE_STRUCT, msg, sizeof(msg_info)*8,op_prg_mem_copy_create,op_prg_mem_free,sizeof(msg_info));
		
	
		//cout<<"encsize"<<"  "<<enc_size<<"\n";
	
		//cout<<"total after send enc "<<total_size<<"\n";
		size=(32*3)+(16*8);//modify
		op_pk_deliver(pkt,procid,0);
			manet_rpg_sent_stats_update (size);
		FOUT;
		
	}



//^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
//SHA256 fn

void sha256_transform(SHA256_CTX *ctx, unsigned char data[])
{  
   unsigned int a,b,c,d,e,f,g,h,i,j,t1,t2,m[64];
      
   for (i=0,j=0; i < 16; ++i, j += 4)//take 4 bytes
      m[i] = (data[j] << 24) | (data[j+1] << 16) | (data[j+2] << 8) | (data[j+3]);//divide into 4 bytes blocks
   for ( ; i < 64; ++i)
      m[i] = SIG1(m[i-2]) + m[i-7] + SIG0(m[i-15]) + m[i-16];

   a = ctx->state[0];
   b = ctx->state[1];
   c = ctx->state[2];
   d = ctx->state[3];
   e = ctx->state[4];
   f = ctx->state[5];
   g = ctx->state[6];
   h = ctx->state[7];
   
   for (i = 0; i < 64; ++i) {
      t1 = h + EP1(e) + CH(e,f,g) + k[i] + m[i];
      t2 = EP0(a) + MAJ(a,b,c);
      h = g;
      g = f;
      f = e;
      e = d + t1;
      d = c;
      c = b;
      b = a;
      a = t1 + t2;
   }
   
   ctx->state[0] += a;
   ctx->state[1] += b;
   ctx->state[2] += c;
   ctx->state[3] += d;
   ctx->state[4] += e;
   ctx->state[5] += f;
   ctx->state[6] += g;
   ctx->state[7] += h;
}  


////////////////////////////////////////////////////////////////////////////////
//1)intial hash value
void sha256_init(SHA256_CTX *ctx)
{  
   ctx->datalen = 0; 
   ctx->bitlen[0] = 0; 
   ctx->bitlen[1] = 0; 
   ctx->state[0] = 0x6a09e667;//H0
   ctx->state[1] = 0xbb67ae85;
   ctx->state[2] = 0x3c6ef372;
   ctx->state[3] = 0xa54ff53a;
   ctx->state[4] = 0x510e527f;
   ctx->state[5] = 0x9b05688c;
   ctx->state[6] = 0x1f83d9ab;
   ctx->state[7] = 0x5be0cd19;//H7
}

void sha256_update(SHA256_CTX *ctx, unsigned char data[],int s,int e)
{  

   unsigned int i;
   
   for (i=s; i < e; ++i) { 
      ctx->data[ctx->datalen] = data[i]; 
      ctx->datalen++; 
      if (ctx->datalen == 64) { 
         sha256_transform(ctx,ctx->data);
         DBL_INT_ADD(ctx->bitlen[0],ctx->bitlen[1],512); 
         ctx->datalen = 0; 
      }  
   }  
}  

void sha256_final(SHA256_CTX *ctx, unsigned char hash[])
{  
   unsigned int i; 
   
   i = ctx->datalen; 
   
   // Pad whatever data is left in the buffer. 
   if (ctx->datalen < 56) { 
      ctx->data[i++] = 0x80; 
      while (i < 56) 
         ctx->data[i++] = 0x00; 
   }  
   else { 
      ctx->data[i++] = 0x80; 
      while (i < 64) 
         ctx->data[i++] = 0x00; 
      sha256_transform(ctx,ctx->data);
      memset(ctx->data,0,56); 
   }  
   
   // Append to the padding the total message's length in bits and transform. 
   DBL_INT_ADD(ctx->bitlen[0],ctx->bitlen[1],ctx->datalen * 8);
   ctx->data[63] = ctx->bitlen[0]; 
   ctx->data[62] = ctx->bitlen[0] >> 8; 
   ctx->data[61] = ctx->bitlen[0] >> 16; 
   ctx->data[60] = ctx->bitlen[0] >> 24; 
   ctx->data[59] = ctx->bitlen[1]; 
   ctx->data[58] = ctx->bitlen[1] >> 8; 
   ctx->data[57] = ctx->bitlen[1] >> 16;  
   ctx->data[56] = ctx->bitlen[1] >> 24; 
   sha256_transform(ctx,ctx->data);
   
   // Since this implementation uses little endian byte ordering and SHA uses big endian,
   // reverse all the bytes when copying the final state to the output hash. 
   for (i=0; i < 4; ++i) { 
      hash[i]    = (ctx->state[0] >> (24-i*8)) & 0x000000ff; 
      hash[i+4]  = (ctx->state[1] >> (24-i*8)) & 0x000000ff; 
      hash[i+8]  = (ctx->state[2] >> (24-i*8)) & 0x000000ff;
      hash[i+12] = (ctx->state[3] >> (24-i*8)) & 0x000000ff;
      hash[i+16] = (ctx->state[4] >> (24-i*8)) & 0x000000ff;
      hash[i+20] = (ctx->state[5] >> (24-i*8)) & 0x000000ff;
      hash[i+24] = (ctx->state[6] >> (24-i*8)) & 0x000000ff;
      hash[i+28] = (ctx->state[7] >> (24-i*8)) & 0x000000ff;
   }  
}  


//^^^^^^^^^^^^^^^**********************************^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
//AES fn

void AddRoundKey(uchar state[][4], uint w[])
{
   uchar subkey[4];
   // memcpy(subkey,&w[idx],4); // Not accurate for big endian machines
   // Subkey 1
   subkey[0] = w[0] >> 24;
   subkey[1] = w[0] >> 16;
   subkey[2] = w[0] >> 8;
   subkey[3] = w[0];
   state[0][0] ^= subkey[0];
   state[1][0] ^= subkey[1];
   state[2][0] ^= subkey[2];
   state[3][0] ^= subkey[3];
   // Subkey 2
   subkey[0] = w[1] >> 24;
   subkey[1] = w[1] >> 16;
   subkey[2] = w[1] >> 8;
   subkey[3] = w[1];
   state[0][1] ^= subkey[0];
   state[1][1] ^= subkey[1];
   state[2][1] ^= subkey[2];
   state[3][1] ^= subkey[3];
   // Subkey 3
   subkey[0] = w[2] >> 24;
   subkey[1] = w[2] >> 16;
   subkey[2] = w[2] >> 8;
   subkey[3] = w[2];
   state[0][2] ^= subkey[0];
   state[1][2] ^= subkey[1];
   state[2][2] ^= subkey[2];
   state[3][2] ^= subkey[3];
   // Subkey 4
   subkey[0] = w[3] >> 24;
   subkey[1] = w[3] >> 16;
   subkey[2] = w[3] >> 8;
   subkey[3] = w[3];
   state[0][3] ^= subkey[0];
   state[1][3] ^= subkey[1];
   state[2][3] ^= subkey[2];
   state[3][3] ^= subkey[3];
   //cout<<"addround"<<"\n";
   //printstate(state);
}
////////////////////////////////////////////////////////////////////////////////////

void SubBytes(uchar state[][4])
{
   state[0][0] = aes_sbox[state[0][0] >> 4][state[0][0] & 0x0F];
   state[0][1] = aes_sbox[state[0][1] >> 4][state[0][1] & 0x0F];
   state[0][2] = aes_sbox[state[0][2] >> 4][state[0][2] & 0x0F];
   state[0][3] = aes_sbox[state[0][3] >> 4][state[0][3] & 0x0F];
   
   state[1][0] = aes_sbox[state[1][0] >> 4][state[1][0] & 0x0F];
   state[1][1] = aes_sbox[state[1][1] >> 4][state[1][1] & 0x0F];
   state[1][2] = aes_sbox[state[1][2] >> 4][state[1][2] & 0x0F];
   state[1][3] = aes_sbox[state[1][3] >> 4][state[1][3] & 0x0F];

   state[2][0] = aes_sbox[state[2][0] >> 4][state[2][0] & 0x0F];
   state[2][1] = aes_sbox[state[2][1] >> 4][state[2][1] & 0x0F];
   state[2][2] = aes_sbox[state[2][2] >> 4][state[2][2] & 0x0F];
   state[2][3] = aes_sbox[state[2][3] >> 4][state[2][3] & 0x0F];
   state[3][0] = aes_sbox[state[3][0] >> 4][state[3][0] & 0x0F];
   state[3][1] = aes_sbox[state[3][1] >> 4][state[3][1] & 0x0F];
   state[3][2] = aes_sbox[state[3][2] >> 4][state[3][2] & 0x0F];
   state[3][3] = aes_sbox[state[3][3] >> 4][state[3][3] & 0x0F];
  
}

void InvSubBytes(uchar state[][4])
{
   state[0][0] = aes_invsbox[state[0][0] >> 4][state[0][0] & 0x0F];
   state[0][1] = aes_invsbox[state[0][1] >> 4][state[0][1] & 0x0F];
   state[0][2] = aes_invsbox[state[0][2] >> 4][state[0][2] & 0x0F];
   state[0][3] = aes_invsbox[state[0][3] >> 4][state[0][3] & 0x0F];
   state[1][0] = aes_invsbox[state[1][0] >> 4][state[1][0] & 0x0F];
   state[1][1] = aes_invsbox[state[1][1] >> 4][state[1][1] & 0x0F];
   state[1][2] = aes_invsbox[state[1][2] >> 4][state[1][2] & 0x0F];
   state[1][3] = aes_invsbox[state[1][3] >> 4][state[1][3] & 0x0F];
   state[2][0] = aes_invsbox[state[2][0] >> 4][state[2][0] & 0x0F];
   state[2][1] = aes_invsbox[state[2][1] >> 4][state[2][1] & 0x0F];
   state[2][2] = aes_invsbox[state[2][2] >> 4][state[2][2] & 0x0F];
   state[2][3] = aes_invsbox[state[2][3] >> 4][state[2][3] & 0x0F];
   state[3][0] = aes_invsbox[state[3][0] >> 4][state[3][0] & 0x0F];
   state[3][1] = aes_invsbox[state[3][1] >> 4][state[3][1] & 0x0F];
   state[3][2] = aes_invsbox[state[3][2] >> 4][state[3][2] & 0x0F];
   state[3][3] = aes_invsbox[state[3][3] >> 4][state[3][3] & 0x0F];
}

void ShiftRows(uchar state[][4])
{
   int t;
   // Shift left by 1
   t = state[1][0];
   state[1][0] = state[1][1];
   state[1][1] = state[1][2];
   state[1][2] = state[1][3];
   state[1][3] = t;
   // Shift left by 2
   t = state[2][0];
   state[2][0] = state[2][2];
   state[2][2] = t;
   t = state[2][1];
   state[2][1] = state[2][3];
   state[2][3] = t;
   // Shift left by 3
   t = state[3][0];
   state[3][0] = state[3][3];
   state[3][3] = state[3][2];
   state[3][2] = state[3][1];
   state[3][1] = t;
   
}

// All rows are shifted cylindrically to the right.
void InvShiftRows(uchar state[][4])
{
   int t;
   // Shift right by 1
   t = state[1][3];
   state[1][3] = state[1][2];
   state[1][2] = state[1][1];
   state[1][1] = state[1][0];
   state[1][0] = t;
   // Shift right by 2
   t = state[2][3];
   state[2][3] = state[2][1];
   state[2][1] = t;
   t = state[2][2];
   state[2][2] = state[2][0];
   state[2][0] = t;
   // Shift right by 3
   t = state[3][3];
   state[3][3] = state[3][0];
   state[3][0] = state[3][1];
   state[3][1] = state[3][2];
   state[3][2] = t;
}


void MixColumns(uchar state[][4])
{
   uchar col[4];
   // Column 1
   col[0] = state[0][0];
   col[1] = state[1][0];
   col[2] = state[2][0];
   col[3] = state[3][0];
   state[0][0] = gf_mul[col[0]][0];
   state[0][0] ^= gf_mul[col[1]][1];
   state[0][0] ^= col[2];
   state[0][0] ^= col[3];
   state[1][0] = col[0];
   state[1][0] ^= gf_mul[col[1]][0];
   state[1][0] ^= gf_mul[col[2]][1];
   state[1][0] ^= col[3];
   state[2][0] = col[0];
   state[2][0] ^= col[1];
   state[2][0] ^= gf_mul[col[2]][0];
   state[2][0] ^= gf_mul[col[3]][1];
   state[3][0] = gf_mul[col[0]][1];
   state[3][0] ^= col[1];
   state[3][0] ^= col[2];
   state[3][0] ^= gf_mul[col[3]][0];
   // Column 2
   col[0] = state[0][1];
   col[1] = state[1][1];
   col[2] = state[2][1];
   col[3] = state[3][1];
   state[0][1] = gf_mul[col[0]][0];
   state[0][1] ^= gf_mul[col[1]][1];
   state[0][1] ^= col[2];
   state[0][1] ^= col[3];
   state[1][1] = col[0];
   state[1][1] ^= gf_mul[col[1]][0];
   state[1][1] ^= gf_mul[col[2]][1];
   state[1][1] ^= col[3];
   state[2][1] = col[0];
   state[2][1] ^= col[1];
   state[2][1] ^= gf_mul[col[2]][0];
   state[2][1] ^= gf_mul[col[3]][1];
   state[3][1] = gf_mul[col[0]][1];
   state[3][1] ^= col[1];
   state[3][1] ^= col[2];
   state[3][1] ^= gf_mul[col[3]][0];
   // Column 3
   col[0] = state[0][2];
   col[1] = state[1][2];
   col[2] = state[2][2];
   col[3] = state[3][2];
   state[0][2] = gf_mul[col[0]][0];
   state[0][2] ^= gf_mul[col[1]][1];
   state[0][2] ^= col[2];
   state[0][2] ^= col[3];
   state[1][2] = col[0];
   state[1][2] ^= gf_mul[col[1]][0];
   state[1][2] ^= gf_mul[col[2]][1];
   state[1][2] ^= col[3];
   state[2][2] = col[0];
   state[2][2] ^= col[1];
   state[2][2] ^= gf_mul[col[2]][0];
   state[2][2] ^= gf_mul[col[3]][1];
   state[3][2] = gf_mul[col[0]][1];
   state[3][2] ^= col[1];
   state[3][2] ^= col[2];
   state[3][2] ^= gf_mul[col[3]][0];
   // Column 4
   col[0] = state[0][3];
   col[1] = state[1][3];
   col[2] = state[2][3];
   col[3] = state[3][3];
   state[0][3] = gf_mul[col[0]][0];
   state[0][3] ^= gf_mul[col[1]][1];
   state[0][3] ^= col[2];
   state[0][3] ^= col[3];
   state[1][3] = col[0];
   state[1][3] ^= gf_mul[col[1]][0];
   state[1][3] ^= gf_mul[col[2]][1];
   state[1][3] ^= col[3];
   state[2][3] = col[0];
   state[2][3] ^= col[1];
   state[2][3] ^= gf_mul[col[2]][0];
   state[2][3] ^= gf_mul[col[3]][1];
   state[3][3] = gf_mul[col[0]][1];
   state[3][3] ^= col[1];
   state[3][3] ^= col[2];
   state[3][3] ^= gf_mul[col[3]][0];
  
}

void InvMixColumns(uchar state[][4])
{
  
   uchar col[4];
   // Column 1
   col[0] = state[0][0];
   col[1] = state[1][0];
   col[2] = state[2][0];
   col[3] = state[3][0];
   state[0][0] = gf_mul[col[0]][5];
   state[0][0] ^= gf_mul[col[1]][3];
   state[0][0] ^= gf_mul[col[2]][4];
   state[0][0] ^= gf_mul[col[3]][2];
   state[1][0] = gf_mul[col[0]][2];
   state[1][0] ^= gf_mul[col[1]][5];
   state[1][0] ^= gf_mul[col[2]][3];
   state[1][0] ^= gf_mul[col[3]][4];
   state[2][0] = gf_mul[col[0]][4];
   state[2][0] ^= gf_mul[col[1]][2];
   state[2][0] ^= gf_mul[col[2]][5];
   state[2][0] ^= gf_mul[col[3]][3];
   state[3][0] = gf_mul[col[0]][3];
   state[3][0] ^= gf_mul[col[1]][4];
   state[3][0] ^= gf_mul[col[2]][2];
   state[3][0] ^= gf_mul[col[3]][5];
   // Column 2
   col[0] = state[0][1];
   col[1] = state[1][1];
   col[2] = state[2][1];
   col[3] = state[3][1];
   state[0][1] = gf_mul[col[0]][5];
   state[0][1] ^= gf_mul[col[1]][3];
   state[0][1] ^= gf_mul[col[2]][4];
   state[0][1] ^= gf_mul[col[3]][2];
   state[1][1] = gf_mul[col[0]][2];
   state[1][1] ^= gf_mul[col[1]][5];
   state[1][1] ^= gf_mul[col[2]][3];
   state[1][1] ^= gf_mul[col[3]][4];
   state[2][1] = gf_mul[col[0]][4];
   state[2][1] ^= gf_mul[col[1]][2];
   state[2][1] ^= gf_mul[col[2]][5];
   state[2][1] ^= gf_mul[col[3]][3];
   state[3][1] = gf_mul[col[0]][3];
   state[3][1] ^= gf_mul[col[1]][4];
   state[3][1] ^= gf_mul[col[2]][2];
   state[3][1] ^= gf_mul[col[3]][5];
   // Column 3
   col[0] = state[0][2];
   col[1] = state[1][2];
   col[2] = state[2][2];
   col[3] = state[3][2];
   state[0][2] = gf_mul[col[0]][5];
   state[0][2] ^= gf_mul[col[1]][3];
   state[0][2] ^= gf_mul[col[2]][4];
   state[0][2] ^= gf_mul[col[3]][2];
   state[1][2] = gf_mul[col[0]][2];
   state[1][2] ^= gf_mul[col[1]][5];
   state[1][2] ^= gf_mul[col[2]][3];
   state[1][2] ^= gf_mul[col[3]][4];
   state[2][2] = gf_mul[col[0]][4];
   state[2][2] ^= gf_mul[col[1]][2];
   state[2][2] ^= gf_mul[col[2]][5];
   state[2][2] ^= gf_mul[col[3]][3];
   state[3][2] = gf_mul[col[0]][3];
   state[3][2] ^= gf_mul[col[1]][4];
   state[3][2] ^= gf_mul[col[2]][2];
   state[3][2] ^= gf_mul[col[3]][5];
   // Column 4
   col[0] = state[0][3];
   col[1] = state[1][3];
   col[2] = state[2][3];
   col[3] = state[3][3];
   state[0][3] = gf_mul[col[0]][5];
   state[0][3] ^= gf_mul[col[1]][3];
   state[0][3] ^= gf_mul[col[2]][4];
   state[0][3] ^= gf_mul[col[3]][2];
   state[1][3] = gf_mul[col[0]][2];
   state[1][3] ^= gf_mul[col[1]][5];
   state[1][3] ^= gf_mul[col[2]][3];
   state[1][3] ^= gf_mul[col[3]][4];
   state[2][3] = gf_mul[col[0]][4];
   state[2][3] ^= gf_mul[col[1]][2];
   state[2][3] ^= gf_mul[col[2]][5];
   state[2][3] ^= gf_mul[col[3]][3];
   state[3][3] = gf_mul[col[0]][3];
   state[3][3] ^= gf_mul[col[1]][4];
   state[3][3] ^= gf_mul[col[2]][2];
   state[3][3] ^= gf_mul[col[3]][5];
}

uint SubWord(uint word)
{
   unsigned int result;

   result = (int)aes_sbox[(word >> 4) & 0x0000000F][word & 0x0000000F];
   result += (int)aes_sbox[(word >> 12) & 0x0000000F][(word >> 8) & 0x0000000F] << 8;
   result += (int)aes_sbox[(word >> 20) & 0x0000000F][(word >> 16) & 0x0000000F] << 16;
   result += (int)aes_sbox[(word >> 28) & 0x0000000F][(word >> 24) & 0x0000000F] << 24;
   return(result);
}
 void KeyExpansion(uchar ininkey[],uint w[],int inkeysize)
{

   int Nb=4,Nr,Nk,idx;
   uint temp,Rcon[]={0x01000000,0x02000000,0x04000000,0x08000000,0x10000000,0x20000000,
                     0x40000000,0x80000000,0x1b000000,0x36000000,0x6c000000,0xd8000000,
                     0xab000000,0x4d000000,0x9a000000};


   switch (inkeysize) {
      case 128: Nr = 10; Nk = 4; break;
      case 192: Nr = 12; Nk = 6; break;
      case 256: Nr = 14; Nk = 8; break;
      default: return;
   }

   for (idx=0; idx < Nk; ++idx) {
      w[idx] = ((ininkey[4 * idx]) << 24) | ((ininkey[4 * idx + 1]) << 16) |
               ((ininkey[4 * idx + 2]) << 8) | ((ininkey[4 * idx + 3]));
   }
    
   
   for (idx = Nk; idx < Nb * (Nr+1); ++idx) {
      temp = w[idx - 1];
     if ((idx % Nk) == 0)
         temp = SubWord(KE_ROTWORD(temp)) ^ Rcon[(idx-1)/Nk];
	
      else if (Nk > 6 && (idx % Nk) == 4)
         temp = SubWord(temp);
	  
        w[idx] = w[idx-Nk] ^ temp;
	 
   }
  
   FOUT;
 
}

void aes_encrypt(Prg_List * in,uchar out[], uint inkey[], int keysize)
{
	
   uchar state[4][4];
   int i=0;
   uchar * ch;
  ch= (uchar *)prg_list_access(in,i); 
   state[0][0] = *ch;
   i++;
   ch= (uchar *)prg_list_access(in,i); 
  state[1][0] = *ch;;
    i++;
   ch= (uchar *)prg_list_access(in,i); 
    state[2][0] = *ch;
   i++;
    ch= (uchar *)prg_list_access(in,i); 
   state[3][0] = *ch;
   i++;
    ch= (uchar *)prg_list_access(in,i); 
   state[0][1] = *ch;
   i++;
    ch= (uchar *)prg_list_access(in,i); 
   state[1][1] = *ch;
   i++;
    ch= (uchar *)prg_list_access(in,i); 
  state[2][1] = *ch;
   i++;
    ch= (uchar *)prg_list_access(in,i); 
   state[3][1] =*ch;
   i++;
   ch= (uchar *)prg_list_access(in,i); 
  state[0][2] = *ch;
   i++;
   ch= (uchar *)prg_list_access(in,i); 
   state[1][2] =*ch;
   i++;
    ch= (uchar *)prg_list_access(in,i); 
   state[2][2] = *ch;
   i++;
    ch= (uchar *)prg_list_access(in,i); 
   state[3][2] =*ch;
   i++;
    ch= (uchar *)prg_list_access(in,i); 
   state[0][3] =*ch;
   i++;
    ch= (uchar *)prg_list_access(in,i); 
   state[1][3] = *ch;
   i++;
   ch= (uchar *)prg_list_access(in,i); 
   state[2][3] =*ch;
   i++;
    ch= (uchar *)prg_list_access(in,i); 
   state[3][3] = *ch;
   
   
  //printstate( state);

		
		
   // Perform the necessary number of rounds. The round inkey is added first.
   // The last round does not perform the MixColumns step.
   AddRoundKey(state,&inkey[0]);
   SubBytes(state); ShiftRows(state); MixColumns(state); AddRoundKey(state,&inkey[4]);
   SubBytes(state); ShiftRows(state); MixColumns(state); AddRoundKey(state,&inkey[8]);
   SubBytes(state); ShiftRows(state); MixColumns(state); AddRoundKey(state,&inkey[12]);
   SubBytes(state); ShiftRows(state); MixColumns(state); AddRoundKey(state,&inkey[16]);
   SubBytes(state); ShiftRows(state); MixColumns(state); AddRoundKey(state,&inkey[20]);
   SubBytes(state); ShiftRows(state); MixColumns(state); AddRoundKey(state,&inkey[24]);
   SubBytes(state); ShiftRows(state); MixColumns(state); AddRoundKey(state,&inkey[28]);
   SubBytes(state); ShiftRows(state); MixColumns(state); AddRoundKey(state,&inkey[32]);
   SubBytes(state); ShiftRows(state); MixColumns(state); AddRoundKey(state,&inkey[36]);
   if (keysize != 128) {
      SubBytes(state); ShiftRows(state); MixColumns(state); AddRoundKey(state,&inkey[40]);
      SubBytes(state); ShiftRows(state); MixColumns(state); AddRoundKey(state,&inkey[44]);
      if (keysize != 192) {
         SubBytes(state); ShiftRows(state); MixColumns(state); AddRoundKey(state,&inkey[48]);
         SubBytes(state); ShiftRows(state); MixColumns(state); AddRoundKey(state,&inkey[52]);
         SubBytes(state); ShiftRows(state); AddRoundKey(state,&inkey[56]);
      }
      else {
         SubBytes(state); ShiftRows(state); AddRoundKey(state,&inkey[48]);
      }
   }
   else {
      SubBytes(state); ShiftRows(state); AddRoundKey(state,&inkey[40]);
   }
   
   
   //printstate(state);

   // Copy the state to the output array
   
 out[0] = state[0][0];
   out[1] = state[1][0];
   out[2] = state[2][0];
   out[3] = state[3][0];
   out[4] = state[0][1];
   out[5] = state[1][1];
   out[6] = state[2][1];
   out[7] = state[3][1];
   out[8] = state[0][2];
   out[9] = state[1][2];
   out[10] = state[2][2];
   out[11] = state[3][2];
   out[12] = state[0][3];
   out[13] = state[1][3];
   out[14] = state[2][3];
   out[15] = state[3][3];

 /*  i=0;
  prg_list_insert(output,&state[0][0],i);
   i++;
  ch=&state[1][0];
   prg_list_insert(output,ch,i);
   i++;
   ch=&state[2][0];
   prg_list_insert(output,ch,i);
   i++;
    ch=&state[3][0];
   prg_list_insert(output,ch,i);
   i++;
    ch=&state[0][1];
    prg_list_insert(output,ch,i);
   i++;
    ch=&state[1][1];
   prg_list_insert(output,ch,i);
   i++;
   ch=&state[2][1];
   prg_list_insert(output,ch,i);
   i++;
    ch=&state[3][1];
   prg_list_insert(output,ch,i);
   i++;
   ch=&state[0][2];
   prg_list_insert(output,ch,i);
   i++;
    ch=&state[1][2];
    prg_list_insert(output,ch,i);
   i++;
    ch=&state[2][2];
    prg_list_insert(output,ch,i);
   i++;
    ch=&state[3][2];
   prg_list_insert(output,ch,i);
   i++;
    ch=&state[0][3];
  prg_list_insert(output,ch,i);
   i++;
   *ch=state[1][3];
   prg_list_insert(output,ch,i);
   i++;
   *ch=state[2][3];
 prg_list_insert(output,ch,i);
   i++;
   *ch=state[3][3];
  prg_list_insert(output,ch,i);			
		
 */ 

	
		
   
}

static void aes_decrypt(uchar in[],uchar out[], uint inkey[], int inkeysize)
{
   uchar state[4][4];
 
   
  int i=0;
   
  
  
 state[0][0] = in[0];
   state[1][0] = in[1];
   state[2][0] = in[2];
   state[3][0] = in[3];
   state[0][1] = in[4];
   state[1][1] = in[5];
   state[2][1] = in[6];
   state[3][1] = in[7];
   state[0][2] = in[8];
   state[1][2] = in[9];
   state[2][2] = in[10];
   state[3][2] = in[11];
   state[0][3] = in[12];
   state[1][3] = in[13];
   state[2][3] = in[14];
   state[3][3] = in[15];
  
   // Perform the necessary number of rounds. The round key is added first.
   // The last round does not perform the MixColumns step.
   if (inkeysize > 128) {
      if (inkeysize > 192) {
         AddRoundKey(state,&inkey[56]);
         InvShiftRows(state);InvSubBytes(state);AddRoundKey(state,&inkey[52]);InvMixColumns(state);
         InvShiftRows(state);InvSubBytes(state);AddRoundKey(state,&inkey[48]);InvMixColumns(state);
      }
      else {
         AddRoundKey(state,&inkey[48]);
      }
      InvShiftRows(state);InvSubBytes(state);AddRoundKey(state,&inkey[44]);InvMixColumns(state);
      InvShiftRows(state);InvSubBytes(state);AddRoundKey(state,&inkey[40]);InvMixColumns(state);
   }
   else {
      AddRoundKey(state,&inkey[40]);
   }
   InvShiftRows(state);InvSubBytes(state);AddRoundKey(state,&inkey[36]);InvMixColumns(state);
   InvShiftRows(state);InvSubBytes(state);AddRoundKey(state,&inkey[32]);InvMixColumns(state);
   InvShiftRows(state);InvSubBytes(state);AddRoundKey(state,&inkey[28]);InvMixColumns(state);
   InvShiftRows(state);InvSubBytes(state);AddRoundKey(state,&inkey[24]);InvMixColumns(state);
   InvShiftRows(state);InvSubBytes(state);AddRoundKey(state,&inkey[20]);InvMixColumns(state);
   InvShiftRows(state);InvSubBytes(state);AddRoundKey(state,&inkey[16]);InvMixColumns(state);
   InvShiftRows(state);InvSubBytes(state);AddRoundKey(state,&inkey[12]);InvMixColumns(state);
   InvShiftRows(state);InvSubBytes(state);AddRoundKey(state,&inkey[8]);InvMixColumns(state);
   InvShiftRows(state);InvSubBytes(state);AddRoundKey(state,&inkey[4]);InvMixColumns(state);
   InvShiftRows(state);InvSubBytes(state);AddRoundKey(state,&inkey[0]);

   // Copy the state to the output array
   out[0] = state[0][0];
   out[1] = state[1][0];
   out[2] = state[2][0];
   out[3] = state[3][0];
   out[4] = state[0][1];
   out[5] = state[1][1];
   out[6] = state[2][1];
   out[7] = state[3][1];
   out[8] = state[0][2];
   out[9] = state[1][2];
   out[10] = state[2][2];
   out[11] = state[3][2];
   out[12] = state[0][3];
   out[13] = state[1][3];
   out[14] = state[2][3];
   out[15] = state[3][3];
 


  
}

//random



void sub_div(int start,int end,uchar sub_nid[])
	{
	unsigned char temp,ch;
	int j,index=0;
	

	
	j=start;
	
	while(j<=end)
		{
		
		temp=0x00;
		ch=0x00;
		for(int i=0;i<2;i++)
		{
		if(Nid[j]>='0' && Nid[j]<='9')
           ch= (ch<<4) | (Nid[j] - '0');
        else if(Nid[j]>='a' && Nid[j]<='f') // lower case
            ch= (ch) | ((Nid[j] - 'a') + 10);
      
		j++;
		if(i==1)
			break;
		temp=ch;
		ch=0x00;
		
		}
		
		
		ch=(temp<<4)|ch;
		sub_nid[index]=ch;
		index++;
		
		}
		///////////////////////////////////////////////////////////////
		/*for(int i=0;i<16;i++)
			//sub_nid[j]=Nid[i];// key head encrypt with it cluster key
			printf("%x", sub_nid[i]);
			
			cout<<"\n";*/
		
	
	
	
	}


void re_dec_clukey(unsigned char list_out[],int rand[],Objid src_id)
	// member reply with decrypted key
	{
		
		Packet * pkt;
		Objid procid;
		msg_info * msg;
		uint w[44]={0};
		uchar  sub_niddec[16]={0x00};
		double size;
		unsigned char* ch;
		int *x, *y;// for re enc
		FIN(re_dec_clukey(<args>));
		Objid	objid         = op_id_self ();
		Objid	node_objid    = op_topo_parent (objid);  
	
		msg=new msg_info();
		
		
	
		sub_div(rand[0],rand[1],sub_niddec);
		
		KeyExpansion(sub_niddec,w,128);
		
		aes_decrypt(list_out,outaes,w,128);
	/*cout<<"random with mem"<<rand[0]<<" "<<rand[1]<<"\n";
		
		
		cout<<"dec clkey with mem"<<"\n";
		for(int j=0;j<16;j++)
			{
		
			printf("%x",outaes[j]);
			}
			cout<<"\n";*/
	
///////////////////////////////////////////////////////////////////////////////////////
		// for re_enc cluster key
			//cout<<"dec clkey with mem at list"<<"\n";
		for(int k=0;k<16;k++)
	{
		ch=&(outaes[k]);
		prg_list_insert(inter_list,ch,k);
		
		
	}
			
		

	random_16();// generate 2 numbers diff between them is 32
			
	x=(int *)prg_list_access(rand_list_16,0);
	y=(int *)prg_list_access(rand_list_16,1);
		//cout<<"tany random with mem at reenc"<<*x<<" "<<*y<<"\n";
		sub_div(*x,*y,sub_niddec);
		KeyExpansion(sub_niddec,w,128);
		aes_encrypt(inter_list,outaes,w,128);
		for(int i=0;i<16;i++)
			{
			msg->info_arr[i]=outaes[i];
		
			//printf("%x",outaes[i]);
			}
			//cout<<"\n";
	
		msg->rand[0]=*x;
		msg->rand[1]=*y;
	
			
		//msg->type=re_deckey;
		
		msg->type=re_reenckey;
		////////////////////////////////////////////////////////////////////////////////////////
		pkt=op_pk_create(0);
		
		procid = op_id_from_name(src_id,OPC_OBJTYPE_PROC,"traf_src");
		
		op_pk_fd_set (pkt, 0, OPC_FIELD_TYPE_STRUCT, msg, sizeof(msg_info)*8,op_prg_mem_copy_create,op_prg_mem_free,sizeof(msg_info));
		
		size=(32*3)+(16*8);
		//cout<<"memberdec size "<<total_size<<"\n";
		op_pk_deliver(pkt,procid,0);
			manet_rpg_sent_stats_update (size);
		FOUT;
		
		
	
	
	}

void store_dec_symkey(unsigned char list_out[],int rand[])
	// member reply with decrypted key
	{

		unsigned char *ch1,* ch2;
	
		
		uint w[44]={0};
		uchar  sub_niddec[16]={0x00};

	double size;
		
		FIN(store_dec_symkey(<args>));
		
		
		
		sub_div(rand[0],rand[1],sub_niddec);
		
		KeyExpansion(sub_niddec,w,128);

		
		aes_decrypt(list_out,outaes,w,128);
		size=(32*3)+(16*8);
		manet_rpg_received_stats_update (size);
		

		for(int j=0;j<16;j++)//access symkey sent from db node
		{
				ch1=&(outaes[j]);
		
		prg_list_insert(symmetric_key,ch1,j);
			ch2=(unsigned char*)prg_list_access(symmetric_key,j);
			//printf("%x",*ch2);
				
		
		}
		
		//cout<<"\n";
		//cout<<"\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\"<<"\n";
	
		FOUT;
		
		
	
	
	}




void printstate(uchar state[][4])
{
   int idx,idx2;
   for (idx=0; idx < 4; idx++)
      for (idx2=0; idx2 < 4; idx2++)
	  {
         printf("%x",state[idx2][idx]);
		 cout<<" ";
	  }
   puts("");
}
		
void check_ckey(uchar list[], int rand[] ,Objid id)// head check re_encrypted ckey sent from member
{
	bool decval=true;
	uchar *he_ch;
	uint w[44]={0};
		uchar  sub_niddec[16]={0x00};
	FIN(check_ckey(<args>));
	
	//////////////////////////////////////////////////////////////////////////////////
	// check dec re_enc cluster key
	sub_div(rand[0],rand[1],sub_niddec);
	//cout<<"tany random at head"<<rand[0]<<" "<<rand[1]<<"\n";
		
		KeyExpansion(sub_niddec,w,128);
	
		
		aes_decrypt(list,outaes,w,128);
		
	/*cout<<"final at head"<<"\n";
	for(int i=0;i<16;i++)
	
		{
		printf("%x",outaes[i]);
		}
	cout<<"\n";
	cout<<"\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\";
	///////////////////////////////////////////////////////////////////////////////////
	*/
	for(int i=0;i<16;i++)		
			{

			he_ch=(uchar *)prg_list_access(cluster_key,i);
			if(*he_ch!=outaes[i])
				{
				cout<<"false "<<"\n";
				decval=false;
				break;
				
				}
			
			
			}
	

				
	if(decval)
		{
		//cout<<"success "<<"\n";
		//send_newc(id,symmetric_key);// send to new comer new sym key
		send_sym_enc(id);// send sym key encrypted
		}
FOUT;
}

void store_keys(Prg_List * list)
	{
	
	uchar * ch;
	
	FIN(store_keys(<args>));

	//cout<<"in store"<<"\n";
		for(int i=0;i<16;i++)
				{
				ch=(uchar *)prg_list_access(list,i);// access ckey
				prg_list_insert(cluster_key,ch,i);
				//printf("%x",*ch);
			
				}
	
				//cout<<"\n";
				for(int i=16;i<32;i++)
				{
				ch=(uchar *)prg_list_access(list,i);// access symkey
				prg_list_insert(symmetric_key,ch,i-16);
				//printf("%x",*ch);
				
				}
			
				//cout<<"\n";
	
				FOUT;
	}

void ann_malc(Objid id)
	
	{
		Packet * pkt;
		msg_info * msg;
		Objid proc,procid;
		int *x;
		x=new int;
		msg=new msg_info();
		msg->info=prg_list_create();
		prg_list_init(msg->info);
		msg->type=malc;
		*x=id;
		prg_list_insert(msg->info,x,0);
		pkt=op_pk_create(0);
		//procid = op_id_from_name(src_node_objid,OPC_OBJTYPE_PROC,"traf_src");
		
		op_pk_fd_set (pkt, 0, OPC_FIELD_TYPE_STRUCT, msg, sizeof(msg_info)*8,op_prg_mem_copy_create,op_prg_mem_free,sizeof(msg_info));
		proc= op_topo_object(OPC_OBJTYPE_NODE_FIX,1);
	
		procid = op_id_from_name(proc,OPC_OBJTYPE_PROC,"recorder");
		
		op_pk_deliver(pkt,procid,0);
	}

void random()
	{
	
		unsigned int  * rand_int,*rand_int1;
	//	int *x;
		PrgT_Random_Gen    *my_rng;
		rand_int=new unsigned int;
		rand_int1=new unsigned int;
		
		FIN(random());
		my_rng = op_prg_random_gen_create (rand()%100);
		
		
			while(true)
				
				
	{
	
		
		*rand_int = (op_prg_random_integer_gen (my_rng) %  96) ;
		*rand_int1 = (op_prg_random_integer_gen (my_rng) %  96) ;
		if(*rand_int==*rand_int1)
			continue;
		
		else
			break;

		
	}
		
	if(*rand_int>*rand_int1)
			{
		prg_list_insert(rand_list,rand_int1,0);
		prg_list_insert(rand_list,rand_int,1);
		}
	
	else
		{
		prg_list_insert(rand_list,rand_int,0);
		prg_list_insert(rand_list,rand_int1,1);
		}
		op_prg_random_gen_destroy (my_rng);
		
		
		FOUT;
			

	
	}

void random_16()
	{
	
		unsigned int  * rand_int,*rand_int1;
		//int *x;
		PrgT_Random_Gen    *my_rng;
		rand_int=new unsigned int;
		rand_int1=new unsigned int;
			FIN(random_16());
		my_rng = op_prg_random_gen_create (rand()%100);
		
		
			while(true)
				
				
	{
	
		
		*rand_int = (op_prg_random_integer_gen (my_rng) %  96) ;
		*rand_int1 = (op_prg_random_integer_gen (my_rng) %  96) ;
		if((*rand_int1-*rand_int)+1!=32)
			continue;
		
		else
			break;

		
	}
	
		
		if(*rand_int>*rand_int1)
	{
		prg_list_insert(rand_list_16,rand_int1,0);
		prg_list_insert(rand_list_16,rand_int,1);
		
		}
		else
			{
			prg_list_insert(rand_list_16,rand_int,0);
			prg_list_insert(rand_list_16,rand_int1,1);
			}
		
		op_prg_random_gen_destroy (my_rng);
	
			
		FOUT;
	
	}
void send_newc(Objid id,Prg_List * sym_list)
	{
	
	
	msg_info* msg;
	Packet *pktptr;
	unsigned char * ch;
	double size;
	Objid procid;


	FIN(send_newc(<args>))
		msg=new msg_info();	
	msg->type=re_symkey;
		msg->info=prg_list_create();
		prg_list_init(msg->info);
	
		for(int j=0;j<16;j++)//access sym key new sent from head
		{
		ch=(unsigned char *)prg_list_access(sym_list,j); 
		prg_list_insert(msg->info,ch,j);
		
		}
		
		pktptr=op_pk_create(0);
	
		op_pk_fd_set (pktptr, 0, OPC_FIELD_TYPE_STRUCT, msg, sizeof(msg_info)*8,op_prg_mem_copy_create,op_prg_mem_free,sizeof(msg_info));
		procid = op_id_from_name(id,OPC_OBJTYPE_PROC,"traf_src");
		size=32+(16*8);
		
		//cout<<"head total size"<<total_size<<"\n";
		
		op_pk_deliver(pktptr,procid,0);
			manet_rpg_sent_stats_update (size);
		FOUT;
		
		}

void store_newsymkeys(Prg_List * list)
	{
	
	
	unsigned char * ch;
	Objid	objid         = op_id_self ();
	Objid	node_objid    = op_topo_parent (objid);  
	
	FIN(store_newsymkeys(<args>))
		
		//cout<<"sym org"<<"\n";
		for(int j=0;j<16;j++)//access symkey sent from db node
		{
		ch=(unsigned char *)prg_list_access(list,j); 
		prg_list_insert(symmetric_key,ch,j);
		//printf("%x",*ch);
		
		}
	/*cout<<"in store "<<node_objid<<"\n";	
	for(int j=0;j<16;j++)//access ckey sent from db node
		{
		ch=(unsigned char *)prg_list_access(symmetric_key,j); 
		
		
		}
	cout<<"\n";*/
	//size=32.0+(16.0*8);
	
	//manet_rpg_received_stats_update(size);
	
	FOUT;
	
	
	}

void recev_msg (Objid id)
	
	{
	
	Objid procid;
	Packet * pktptr;
	
	
	
		FIN(recev(<args>))
	{
		msg_info *msg=new msg_info();	
			
		msg->type=recev;
		
		pktptr=op_pk_create(0);
	
		op_pk_fd_set (pktptr, 0, OPC_FIELD_TYPE_STRUCT, msg, sizeof(msg_info)*8,op_prg_mem_copy_create,op_prg_mem_free,sizeof(msg_info));		
		
		
		procid = op_id_from_name(id,OPC_OBJTYPE_PROC,"traf_src");
	
	
		op_pk_deliver(pktptr,procid,0);
			//cout<<"after"<<"\n";
	
	FOUT;
		}
	
	}

void ann_recev(Objid id)
	
	{
		Packet * pkt;
		msg_info * msg;
		msg=new msg_info();
		int *x;
		Objid proc,procid;
		x=new int;
		msg->info=prg_list_create();
		prg_list_init(msg->info);
		*x=id;
		prg_list_insert(msg->info,x,0);
		msg->type=recev;
		pkt=op_pk_create(0);
		//procid = op_id_from_name(src_node_objid,OPC_OBJTYPE_PROC,"traf_src");
		
		op_pk_fd_set (pkt, 0, OPC_FIELD_TYPE_STRUCT, msg, sizeof(msg_info)*8,op_prg_mem_copy_create,op_prg_mem_free,sizeof(msg_info));
		proc= op_topo_object(OPC_OBJTYPE_NODE_FIX,1);
			//cout<<"proc"<<proc<<"\n";
		procid = op_id_from_name(proc,OPC_OBJTYPE_PROC,"recorder");
		//cout<<"id"<<procid<<"\n";
		op_pk_deliver(pkt,procid,0);
	}


void ann_comer(Objid id)
	
	{
		Packet * pkt;
		msg_info * msg;
		msg=new msg_info();
		Objid proc,procid;
		int *x;
		x=new int;
		msg->info=prg_list_create();
		prg_list_init(msg->info);
		*x=id;
		prg_list_insert(msg->info,x,0);
		msg->type=comer_msg;
		pkt=op_pk_create(0);
		//procid = op_id_from_name(src_node_objid,OPC_OBJTYPE_PROC,"traf_src");
		
		op_pk_fd_set (pkt, 0, OPC_FIELD_TYPE_STRUCT, msg, sizeof(msg_info)*8,op_prg_mem_copy_create,op_prg_mem_free,sizeof(msg_info));
	
		proc= op_topo_object(OPC_OBJTYPE_NODE_FIX,1);
		//cout<<"proc"<<proc<<"\n";
		procid = op_id_from_name(proc,OPC_OBJTYPE_PROC,"recorder");
		op_pk_deliver(pkt,procid,0);
	}
void ann_overhead(Objid src_node,int size)
{

	Packet * pkt;
		msg_info * msg;
	Objid proc,procid;
		msg=new msg_info();
		int *x;
		x=new int;
		msg->info=prg_list_create();
		prg_list_init(msg->info);
		*x=src_node;
		prg_list_insert(msg->info,x,0);
		x=new int;
		*x=size;
		prg_list_insert(msg->info,x,1);
		msg->type=over_head;
		
		pkt=op_pk_create(0);
		//procid = op_id_from_name(src_node_objid,OPC_OBJTYPE_PROC,"traf_src");
		
		op_pk_fd_set (pkt, 0, OPC_FIELD_TYPE_STRUCT, msg, sizeof(msg_info)*8,op_prg_mem_copy_create,op_prg_mem_free,sizeof(msg_info));
	
		proc= op_topo_object(OPC_OBJTYPE_NODE_FIX,1);
		procid = op_id_from_name(proc,OPC_OBJTYPE_PROC,"recorder");
		op_pk_deliver(pkt,procid,0);



}

/* End of Function Block */

/* Undefine optional tracing in FIN/FOUT/FRET */
/* The FSM has its own tracing code and the other */
/* functions should not have any tracing.		  */
#undef FIN_TRACING
#define FIN_TRACING

#undef FOUTRET_TRACING
#define FOUTRET_TRACING

/* Undefine shortcuts to state variables because the */
/* following functions are part of the state class */
#undef my_objid
#undef my_node_objid
#undef my_subnet_objid
#undef local_packets_received_hndl
#undef local_bits_received_hndl
#undef local_delay_hndl
#undef global_packets_received_hndl
#undef global_bits_received_hndl
#undef outstrm_to_ip_encap
#undef instrm_from_ip_encap
#undef manet_flow_info_array
#undef higher_layer_proto_id
#undef ip_encap_req_ici_ptr
#undef local_packets_sent_hndl
#undef local_bits_sent_hndl
#undef global_packets_sent_hndl
#undef global_bits_sent_hndl
#undef global_delay_hndl
#undef iface_info_ptr
#undef next_pkt_interarrival
#undef cluster_key
#undef symmetric_key
#undef outaes
#undef ophash
#undef total_size
#undef count_recev
#undef count_comer
#undef misbehave
#undef r1
#undef r2
#undef rand_list
#undef rand_list_16
#undef inter_list

/* Access from C kernel using C linkage */
extern "C"
{
	VosT_Obtype _op_manet_dispatcher_cluster_init (int * init_block_ptr);
	VosT_Address _op_manet_dispatcher_cluster_alloc (VosT_Obtype, int);
	void manet_dispatcher_cluster (OP_SIM_CONTEXT_ARG_OPT)
		{
		((manet_dispatcher_cluster_state *)(OP_SIM_CONTEXT_PTR->_op_mod_state_ptr))->manet_dispatcher_cluster (OP_SIM_CONTEXT_PTR_OPT);
		}

	void _op_manet_dispatcher_cluster_svar (void *, const char *, void **);

	void _op_manet_dispatcher_cluster_diag (OP_SIM_CONTEXT_ARG_OPT)
		{
		((manet_dispatcher_cluster_state *)(OP_SIM_CONTEXT_PTR->_op_mod_state_ptr))->_op_manet_dispatcher_cluster_diag (OP_SIM_CONTEXT_PTR_OPT);
		}

	void _op_manet_dispatcher_cluster_terminate (OP_SIM_CONTEXT_ARG_OPT)
		{
		/* The destructor is the Termination Block */
		delete (manet_dispatcher_cluster_state *)(OP_SIM_CONTEXT_PTR->_op_mod_state_ptr);
		}


} /* end of 'extern "C"' */




/* Process model interrupt handling procedure */


void
manet_dispatcher_cluster_state::manet_dispatcher_cluster (OP_SIM_CONTEXT_ARG_OPT)
	{
#if !defined (VOSD_NO_FIN)
	int _op_block_origin = 0;
#endif
	FIN_MT (manet_dispatcher_cluster_state::manet_dispatcher_cluster ());
	try
		{
		/* Temporary Variables */
		List*					proc_record_handle_lptr;
		int						proc_record_handle_list_size;
		OmsT_Pr_Handle  		process_record_handle;
		Objid					low_module_objid;
		IpT_Rte_Module_Data*	ip_module_data_ptr;
		int						intrpt_type;
		int                     intrpt_code=0;
		
		
		
		/* End of Temporary Variables */


		FSM_ENTER ("manet_dispatcher_cluster")

		FSM_BLOCK_SWITCH
			{
			/*---------------------------------------------------------*/
			/** state (init) enter executives **/
			FSM_STATE_ENTER_UNFORCED_NOLABEL (0, "init", "manet_dispatcher_cluster [init enter execs]")
				FSM_PROFILE_SECTION_IN ("manet_dispatcher_cluster [init enter execs]", state0_enter_exec)
				{
				/* Initialize the state variables used by this model.					*/
				//overhead_handle  = op_stat_reg ("Overhead_Nodes",OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL);
				//recev_handle  = op_stat_reg ("Recev Counter",OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL);
				manet_rpg_sv_init ();
				
				//comer_handle  = op_stat_reg ("Comer_Counter",OPC_STAT_INDEX_NONE, OPC_STAT_LOCAL);
				
				/* Register this process in the network wide process registery so that	*/
				/* lower layer can detect our existence.								*/
				manet_rpg_register_self ();
				
				/* Schedule a self interrupt to wait for lower layer process to			*/
				/* initialize and register itself in the model-wide process registry.	*/
				/* This is necessary since global RPG start time may have been set as	*/
				/* low as zero seconds, which is acceptable when operating over MAC		*/
				/* layer.																*/
				count_recev=0;
				count_comer=0;
				
				
				op_intrpt_schedule_self (op_sim_time (), 0);
				
				
				
					  
				cluster_key=prg_list_create();
					prg_list_init(cluster_key);
					symmetric_key=prg_list_create();
					prg_list_init(symmetric_key);
				misbehave=false;
					
				rand_list=prg_list_create();
					prg_list_init(rand_list);
				
				rand_list_16=prg_list_create();
					prg_list_init(rand_list_16);
				
				inter_list=prg_list_create();
					prg_list_init(inter_list);
				
				
				}
				FSM_PROFILE_SECTION_OUT (state0_enter_exec)

			/** blocking after enter executives of unforced state. **/
			FSM_EXIT (1,"manet_dispatcher_cluster")


			/** state (init) exit executives **/
			FSM_STATE_EXIT_UNFORCED (0, "init", "manet_dispatcher_cluster [init exit execs]")
				FSM_PROFILE_SECTION_IN ("manet_dispatcher_cluster [init exit execs]", state0_exit_exec)
				{
				
				}
				FSM_PROFILE_SECTION_OUT (state0_exit_exec)


			/** state (init) transition processing **/
			FSM_TRANSIT_FORCE (2, state2_enter_exec, ;, "default", "", "init", "wait", "tr_31", "manet_dispatcher_cluster [init -> wait : default / ]")
				/*---------------------------------------------------------*/



			/** state (discover) enter executives **/
			FSM_STATE_ENTER_UNFORCED (1, "discover", state1_enter_exec, "manet_dispatcher_cluster [discover enter execs]")
				FSM_PROFILE_SECTION_IN ("manet_dispatcher_cluster [discover enter execs]", state1_enter_exec)
				{
				/* Schedule a self interrupt, that will indicate the completion of		*/
				/* lower layer initializations. We will perform the discovery process	*/
				/* following the delivery of this interrupt, i.e. in the exit execs of	*/
				/* this state.															*/
				op_intrpt_schedule_self (op_sim_time (), 0);
				}
				FSM_PROFILE_SECTION_OUT (state1_enter_exec)

			/** blocking after enter executives of unforced state. **/
			FSM_EXIT (3,"manet_dispatcher_cluster")


			/** state (discover) exit executives **/
			FSM_STATE_EXIT_UNFORCED (1, "discover", "manet_dispatcher_cluster [discover exit execs]")
				FSM_PROFILE_SECTION_IN ("manet_dispatcher_cluster [discover exit execs]", state1_exit_exec)
				{
				/** In this state we try to discover the IP module	**/
				
				/* First check whether we have an IP module in the same node.			*/
				proc_record_handle_lptr = op_prg_list_create ();
				oms_pr_process_discover (my_objid, proc_record_handle_lptr,
										 "node objid",	OMSC_PR_OBJID,		my_node_objid,
										 "protocol", 	OMSC_PR_STRING,		"ip_encap",
										 OPC_NIL);
				
				/* Check the number of modules matching to the given discovery query.	*/
				proc_record_handle_list_size = op_prg_list_size (proc_record_handle_lptr);
				if (proc_record_handle_list_size != 1)
					{
					/* A node with multiple IP modules is not an acceptable				*/
					/* configuration. Terminate the simulation.							*/
					op_sim_end ("Error: Zero or Multiple IP modules are found in the surrounding node.", "", "", "");
					}
				else
					{
					/* We have exactly one ip_encap module in the surrounding node and	*/
					/* we should be running over this module. Get a handle to its		*/
					/* process record.													*/
					process_record_handle = (OmsT_Pr_Handle) op_prg_list_access (proc_record_handle_lptr, OPC_LISTPOS_HEAD);
				
					/* Obtain the module objid of the IP-ENCAP module and using that	*/
					/* determine our stream numbers with the lower layer.				*/
					oms_pr_attr_get (process_record_handle, "module objid", OMSC_PR_OBJID, &low_module_objid);
					oms_tan_neighbor_streams_find (my_objid, low_module_objid, &instrm_from_ip_encap, &outstrm_to_ip_encap);
					}
				
				/* 	Deallocate no longer needed process registry 		*/
				/*	information. 										*/
				while (op_prg_list_size (proc_record_handle_lptr))
					op_prg_list_remove (proc_record_handle_lptr, OPC_LISTPOS_HEAD);
				op_prg_mem_free (proc_record_handle_lptr);
				
				
				/* 	Obtain the IP interface information for the local 	*/
				/*	ip process from the model-wide registry. 			*/
				proc_record_handle_lptr = op_prg_list_create ();
				oms_pr_process_discover (OPC_OBJID_INVALID, proc_record_handle_lptr, 
					"node objid",	OMSC_PR_OBJID,		my_node_objid,
					"protocol", 	OMSC_PR_STRING,		"ip", 
					OPC_NIL);
				
				proc_record_handle_list_size = op_prg_list_size (proc_record_handle_lptr);
				if (proc_record_handle_list_size != 1)
					{
					/* 	An error should be created if there are more 	*/
					/*	than one ip process in the local node, or		*/
					/*	if no match is found. 							*/
					op_sim_end ("Error: either zero or several ip processes found in the local node", "", "", "");
					}
				else
					{
					/*	Obtain a handle on the process record.			*/
					process_record_handle = (OmsT_Pr_Handle) op_prg_list_access (proc_record_handle_lptr, OPC_LISTPOS_HEAD);
				
					/* Obtain a pointer to the ip module data	. 		*/
					oms_pr_attr_get (process_record_handle,	"module data", OMSC_PR_POINTER, &ip_module_data_ptr);	
					}
				
				/* 	Deallocate no longer needed process registry 		*/
				/*	information. 										*/
				while (op_prg_list_size (proc_record_handle_lptr))
					op_prg_list_remove (proc_record_handle_lptr, OPC_LISTPOS_HEAD);
				op_prg_mem_free (proc_record_handle_lptr);
				
				/* Get the IP address of this station node	*/
				/* Since this node can have only one		*/
				/* interface, access index 0				*/
				iface_info_ptr = inet_rte_intf_tbl_access (ip_module_data_ptr,0);
				
				/* Register this node's IP address in the global	*/
				/* list of IP address for auto assignment of a		*/
				/* destination address								*/
				manet_rte_ip_address_register (iface_info_ptr);
				}
				FSM_PROFILE_SECTION_OUT (state1_exit_exec)


			/** state (discover) transition processing **/
			FSM_TRANSIT_FORCE (4, state4_enter_exec, ;, "default", "", "discover", "wait_2", "tr_40", "manet_dispatcher_cluster [discover -> wait_2 : default / ]")
				/*---------------------------------------------------------*/



			/** state (wait) enter executives **/
			FSM_STATE_ENTER_UNFORCED (2, "wait", state2_enter_exec, "manet_dispatcher_cluster [wait enter execs]")
				FSM_PROFILE_SECTION_IN ("manet_dispatcher_cluster [wait enter execs]", state2_enter_exec)
				{
				/* Wait for one more wave of interrupts to gurantee that lower layers	*/
				/* will have finalized their address resolution when we query for the	*/
				/* address (and other) information in the exit execs of discover state.	*/
				
				op_intrpt_schedule_self (op_sim_time (), 0);
				}
				FSM_PROFILE_SECTION_OUT (state2_enter_exec)

			/** blocking after enter executives of unforced state. **/
			FSM_EXIT (5,"manet_dispatcher_cluster")


			/** state (wait) exit executives **/
			FSM_STATE_EXIT_UNFORCED (2, "wait", "manet_dispatcher_cluster [wait exit execs]")


			/** state (wait) transition processing **/
			FSM_TRANSIT_FORCE (5, state5_enter_exec, ;, "default", "", "wait", "wait_0", "tr_37", "manet_dispatcher_cluster [wait -> wait_0 : default / ]")
				/*---------------------------------------------------------*/



			/** state (dispatch) enter executives **/
			FSM_STATE_ENTER_UNFORCED (3, "dispatch", state3_enter_exec, "manet_dispatcher_cluster [dispatch enter execs]")

			/** blocking after enter executives of unforced state. **/
			FSM_EXIT (7,"manet_dispatcher_cluster")


			/** state (dispatch) exit executives **/
			FSM_STATE_EXIT_UNFORCED (3, "dispatch", "manet_dispatcher_cluster [dispatch exit execs]")
				FSM_PROFILE_SECTION_IN ("manet_dispatcher_cluster [dispatch exit execs]", state3_exit_exec)
				{
				/* Get the interrupt type. This will be used to determine	*/
				/* whether this is a self interrupt to generate a packet or	*/
				/* a stream interrupt from ip_encap.						*/
				int  x;
				
				Packet * rcvd_pkt=OPC_NIL;
				Objid src_objid, src_node_objid;
				
				Objid	objid         = op_id_self ();
				
				Objid	node_objid    = op_topo_parent (objid);
				
				
				
				//int *m;
					
				//op_ima_obj_attr_get_toggle(node_objid,"condition",&z);
				
				//op_ima_obj_attr_set_toggle(8,"condition",0);
				
				
				
				
				intrpt_type = op_intrpt_type ();
				msg_info * msg=new msg_info();
				if (intrpt_type==OPC_INTRPT_STRM)
					{
					
						rcvd_pkt=op_pk_get (instrm_from_ip_encap);
						//cout<<"one"<<instrm_from_ip_encap<<"\n";
						//rcvd_pkt= op_pk_get (instrm_from_ip_encap);
						//cout<<"two"<<rcvd_pkt<<"\n";
						x=op_pk_fd_max_index(rcvd_pkt);
					
						
						if(x<0)
						{
					
						manet_rpg_packet_destroy(rcvd_pkt);
						}
						
						else
							{
							
							
							op_pk_fd_get(rcvd_pkt,0,&msg);
					
							
							switch(msg->type)
							{
				
							case head:// msg from db to head
								count_recev=0;
								count_comer=0;	
							store_keys(msg->info);// head store keys (cluster and symm)
							send_members(msg->info);//send keys to cluster members
							
							
							
							cout<<"head "<<node_objid<<"\n";
							break;
							
							case key:// msg sent from head to members
							total_size=0;
							//get_keys(msg->info);// each member get keys
							store_dec_symkey(msg->info_arr,msg->rand);// for receveing key then decrypt
							//cout<<"after decryption in curr mem"<<"\n";
							src_objid = op_pk_creation_mod_get (rcvd_pkt);
							src_node_objid = op_topo_parent (src_objid);
							//cout<<"mem rec from"<<node_objid<<" "<<src_node_objid<<" "<<op_sim_time() <<"\n";
							
							ann_recev(src_node_objid);
							
							total_size+=(32*3)+(16*8);// overhead after modify
							ann_overhead(src_node_objid,total_size);
							
							
							break;
							
							case recev:
							 src_objid = op_pk_creation_mod_get (rcvd_pkt);
							 src_node_objid = op_topo_parent (src_objid);
							count_recev++;
							
							//cout<<"count recev for"<<" "<<node_objid<<" "<<count_recev<<"\n";
						
							break;
							
							case auth_hash://member received auth message
							total_size=0;
							 src_objid = op_pk_creation_mod_get (rcvd_pkt);
							 src_node_objid = op_topo_parent (src_objid);
							//cout<<"comer rec from"<<node_objid<<" "<<src_node_objid <<"\n";
							manet_rpg_received_stats_update (32.0*3.0);
							ann_recev(src_node_objid);
							ann_comer(src_node_objid);
							total_size+=32*3;// auth_hash
							total_size+=(32)+(32*8);// re_hash
							re_hash(src_node_objid,msg->info);//384 byte
							//cout<<"hash "<<node_objid<<"\n";
							break;
							
							case re_hashed:// head received hashed id
							 src_objid = op_pk_creation_mod_get (rcvd_pkt);
							 src_node_objid = op_topo_parent (src_objid);
							manet_rpg_received_stats_update (32.0+(32.0*8.0));
							count_comer++;
							//cout<<"comer for head"<<node_objid <<" "<<op_sim_time()<<"\n";		
							check_hash(msg->info,src_node_objid);
							
							break;
							case re_keys:// members received  enc ckey from head
							manet_rpg_received_stats_update ((32.0*3.0)+(16.0*8.0));
							total_size+=(32*3)+(16*8);// send enc
							total_size+=(32*3)+(16*8);// re dec  //384// after modif
							src_objid = op_pk_creation_mod_get (rcvd_pkt);
							src_node_objid = op_topo_parent (src_objid);
							re_dec_clukey(msg->info_arr,msg->rand, src_node_objid );// member will dec then re_enc
							//cout<<"rekey "<<node_objid<<"\n";
					
							break;
							
						case re_reenckey:// head received re_enc ckeys from members
							manet_rpg_received_stats_update ((32*3)+(16.0*8.0));
							src_objid = op_pk_creation_mod_get (rcvd_pkt);
							src_node_objid = op_topo_parent (src_objid);
							check_ckey(msg->info_arr,msg->rand,src_node_objid);
							
							break;
							case re_encsymkey:
							//case re_symkey:
							
							manet_rpg_received_stats_update ((32.0*3.0)+(16.0*8.0));// will modify
							src_objid = op_pk_creation_mod_get (rcvd_pkt);
							src_node_objid = op_topo_parent (src_objid);
							
							//cout<<"recv sym"<<src_node_objid<<" "<<node_objid<<" "<<op_sim_time()<<"\n";
							//total_size+=32+(16*8);// send new comer 
							total_size+=(32*3)+(16*8);// new  
							//store_newsymkeys(msg->info);//will modify
							store_dec_symkey(msg->info_arr,msg->rand);
							//cout<<"dec in new mem"<<"\n";
							ann_overhead(src_node_objid,total_size);
						
							default:
							
							break;
					
							}
							
							//delete msg;
								/* Destroy the received packet.	*/				
							//op_pk_destroy(rcvd_pkt);
							packet_destroy(rcvd_pkt);
						
						
							}
						
					
						}
				
				
				
				}
				FSM_PROFILE_SECTION_OUT (state3_exit_exec)


			/** state (dispatch) transition processing **/
			FSM_PROFILE_SECTION_IN ("manet_dispatcher_cluster [dispatch trans conditions]", state3_trans_conds)
			FSM_INIT_COND (SELF_INTERRUPT )
			FSM_DFLT_COND
			FSM_TEST_LOGIC ("dispatch")
			FSM_PROFILE_SECTION_OUT (state3_trans_conds)

			FSM_TRANSIT_SWITCH
				{
				FSM_CASE_TRANSIT (0, 3, state3_enter_exec, manet_rpg_generate_packet ();, "SELF_INTERRUPT ", "manet_rpg_generate_packet ()", "dispatch", "dispatch", "tr_41_0", "manet_dispatcher_cluster [dispatch -> dispatch : SELF_INTERRUPT  / manet_rpg_generate_packet ()]")
				FSM_CASE_TRANSIT (1, 3, state3_enter_exec, ;, "default", "", "dispatch", "dispatch", "tr_33", "manet_dispatcher_cluster [dispatch -> dispatch : default / ]")
				}
				/*---------------------------------------------------------*/



			/** state (wait_2) enter executives **/
			FSM_STATE_ENTER_UNFORCED (4, "wait_2", state4_enter_exec, "manet_dispatcher_cluster [wait_2 enter execs]")
				FSM_PROFILE_SECTION_IN ("manet_dispatcher_cluster [wait_2 enter execs]", state4_enter_exec)
				{
				/** Wait so that all nodes can register their		**/
				/** own addresses in the global list of possible	**/
				/** IP destinations.								**/
				
				
				op_intrpt_schedule_self (op_sim_time (), 0);
				
				
				
				
				}
				FSM_PROFILE_SECTION_OUT (state4_enter_exec)

			/** blocking after enter executives of unforced state. **/
			FSM_EXIT (9,"manet_dispatcher_cluster")


			/** state (wait_2) exit executives **/
			FSM_STATE_EXIT_UNFORCED (4, "wait_2", "manet_dispatcher_cluster [wait_2 exit execs]")
				FSM_PROFILE_SECTION_IN ("manet_dispatcher_cluster [wait_2 exit execs]", state4_exit_exec)
				{
				/* Read in the traffic flow information	*/
				manet_rpg_packet_flow_info_read ();
				}
				FSM_PROFILE_SECTION_OUT (state4_exit_exec)


			/** state (wait_2) transition processing **/
			FSM_TRANSIT_FORCE (3, state3_enter_exec, ;, "default", "", "wait_2", "dispatch", "tr_41", "manet_dispatcher_cluster [wait_2 -> dispatch : default / ]")
				/*---------------------------------------------------------*/



			/** state (wait_0) enter executives **/
			FSM_STATE_ENTER_UNFORCED (5, "wait_0", state5_enter_exec, "manet_dispatcher_cluster [wait_0 enter execs]")
				FSM_PROFILE_SECTION_IN ("manet_dispatcher_cluster [wait_0 enter execs]", state5_enter_exec)
				{
				/** Wait so that all nodes can register their		**/
				/** own addresses in the global list of possible	**/
				/** IP destinations.								**/
				op_intrpt_schedule_self (op_sim_time (), 0);
				}
				FSM_PROFILE_SECTION_OUT (state5_enter_exec)

			/** blocking after enter executives of unforced state. **/
			FSM_EXIT (11,"manet_dispatcher_cluster")


			/** state (wait_0) exit executives **/
			FSM_STATE_EXIT_UNFORCED (5, "wait_0", "manet_dispatcher_cluster [wait_0 exit execs]")
				FSM_PROFILE_SECTION_IN ("manet_dispatcher_cluster [wait_0 exit execs]", state5_exit_exec)
				{
				
				}
				FSM_PROFILE_SECTION_OUT (state5_exit_exec)


			/** state (wait_0) transition processing **/
			FSM_TRANSIT_FORCE (6, state6_enter_exec, ;, "default", "", "wait_0", "wait_1", "tr_39", "manet_dispatcher_cluster [wait_0 -> wait_1 : default / ]")
				/*---------------------------------------------------------*/



			/** state (wait_1) enter executives **/
			FSM_STATE_ENTER_UNFORCED (6, "wait_1", state6_enter_exec, "manet_dispatcher_cluster [wait_1 enter execs]")
				FSM_PROFILE_SECTION_IN ("manet_dispatcher_cluster [wait_1 enter execs]", state6_enter_exec)
				{
				/** Wait so that all nodes can register their		**/
				/** own addresses in the global list of possible	**/
				/** IP destinations.								**/
				op_intrpt_schedule_self (op_sim_time (), 0);
				}
				FSM_PROFILE_SECTION_OUT (state6_enter_exec)

			/** blocking after enter executives of unforced state. **/
			FSM_EXIT (13,"manet_dispatcher_cluster")


			/** state (wait_1) exit executives **/
			FSM_STATE_EXIT_UNFORCED (6, "wait_1", "manet_dispatcher_cluster [wait_1 exit execs]")
				FSM_PROFILE_SECTION_IN ("manet_dispatcher_cluster [wait_1 exit execs]", state6_exit_exec)
				{
				
				}
				FSM_PROFILE_SECTION_OUT (state6_exit_exec)


			/** state (wait_1) transition processing **/
			FSM_TRANSIT_FORCE (1, state1_enter_exec, ;, "default", "", "wait_1", "discover", "tr_32", "manet_dispatcher_cluster [wait_1 -> discover : default / ]")
				/*---------------------------------------------------------*/



			}


		FSM_EXIT (0,"manet_dispatcher_cluster")
		}
	catch (...)
		{
		Vos_Error_Print (VOSC_ERROR_ABORT,
			(const char *)VOSC_NIL,
			"Unhandled C++ exception in process model (manet_dispatcher_cluster)",
			(const char *)VOSC_NIL, (const char *)VOSC_NIL);
		}
	}




void
manet_dispatcher_cluster_state::_op_manet_dispatcher_cluster_diag (OP_SIM_CONTEXT_ARG_OPT)
	{
	/* No Diagnostic Block */
	}

void
manet_dispatcher_cluster_state::operator delete (void* ptr)
	{
	FIN (manet_dispatcher_cluster_state::operator delete (ptr));
	Vos_Poolmem_Dealloc (ptr);
	FOUT
	}

manet_dispatcher_cluster_state::~manet_dispatcher_cluster_state (void)
	{

	FIN (manet_dispatcher_cluster_state::~manet_dispatcher_cluster_state ())


	/* No Termination Block */


	FOUT
	}


#undef FIN_PREAMBLE_DEC
#undef FIN_PREAMBLE_CODE

#define FIN_PREAMBLE_DEC
#define FIN_PREAMBLE_CODE

void *
manet_dispatcher_cluster_state::operator new (size_t)
#if defined (VOSD_NEW_BAD_ALLOC)
		throw (VOSD_BAD_ALLOC)
#endif
	{
	void * new_ptr;

	FIN_MT (manet_dispatcher_cluster_state::operator new ());

	new_ptr = Vos_Alloc_Object (manet_dispatcher_cluster_state::obtype);
#if defined (VOSD_NEW_BAD_ALLOC)
	if (new_ptr == VOSC_NIL) throw VOSD_BAD_ALLOC();
#endif
	FRET (new_ptr)
	}

/* State constructor initializes FSM handling */
/* by setting the initial state to the first */
/* block of code to enter. */

manet_dispatcher_cluster_state::manet_dispatcher_cluster_state (void) :
		_op_current_block (0)
	{
#if defined (OPD_ALLOW_ODB)
		_op_current_state = "manet_dispatcher_cluster [init enter execs]";
#endif
	}

VosT_Obtype
_op_manet_dispatcher_cluster_init (int * init_block_ptr)
	{
	FIN_MT (_op_manet_dispatcher_cluster_init (init_block_ptr))

	manet_dispatcher_cluster_state::obtype = Vos_Define_Object_Prstate ("proc state vars (manet_dispatcher_cluster)",
		sizeof (manet_dispatcher_cluster_state));
	*init_block_ptr = 0;

	FRET (manet_dispatcher_cluster_state::obtype)
	}

VosT_Address
_op_manet_dispatcher_cluster_alloc (VosT_Obtype, int)
	{
#if !defined (VOSD_NO_FIN)
	int _op_block_origin = 0;
#endif
	manet_dispatcher_cluster_state * ptr;
	FIN_MT (_op_manet_dispatcher_cluster_alloc ())

	/* New instance will have FSM handling initialized */
#if defined (VOSD_NEW_BAD_ALLOC)
	try {
		ptr = new manet_dispatcher_cluster_state;
	} catch (const VOSD_BAD_ALLOC &) {
		ptr = VOSC_NIL;
	}
#else
	ptr = new manet_dispatcher_cluster_state;
#endif
	FRET ((VosT_Address)ptr)
	}



void
_op_manet_dispatcher_cluster_svar (void * gen_ptr, const char * var_name, void ** var_p_ptr)
	{
	manet_dispatcher_cluster_state		*prs_ptr;

	FIN_MT (_op_manet_dispatcher_cluster_svar (gen_ptr, var_name, var_p_ptr))

	if (var_name == OPC_NIL)
		{
		*var_p_ptr = (void *)OPC_NIL;
		FOUT
		}
	prs_ptr = (manet_dispatcher_cluster_state *)gen_ptr;

	if (strcmp ("my_objid" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->my_objid);
		FOUT
		}
	if (strcmp ("my_node_objid" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->my_node_objid);
		FOUT
		}
	if (strcmp ("my_subnet_objid" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->my_subnet_objid);
		FOUT
		}
	if (strcmp ("local_packets_received_hndl" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->local_packets_received_hndl);
		FOUT
		}
	if (strcmp ("local_bits_received_hndl" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->local_bits_received_hndl);
		FOUT
		}
	if (strcmp ("local_delay_hndl" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->local_delay_hndl);
		FOUT
		}
	if (strcmp ("global_packets_received_hndl" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->global_packets_received_hndl);
		FOUT
		}
	if (strcmp ("global_bits_received_hndl" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->global_bits_received_hndl);
		FOUT
		}
	if (strcmp ("outstrm_to_ip_encap" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->outstrm_to_ip_encap);
		FOUT
		}
	if (strcmp ("instrm_from_ip_encap" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->instrm_from_ip_encap);
		FOUT
		}
	if (strcmp ("manet_flow_info_array" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->manet_flow_info_array);
		FOUT
		}
	if (strcmp ("higher_layer_proto_id" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->higher_layer_proto_id);
		FOUT
		}
	if (strcmp ("ip_encap_req_ici_ptr" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->ip_encap_req_ici_ptr);
		FOUT
		}
	if (strcmp ("local_packets_sent_hndl" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->local_packets_sent_hndl);
		FOUT
		}
	if (strcmp ("local_bits_sent_hndl" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->local_bits_sent_hndl);
		FOUT
		}
	if (strcmp ("global_packets_sent_hndl" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->global_packets_sent_hndl);
		FOUT
		}
	if (strcmp ("global_bits_sent_hndl" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->global_bits_sent_hndl);
		FOUT
		}
	if (strcmp ("global_delay_hndl" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->global_delay_hndl);
		FOUT
		}
	if (strcmp ("iface_info_ptr" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->iface_info_ptr);
		FOUT
		}
	if (strcmp ("next_pkt_interarrival" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->next_pkt_interarrival);
		FOUT
		}
	if (strcmp ("cluster_key" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->cluster_key);
		FOUT
		}
	if (strcmp ("symmetric_key" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->symmetric_key);
		FOUT
		}
	if (strcmp ("outaes" , var_name) == 0)
		{
		*var_p_ptr = (void *) (prs_ptr->outaes);
		FOUT
		}
	if (strcmp ("ophash" , var_name) == 0)
		{
		*var_p_ptr = (void *) (prs_ptr->ophash);
		FOUT
		}
	if (strcmp ("total_size" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->total_size);
		FOUT
		}
	if (strcmp ("count_recev" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->count_recev);
		FOUT
		}
	if (strcmp ("count_comer" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->count_comer);
		FOUT
		}
	if (strcmp ("misbehave" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->misbehave);
		FOUT
		}
	if (strcmp ("r1" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->r1);
		FOUT
		}
	if (strcmp ("r2" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->r2);
		FOUT
		}
	if (strcmp ("rand_list" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->rand_list);
		FOUT
		}
	if (strcmp ("rand_list_16" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->rand_list_16);
		FOUT
		}
	if (strcmp ("inter_list" , var_name) == 0)
		{
		*var_p_ptr = (void *) (&prs_ptr->inter_list);
		FOUT
		}
	*var_p_ptr = (void *)OPC_NIL;

	FOUT
	}

