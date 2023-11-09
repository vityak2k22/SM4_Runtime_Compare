#pragma once
#include <Windows.h>
#include <string>
#include <iostream>
#include <fstream>
#include <chrono>
#include <sstream>

const double COUNT_EX = 1.;

using namespace std;
using namespace chrono;

//=========================================================================================================
string Input_from_File(ifstream& in);						// �������� ������ ������ � ����� (���������� �������� �����)
//=========================================================================================================
namespace SM4_Consts {
	const BYTE SBox[256] = {
		0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
		0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
		0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
		0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
		0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
		0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
		0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
		0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
		0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
		0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
		0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
		0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
		0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
		0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
		0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
		0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
	};
	const DWORD FK[4] = { 0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc };
	const DWORD CK[32] = {
		0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
		0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
		0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
		0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
		0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
		0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
		0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
		0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
	};
}
//=========================================================================================================
namespace SM4_Consts_opt {
	const DWORD X_A0[256] = {
		0x8ED55B5B, 0xD0924242, 0x4DEAA7A7, 0x6FDFBFB,  0xFCCF3333, 0x65E28787, 0xC93DF4F4, 0x6BB5DEDE,
		0x4E165858, 0x6EB4DADA, 0x44145050, 0xCAC10B0B, 0x8828A0A0, 0x17F8EFEF, 0x9C2CB0B0, 0x11051414,
		0x872BACAC, 0xFB669D9D, 0xF2986A6A, 0xAE77D9D9, 0x822AA8A8, 0x46BCFAFA, 0x14041010, 0xCFC00F0F,
		0x2A8AAAA,  0x54451111, 0x5F134C4C, 0xBE269898, 0x6D482525, 0x9E841A1A, 0x1E061818, 0xFD9B6666,
		0xEC9E7272, 0x4A430909, 0x10514141, 0x24F7D3D3, 0xD5934646, 0x53ECBFBF, 0xF89A6262, 0x927BE9E9,
		0xFF33CCCC, 0x4555151,  0x270B2C2C, 0x4F420D0D, 0x59EEB7B7, 0xF3CC3F3F, 0x1CAEB2B2, 0xEA638989,
		0x74E79393, 0x7FB1CECE, 0x6C1C7070, 0xDABA6A6,  0xEDCA2727, 0x28082020, 0x48EBA3A3, 0xC1975656,
		0x80820202, 0xA3DC7F7F, 0xC4965252, 0x12F9EBEB, 0xA174D5D5, 0xB38D3E3E, 0xC33FFCFC, 0x3EA49A9A,
		0x5B461D1D, 0x1B071C1C, 0x3BA59E9E, 0xCFFF3F3,  0x3FF0CFCF, 0xBF72CDCD, 0x4B175C5C, 0x52B8EAEA,
		0x8F810E0E, 0x3D586565, 0xCC3CF0F0, 0x7D196464, 0x7EE59B9B, 0x91871616, 0x734E3D3D, 0x8AAA2A2,
		0xC869A1A1, 0xC76AADAD, 0x85830606, 0x7AB0CACA, 0xB570C5C5, 0xF4659191, 0xB2D96B6B, 0xA7892E2E,
		0x18FBE3E3, 0x47E8AFAF, 0x330F3C3C, 0x674A2D2D, 0xB071C1C1, 0xE575959,  0xE99F7676, 0xE135D4D4,
		0x661E7878, 0xB4249090, 0x360E3838, 0x265F7979, 0xEF628D8D, 0x38596161, 0x95D24747, 0x2AA08A8A,
		0xB1259494, 0xAA228888, 0x8C7DF1F1, 0xD73BECEC, 0x5010404,  0xA5218484, 0x9879E1E1, 0x9B851E1E,
		0x84D75353, 0x00000000, 0x5E471919, 0xB565D5D,  0xE39D7E7E, 0x9FD04F4F, 0xBB279C9C, 0x1A534949,
		0x7C4D3131, 0xEE36D8D8, 0xA020808,  0x7BE49F9F, 0x20A28282, 0xD4C71313, 0xE8CB2323, 0xE69C7A7A,
		0x42E9ABAB, 0x43BDFEFE, 0xA2882A2A, 0x9AD14B4B, 0x40410101, 0xDBC41F1F, 0xD838E0E0, 0x61B7D6D6,
		0x2FA18E8E, 0x2BF4DFDF, 0x3AF1CBCB, 0xF6CD3B3B, 0x1DFAE7E7, 0xE5608585, 0x41155454, 0x25A38686,
		0x60E38383, 0x16ACBABA, 0x295C7575, 0x34A69292, 0xF7996E6E, 0xE434D0D0, 0x721A6868, 0x1545555,
		0x19AFB6B6, 0xDF914E4E, 0xFA32C8C8, 0xF030C0C0, 0x21F6D7D7, 0xBC8E3232, 0x75B3C6C6, 0x6FE08F8F,
		0x691D7474, 0x2EF5DBDB, 0x6AE18B8B, 0x962EB8B8, 0x8A800A0A, 0xFE679999, 0xE2C92B2B, 0xE0618181,
		0xC0C30303, 0x8D29A4A4, 0xAF238C8C, 0x7A9AEAE,  0x390D3434, 0x1F524D4D, 0x764F3939, 0xD36EBDBD,
		0x81D65757, 0xB7D86F6F, 0xEB37DCDC, 0x51441515, 0xA6DD7B7B, 0x9FEF7F7,  0xB68C3A3A, 0x932FBCBC,
		0xF030C0C,  0x3FCFFFF, 0xC26BA9A9,  0xBA73C9C9, 0xD96CB5B5, 0xDC6DB1B1, 0x375A6D6D, 0x15504545,
		0xB98F3636, 0x771B6C6C, 0x13ADBEBE, 0xDA904A4A, 0x57B9EEEE, 0xA9DE7777, 0x4CBEF2F2, 0x837EFDFD,
		0x55114444, 0xBDDA6767, 0x2C5D7171, 0x45400505, 0x631F7C7C, 0x50104040, 0x325B6969, 0xB8DB6363,
		0x220A2828, 0xC5C20707, 0xF531C4C4, 0xA88A2222, 0x31A79696, 0xF9CE3737, 0x977AEDED, 0x49BFF6F6,
		0x992DB4B4, 0xA475D1D1, 0x90D34343, 0x5A124848, 0x58BAE2E2, 0x71E69797, 0x64B6D2D2, 0x70B2C2C2,
		0xAD8B2626, 0xCD68A5A5, 0xCB955E5E, 0x624B2929, 0x3C0C3030, 0xCE945A5A, 0xAB76DDDD, 0x867FF9F9,
		0xF1649595, 0x5DBBE6E6, 0x35F2C7C7, 0x2D092424, 0xD1C61717, 0xD66FB9B9, 0xDEC51B1B, 0x94861212,
		0x78186060, 0x30F3C3C3, 0x897CF5F5, 0x5CEFB3B3, 0xD23AE8E8, 0xACDF7373, 0x794C3535, 0xA0208080,
		0x9D78E5E5, 0x56EDBBBB, 0x235E7D7D, 0xC63EF8F8, 0x8BD45F5F, 0xE7C82F2F, 0xDD39E4E4, 0x68492121
	};
	const DWORD X_A1[256] = {
		0x5B8ED55B, 0x42D09242, 0xA74DEAA7, 0xFB06FDFB, 0x33FCCF33, 0x8765E287, 0xF4C93DF4, 0xDE6BB5DE,
		0x584E1658, 0xDA6EB4DA, 0x50441450, 0xBCAC10B,  0xA08828A0, 0xEF17F8EF, 0xB09C2CB0, 0x14110514,
		0xAC872BAC, 0x9DFB669D, 0x6AF2986A, 0xD9AE77D9, 0xA8822AA8, 0xFA46BCFA, 0x10140410, 0xFCFC00F,
		0xAA02A8AA, 0x11544511, 0x4C5F134C, 0x98BE2698, 0x256D4825, 0x1A9E841A, 0x181E0618, 0x66FD9B66,
		0x72EC9E72, 0x94A4309,  0x41105141, 0xD324F7D3, 0x46D59346, 0xBF53ECBF, 0x62F89A62, 0xE9927BE9,
		0xCCFF33CC, 0x51045551, 0x2C270B2C, 0xD4F420D,  0xB759EEB7, 0x3FF3CC3F, 0xB21CAEB2, 0x89EA6389,
		0x9374E793, 0xCE7FB1CE, 0x706C1C70, 0xA60DABA6, 0x27EDCA27, 0x20280820, 0xA348EBA3, 0x56C19756,
		0x2808202,  0x7FA3DC7F, 0x52C49652, 0xEB12F9EB, 0xD5A174D5, 0x3EB38D3E, 0xFCC33FFC, 0x9A3EA49A,
		0x1D5B461D, 0x1C1B071C, 0x9E3BA59E, 0xF30CFFF3, 0xCF3FF0CF, 0xCDBF72CD, 0x5C4B175C, 0xEA52B8EA,
		0xE8F810E,  0x653D5865, 0xF0CC3CF0, 0x647D1964, 0x9B7EE59B, 0x16918716, 0x3D734E3D, 0xA208AAA2,
		0xA1C869A1, 0xADC76AAD, 0x6858306,  0xCA7AB0CA, 0xC5B570C5, 0x91F46591, 0x6BB2D96B, 0x2EA7892E,
		0xE318FBE3, 0xAF47E8AF, 0x3C330F3C, 0x2D674A2D, 0xC1B071C1, 0x590E5759, 0x76E99F76, 0xD4E135D4,
		0x78661E78, 0x90B42490, 0x38360E38, 0x79265F79, 0x8DEF628D, 0x61385961, 0x4795D247, 0x8A2AA08A,
		0x94B12594, 0x88AA2288, 0xF18C7DF1, 0xECD73BEC, 0x4050104,  0x84A52184, 0xE19879E1, 0x1E9B851E,
		0x5384D753, 0x00000000, 0x195E4719, 0x5D0B565D, 0x7EE39D7E, 0x4F9FD04F, 0x9CBB279C, 0x491A5349,
		0x317C4D31, 0xD8EE36D8, 0x80A0208,  0x9F7BE49F, 0x8220A282, 0x13D4C713, 0x23E8CB23, 0x7AE69C7A,
		0xAB42E9AB, 0xFE43BDFE, 0x2AA2882A, 0x4B9AD14B, 0x1404101,  0x1FDBC41F, 0xE0D838E0, 0xD661B7D6,
		0x8E2FA18E, 0xDF2BF4DF, 0xCB3AF1CB, 0x3BF6CD3B, 0xE71DFAE7, 0x85E56085, 0x54411554, 0x8625A386,
		0x8360E383, 0xBA16ACBA, 0x75295C75, 0x9234A692, 0x6EF7996E, 0xD0E434D0, 0x68721A68, 0x55015455,
		0xB619AFB6, 0x4EDF914E, 0xC8FA32C8, 0xC0F030C0, 0xD721F6D7, 0x32BC8E32, 0xC675B3C6, 0x8F6FE08F,
		0x74691D74, 0xDB2EF5DB, 0x8B6AE18B, 0xB8962EB8, 0xA8A800A,  0x99FE6799, 0x2BE2C92B, 0x81E06181,
		0x3C0C303,  0xA48D29A4, 0x8CAF238C, 0xAE07A9AE, 0x34390D34, 0x4D1F524D, 0x39764F39, 0xBDD36EBD,
		0x5781D657, 0x6FB7D86F, 0xDCEB37DC, 0x15514415, 0x7BA6DD7B, 0xF709FEF7, 0x3AB68C3A, 0xBC932FBC,
		0xC0F030C,  0xFF03FCFF, 0xA9C26BA9, 0xC9BA73C9, 0xB5D96CB5, 0xB1DC6DB1, 0x6D375A6D, 0x45155045,
		0x36B98F36, 0x6C771B6C, 0xBE13ADBE, 0x4ADA904A, 0xEE57B9EE, 0x77A9DE77, 0xF24CBEF2, 0xFD837EFD,
		0x44551144, 0x67BDDA67, 0x712C5D71, 0x5454005,  0x7C631F7C, 0x40501040, 0x69325B69, 0x63B8DB63,
		0x28220A28, 0x7C5C207,  0xC4F531C4, 0x22A88A22, 0x9631A796, 0x37F9CE37, 0xED977AED, 0xF649BFF6,
		0xB4992DB4, 0xD1A475D1, 0x4390D343, 0x485A1248, 0xE258BAE2, 0x9771E697, 0xD264B6D2, 0xC270B2C2,
		0x26AD8B26, 0xA5CD68A5, 0x5ECB955E, 0x29624B29, 0x303C0C30, 0x5ACE945A, 0xDDAB76DD, 0xF9867FF9,
		0x95F16495, 0xE65DBBE6, 0xC735F2C7, 0x242D0924, 0x17D1C617, 0xB9D66FB9, 0x1BDEC51B, 0x12948612,
		0x60781860, 0xC330F3C3, 0xF5897CF5, 0xB35CEFB3, 0xE8D23AE8, 0x73ACDF73, 0x35794C35, 0x80A02080,
		0xE59D78E5, 0xBB56EDBB, 0x7D235E7D, 0xF8C63EF8, 0x5F8BD45F, 0x2FE7C82F, 0xE4DD39E4, 0x21684921
	};
	const DWORD X_A2[256] = {
		0x5B5B8ED5, 0x4242D092, 0xA7A74DEA, 0xFBFB06FD, 0x3333FCCF, 0x878765E2, 0xF4F4C93D, 0xDEDE6BB5,
		0x58584E16, 0xDADA6EB4, 0x50504414, 0xB0BCAC1,  0xA0A08828, 0xEFEF17F8, 0xB0B09C2C, 0x14141105,
		0xACAC872B, 0x9D9DFB66, 0x6A6AF298, 0xD9D9AE77, 0xA8A8822A, 0xFAFA46BC, 0x10101404, 0xF0FCFC0,
		0xAAAA02A8, 0x11115445, 0x4C4C5F13, 0x9898BE26, 0x25256D48, 0x1A1A9E84, 0x18181E06, 0x6666FD9B,
		0x7272EC9E, 0x9094A43,  0x41411051, 0xD3D324F7, 0x4646D593, 0xBFBF53EC, 0x6262F89A, 0xE9E9927B,
		0xCCCCFF33, 0x51510455, 0x2C2C270B, 0xD0D4F42,  0xB7B759EE, 0x3F3FF3CC, 0xB2B21CAE, 0x8989EA63,
		0x939374E7, 0xCECE7FB1, 0x70706C1C, 0xA6A60DAB, 0x2727EDCA, 0x20202808, 0xA3A348EB, 0x5656C197,
		0x2028082,  0x7F7FA3DC, 0x5252C496, 0xEBEB12F9, 0xD5D5A174, 0x3E3EB38D, 0xFCFCC33F, 0x9A9A3EA4,
		0x1D1D5B46, 0x1C1C1B07, 0x9E9E3BA5, 0xF3F30CFF, 0xCFCF3FF0, 0xCDCDBF72, 0x5C5C4B17, 0xEAEA52B8,
		0xE0E8F81,  0x65653D58, 0xF0F0CC3C, 0x64647D19, 0x9B9B7EE5, 0x16169187, 0x3D3D734E, 0xA2A208AA,
		0xA1A1C869, 0xADADC76A, 0x6068583,  0xCACA7AB0, 0xC5C5B570, 0x9191F465, 0x6B6BB2D9, 0x2E2EA789,
		0xE3E318FB, 0xAFAF47E8, 0x3C3C330F, 0x2D2D674A, 0xC1C1B071, 0x59590E57, 0x7676E99F, 0xD4D4E135,
		0x7878661E, 0x9090B424, 0x3838360E, 0x7979265F, 0x8D8DEF62, 0x61613859, 0x474795D2, 0x8A8A2AA0,
		0x9494B125, 0x8888AA22, 0xF1F18C7D, 0xECECD73B, 0x4040501,  0x8484A521, 0xE1E19879, 0x1E1E9B85,
		0x535384D7, 0x00000000, 0x19195E47, 0x5D5D0B56, 0x7E7EE39D, 0x4F4F9FD0, 0x9C9CBB27, 0x49491A53,
		0x31317C4D, 0xD8D8EE36, 0x8080A02,  0x9F9F7BE4, 0x828220A2, 0x1313D4C7, 0x2323E8CB, 0x7A7AE69C,
		0xABAB42E9, 0xFEFE43BD, 0x2A2AA288, 0x4B4B9AD1, 0x1014041,  0x1F1FDBC4, 0xE0E0D838, 0xD6D661B7,
		0x8E8E2FA1, 0xDFDF2BF4, 0xCBCB3AF1, 0x3B3BF6CD, 0xE7E71DFA, 0x8585E560, 0x54544115, 0x868625A3,
		0x838360E3, 0xBABA16AC, 0x7575295C, 0x929234A6, 0x6E6EF799, 0xD0D0E434, 0x6868721A, 0x55550154,
		0xB6B619AF, 0x4E4EDF91, 0xC8C8FA32, 0xC0C0F030, 0xD7D721F6, 0x3232BC8E, 0xC6C675B3, 0x8F8F6FE0,
		0x7474691D, 0xDBDB2EF5, 0x8B8B6AE1, 0xB8B8962E, 0xA0A8A80,  0x9999FE67, 0x2B2BE2C9, 0x8181E061,
		0x303C0C3,  0xA4A48D29, 0x8C8CAF23, 0xAEAE07A9, 0x3434390D, 0x4D4D1F52, 0x3939764F, 0xBDBDD36E,
		0x575781D6, 0x6F6FB7D8, 0xDCDCEB37, 0x15155144, 0x7B7BA6DD, 0xF7F709FE, 0x3A3AB68C, 0xBCBC932F,
		0xC0C0F03,  0xFFFF03FC, 0xA9A9C26B, 0xC9C9BA73, 0xB5B5D96C, 0xB1B1DC6D, 0x6D6D375A, 0x45451550,
		0x3636B98F, 0x6C6C771B, 0xBEBE13AD, 0x4A4ADA90, 0xEEEE57B9, 0x7777A9DE, 0xF2F24CBE, 0xFDFD837E,
		0x44445511, 0x6767BDDA, 0x71712C5D, 0x5054540,  0x7C7C631F, 0x40405010, 0x6969325B, 0x6363B8DB,
		0x2828220A, 0x707C5C2,  0xC4C4F531, 0x2222A88A, 0x969631A7, 0x3737F9CE, 0xEDED977A, 0xF6F649BF,
		0xB4B4992D, 0xD1D1A475, 0x434390D3, 0x48485A12, 0xE2E258BA, 0x979771E6, 0xD2D264B6, 0xC2C270B2,
		0x2626AD8B, 0xA5A5CD68, 0x5E5ECB95, 0x2929624B, 0x30303C0C, 0x5A5ACE94, 0xDDDDAB76, 0xF9F9867F,
		0x9595F164, 0xE6E65DBB, 0xC7C735F2, 0x24242D09, 0x1717D1C6, 0xB9B9D66F, 0x1B1BDEC5, 0x12129486,
		0x60607818, 0xC3C330F3, 0xF5F5897C, 0xB3B35CEF, 0xE8E8D23A, 0x7373ACDF, 0x3535794C, 0x8080A020,
		0xE5E59D78, 0xBBBB56ED, 0x7D7D235E, 0xF8F8C63E, 0x5F5F8BD4, 0x2F2FE7C8, 0xE4E4DD39, 0x21216849
	};
	const DWORD X_A3[256] = {
		0xD55B5B8E, 0x924242D0, 0xEAA7A74D, 0xFDFBFB06, 0xCF3333FC, 0xE2878765, 0x3DF4F4C9, 0xB5DEDE6B,
		0x1658584E, 0xB4DADA6E, 0x14505044, 0xC10B0BCA, 0x28A0A088, 0xF8EFEF17, 0x2CB0B09C, 0x5141411,
		0x2BACAC87, 0x669D9DFB, 0x986A6AF2, 0x77D9D9AE, 0x2AA8A882, 0xBCFAFA46, 0x4101014,  0xC00F0FCF,
		0xA8AAAA02, 0x45111154, 0x134C4C5F, 0x269898BE, 0x4825256D, 0x841A1A9E, 0x618181E,  0x9B6666FD,
		0x9E7272EC, 0x4309094A, 0x51414110, 0xF7D3D324, 0x934646D5, 0xECBFBF53, 0x9A6262F8, 0x7BE9E992,
		0x33CCCCFF, 0x55515104, 0xB2C2C27,  0x420D0D4F, 0xEEB7B759, 0xCC3F3FF3, 0xAEB2B21C, 0x638989EA,
		0xE7939374, 0xB1CECE7F, 0x1C70706C, 0xABA6A60D, 0xCA2727ED, 0x8202028,  0xEBA3A348, 0x975656C1,
		0x82020280, 0xDC7F7FA3, 0x965252C4, 0xF9EBEB12, 0x74D5D5A1, 0x8D3E3EB3, 0x3FFCFCC3, 0xA49A9A3E,
		0x461D1D5B, 0x71C1C1B,  0xA59E9E3B, 0xFFF3F30C, 0xF0CFCF3F, 0x72CDCDBF, 0x175C5C4B, 0xB8EAEA52,
		0x810E0E8F, 0x5865653D, 0x3CF0F0CC, 0x1964647D, 0xE59B9B7E, 0x87161691, 0x4E3D3D73, 0xAAA2A208,
		0x69A1A1C8, 0x6AADADC7, 0x83060685, 0xB0CACA7A, 0x70C5C5B5, 0x659191F4, 0xD96B6BB2, 0x892E2EA7,
		0xFBE3E318, 0xE8AFAF47, 0xF3C3C33,  0x4A2D2D67, 0x71C1C1B0, 0x5759590E, 0x9F7676E9, 0x35D4D4E1,
		0x1E787866, 0x249090B4, 0xE383836,  0x5F797926, 0x628D8DEF, 0x59616138, 0xD2474795, 0xA08A8A2A,
		0x259494B1, 0x228888AA, 0x7DF1F18C, 0x3BECECD7, 0x1040405,  0x218484A5, 0x79E1E198, 0x851E1E9B,
		0xD7535384, 0x00000000, 0x4719195E, 0x565D5D0B, 0x9D7E7EE3, 0xD04F4F9F, 0x279C9CBB, 0x5349491A,
		0x4D31317C, 0x36D8D8EE, 0x208080A,  0xE49F9F7B, 0xA2828220, 0xC71313D4, 0xCB2323E8, 0x9C7A7AE6,
		0xE9ABAB42, 0xBDFEFE43, 0x882A2AA2, 0xD14B4B9A, 0x41010140, 0xC41F1FDB, 0x38E0E0D8, 0xB7D6D661,
		0xA18E8E2F, 0xF4DFDF2B, 0xF1CBCB3A, 0xCD3B3BF6, 0xFAE7E71D, 0x608585E5, 0x15545441, 0xA3868625,
		0xE3838360, 0xACBABA16, 0x5C757529, 0xA6929234, 0x996E6EF7, 0x34D0D0E4, 0x1A686872, 0x54555501,
		0xAFB6B619, 0x914E4EDF, 0x32C8C8FA, 0x30C0C0F0, 0xF6D7D721, 0x8E3232BC, 0xB3C6C675, 0xE08F8F6F,
		0x1D747469, 0xF5DBDB2E, 0xE18B8B6A, 0x2EB8B896, 0x800A0A8A, 0x679999FE, 0xC92B2BE2, 0x618181E0,
		0xC30303C0, 0x29A4A48D, 0x238C8CAF, 0xA9AEAE07, 0xD343439,  0x524D4D1F, 0x4F393976, 0x6EBDBDD3,
		0xD6575781, 0xD86F6FB7, 0x37DCDCEB, 0x44151551, 0xDD7B7BA6, 0xFEF7F709, 0x8C3A3AB6, 0x2FBCBC93,
		0x30C0C0F,  0xFCFFFF03, 0x6BA9A9C2, 0x73C9C9BA, 0x6CB5B5D9, 0x6DB1B1DC, 0x5A6D6D37, 0x50454515,
		0x8F3636B9, 0x1B6C6C77, 0xADBEBE13, 0x904A4ADA, 0xB9EEEE57, 0xDE7777A9, 0xBEF2F24C, 0x7EFDFD83,
		0x11444455, 0xDA6767BD, 0x5D71712C, 0x40050545, 0x1F7C7C63, 0x10404050, 0x5B696932, 0xDB6363B8,
		0xA282822,  0xC20707C5, 0x31C4C4F5, 0x8A2222A8, 0xA7969631, 0xCE3737F9, 0x7AEDED97, 0xBFF6F649,
		0x2DB4B499, 0x75D1D1A4, 0xD3434390, 0x1248485A, 0xBAE2E258, 0xE6979771, 0xB6D2D264, 0xB2C2C270,
		0x8B2626AD, 0x68A5A5CD, 0x955E5ECB, 0x4B292962, 0xC30303C,  0x945A5ACE, 0x76DDDDAB, 0x7FF9F986,
		0x649595F1, 0xBBE6E65D, 0xF2C7C735, 0x924242D,  0xC61717D1, 0x6FB9B9D6, 0xC51B1BDE, 0x86121294,
		0x18606078, 0xF3C3C330, 0x7CF5F589, 0xEFB3B35C, 0x3AE8E8D2, 0xDF7373AC, 0x4C353579, 0x208080A0,
		0x78E5E59D, 0xEDBBBB56, 0x5E7D7D23, 0x3EF8F8C6, 0xD45F5F8B, 0xC82F2FE7, 0x39E4E4DD, 0x49212168
	};
	const DWORD rk_A0[256] = {
		0xD66B1AC0, 0x90481200, 0xE9749D20, 0xFE7F1FC0, 0xCC661980, 0xE1709C20, 0x3D1E87A0, 0xB75B96E0,
		0x160B02C0, 0xB65B16C0, 0x140A0280, 0xC2611840, 0x28140500, 0xFB7D9F60, 0x2C160580, 0x50280A0,
		0x2B158560, 0x67338CE0, 0x9A4D1340, 0x763B0EC0, 0x2A150540, 0xBE5F17C0, 0x4020080,  0xC3619860,
		0xAA551540, 0x44220880, 0x13098260, 0x261304C0, 0x49248920, 0x864310C0, 0x60300C0,  0x994C9320,
		0x9C4E1380, 0x42210840, 0x50280A00, 0xF47A1E80, 0x91489220, 0xEF779DE0, 0x984C1300, 0x7A3D0F40,
		0x33198660, 0x542A0A80, 0xB058160,  0x43218860, 0xED769DA0, 0xCF6799E0, 0xAC561580, 0x62310C40,
		0xE4721C80, 0xB3599660, 0x1C0E0380, 0xA9549520, 0xC9649920, 0x8040100,  0xE8741D00, 0x954A92A0,
		0x80401000, 0xDF6F9BE0, 0x944A1280, 0xFA7D1F40, 0x753A8EA0, 0x8F4791E0, 0x3F1F87E0, 0xA65314C0,
		0x472388E0, 0x70380E0,  0xA75394E0, 0xFC7E1F80, 0xF3799E60, 0x73398E60, 0x170B82E0, 0xBA5D1740,
		0x83419060, 0x592C8B20, 0x3C1E0780, 0x190C8320, 0xE6731CC0, 0x854290A0, 0x4F2789E0, 0xA8541500,
		0x68340D00, 0x6B358D60, 0x81409020, 0xB2591640, 0x71388E20, 0x64320C80, 0xDA6D1B40, 0x8B459160,
		0xF87C1F00, 0xEB759D60, 0xF0781E0,  0x4B258960, 0x70380E00, 0x562B0AC0, 0x9D4E93A0, 0x351A86A0,
		0x1E0F03C0, 0x24120480, 0xE0701C0,  0x5E2F0BC0, 0x63318C60, 0x582C0B00, 0xD1689A20, 0xA2511440,
		0x251284A0, 0x22110440, 0x7C3E0F80, 0x3B1D8760, 0x1008020,  0x21108420, 0x783C0F00, 0x874390E0,
		0x6A1A80,   0x00000000, 0x462308C0, 0x572B8AE0, 0x9F4F93E0, 0xD3699A60, 0x271384E0, 0x52290A40,
		0x4C260980, 0x361B06C0, 0x2010040,  0xE7739CE0, 0xA0501400, 0xC4621880, 0xC8641900, 0x9E4F13C0,
		0xEA751D40, 0xBF5F97E0, 0x8A451140, 0xD2691A40, 0x40200800, 0xC76398E0, 0x381C0700, 0xB55A96A0,
		0xA3519460, 0xF77B9EE0, 0xF2791E40, 0xCE6719C0, 0xF97C9F20, 0x61308C20, 0x150A82A0, 0xA1509420,
		0xE0701C00, 0xAE5715C0, 0x5D2E8BA0, 0xA4521480, 0x9B4D9360, 0x341A0680, 0x1A0D0340, 0x552A8AA0,
		0xAD5695A0, 0x93499260, 0x32190640, 0x30180600, 0xF57A9EA0, 0x8C461180, 0xB1589620, 0xE3719C60,
		0x1D0E83A0, 0xF67B1EC0, 0xE2711C40, 0x2E1705C0, 0x82411040, 0x66330CC0, 0xCA651940, 0x60300C00,
		0xC0601800, 0x29148520, 0x23118460, 0xAB559560, 0xD0681A0,  0x53298A60, 0x4E2709C0, 0x6F378DE0,
		0xD56A9AA0, 0xDB6D9B60, 0x371B86E0, 0x452288A0, 0xDE6F1BC0, 0xFD7E9FA0, 0x8E4711C0, 0x2F1785E0,
		0x3018060,  0xFF7F9FE0, 0x6A350D40, 0x72390E40, 0x6D368DA0, 0x6C360D80, 0x5B2D8B60, 0x51288A20,
		0x8D4691A0, 0x1B0D8360, 0xAF5795E0, 0x92491240, 0xBB5D9760, 0xDD6E9BA0, 0xBC5E1780, 0x7F3F8FE0,
		0x11088220, 0xD96C9B20, 0x5C2E0B80, 0x41208820, 0xF0F83E0,  0x10080200, 0x5A2D0B40, 0xD86C1B00,
		0xA050140,  0xC1609820, 0x31188620, 0x88441100, 0xA55294A0, 0xCD6699A0, 0x7B3D8F60, 0xBD5E97A0,
		0x2D1685A0, 0x743A0E80, 0xD0681A00, 0x12090240, 0xB85C1700, 0xE5729CA0, 0xB45A1680, 0xB0581600,
		0x89449120, 0x69348D20, 0x974B92E0, 0x4A250940, 0xC060180,  0x964B12C0, 0x773B8EE0, 0x7E3F0FC0,
		0x65328CA0, 0xB95C9720, 0xF1789E20, 0x9048120,  0xC56298A0, 0x6E370DC0, 0xC66318C0, 0x84421080,
		0x180C0300, 0xF0781E00, 0x7D3E8FA0, 0xEC761D80, 0x3A1D0740, 0xDC6E1B80, 0x4D2689A0, 0x20100400,
		0x793C8F20, 0xEE771DC0, 0x5F2F8BE0, 0x3E1F07C0, 0xD76B9AE0, 0xCB659960, 0x391C8720, 0x48240900
	};
	const DWORD rk_A1[256] = {
		0xC0D66B1A, 0x904812, 0x20E9749D, 0xC0FE7F1F, 0x80CC6619, 0x20E1709C, 0xA03D1E87, 0xE0B75B96,
		0xC0160B02, 0xC0B65B16, 0x80140A02, 0x40C26118, 0x281405, 0x60FB7D9F, 0x802C1605, 0xA0050280,
		0x602B1585, 0xE067338C, 0x409A4D13, 0xC0763B0E, 0x402A1505, 0xC0BE5F17, 0x80040200, 0x60C36198,
		0x40AA5515, 0x80442208, 0x60130982, 0xC0261304, 0x20492489, 0xC0864310, 0xC0060300, 0x20994C93,
		0x809C4E13, 0x40422108, 0x50280A, 0x80F47A1E, 0x20914892, 0xE0EF779D, 0x984C13, 0x407A3D0F,
		0x60331986, 0x80542A0A, 0x600B0581, 0x60432188, 0xA0ED769D, 0xE0CF6799, 0x80AC5615, 0x4062310C,
		0x80E4721C, 0x60B35996, 0x801C0E03, 0x20A95495, 0x20C96499, 0x80401, 0xE8741D, 0xA0954A92,
		0x804010, 0xE0DF6F9B, 0x80944A12, 0x40FA7D1F, 0xA0753A8E, 0xE08F4791, 0xE03F1F87, 0xC0A65314,
		0xE0472388, 0xE0070380, 0xE0A75394, 0x80FC7E1F, 0x60F3799E, 0x6073398E, 0xE0170B82, 0x40BA5D17,
		0x60834190, 0x20592C8B, 0x803C1E07, 0x20190C83, 0xC0E6731C, 0xA0854290, 0xE04F2789, 0xA85415,
		0x68340D, 0x606B358D, 0x20814090, 0x40B25916, 0x2071388E, 0x8064320C, 0x40DA6D1B, 0x608B4591,
		0xF87C1F, 0x60EB759D, 0xE00F0781, 0x604B2589, 0x70380E, 0xC0562B0A, 0xA09D4E93, 0xA0351A86, 0xC01E0F03,
		0x80241204, 0xC00E0701, 0xC05E2F0B, 0x6063318C, 0x582C0B, 0x20D1689A, 0x40A25114, 0xA0251284,
		0x40221104, 0x807C3E0F, 0x603B1D87, 0x20010080, 0x20211084, 0x783C0F, 0xE0874390, 0x80D46A1A, 0x00000000,
		0xC0462308, 0xE0572B8A, 0xE09F4F93, 0x60D3699A, 0xE0271384, 0x4052290A, 0x804C2609, 0xC0361B06,
		0x40020100, 0xE0E7739C, 0xA05014, 0x80C46218, 0xC86419, 0xC09E4F13, 0x40EA751D, 0xE0BF5F97,
		0x408A4511, 0x40D2691A, 0x402008, 0xE0C76398, 0x381C07, 0xA0B55A96, 0x60A35194, 0xE0F77B9E,
		0x40F2791E, 0xC0CE6719, 0x20F97C9F, 0x2061308C, 0xA0150A82, 0x20A15094, 0xE0701C, 0xC0AE5715,
		0xA05D2E8B, 0x80A45214, 0x609B4D93, 0x80341A06, 0x401A0D03, 0xA0552A8A, 0xA0AD5695, 0x60934992,
		0x40321906, 0x301806, 0xA0F57A9E, 0x808C4611, 0x20B15896, 0x60E3719C, 0xA01D0E83, 0xC0F67B1E,
		0x40E2711C, 0xC02E1705, 0x40824110, 0xC066330C, 0x40CA6519, 0x60300C, 0xC06018, 0x20291485,
		0x60231184, 0x60AB5595, 0xA00D0681, 0x6053298A, 0xC04E2709, 0xE06F378D, 0xA0D56A9A, 0x60DB6D9B,
		0xE0371B86, 0xA0452288, 0xC0DE6F1B, 0xA0FD7E9F, 0xC08E4711, 0xE02F1785, 0x60030180, 0xE0FF7F9F,
		0x406A350D, 0x4072390E, 0xA06D368D, 0x806C360D, 0x605B2D8B, 0x2051288A, 0xA08D4691, 0x601B0D83,
		0xE0AF5795, 0x40924912, 0x60BB5D97, 0xA0DD6E9B, 0x80BC5E17, 0xE07F3F8F, 0x20110882, 0x20D96C9B,
		0x805C2E0B, 0x20412088, 0xE01F0F83, 0x100802, 0x405A2D0B, 0xD86C1B, 0x400A0501, 0x20C16098,
		0x20311886, 0x884411, 0xA0A55294, 0xA0CD6699, 0x607B3D8F, 0xA0BD5E97, 0xA02D1685, 0x80743A0E,
		0xD0681A, 0x40120902, 0xB85C17, 0xA0E5729C, 0x80B45A16, 0xB05816, 0x20894491, 0x2069348D,
		0xE0974B92, 0x404A2509, 0x800C0601, 0xC0964B12, 0xE0773B8E, 0xC07E3F0F, 0xA065328C, 0x20B95C97,
		0x20F1789E, 0x20090481, 0xA0C56298, 0xC06E370D, 0xC0C66318, 0x80844210, 0x180C03, 0xF0781E,
		0xA07D3E8F, 0x80EC761D, 0x403A1D07, 0x80DC6E1B, 0xA04D2689, 0x201004, 0x20793C8F, 0xC0EE771D,
		0xE05F2F8B, 0xC03E1F07, 0xE0D76B9A, 0x60CB6599, 0x20391C87, 0x482409
	};
	const DWORD rk_A2[256] = {
		0x1AC0D66B, 0x12009048, 0x9D20E974, 0x1FC0FE7F, 0x1980CC66, 0x9C20E170, 0x87A03D1E, 0x96E0B75B,
		0x2C0160B,  0x16C0B65B, 0x280140A,  0x1840C261, 0x5002814,  0x9F60FB7D, 0x5802C16,  0x80A00502,
		0x85602B15, 0x8CE06733, 0x13409A4D, 0xEC0763B,  0x5402A15,  0x17C0BE5F, 0x800402,   0x9860C361,
		0x1540AA55, 0x8804422,  0x82601309, 0x4C02613,  0x89204924, 0x10C08643, 0xC00603,   0x9320994C,
		0x13809C4E, 0x8404221,  0xA005028,  0x1E80F47A, 0x92209148, 0x9DE0EF77, 0x1300984C, 0xF407A3D,
		0x86603319, 0xA80542A,  0x81600B05, 0x88604321, 0x9DA0ED76, 0x99E0CF67, 0x1580AC56, 0xC406231,
		0x1C80E472, 0x9660B359, 0x3801C0E,  0x9520A954, 0x9920C964, 0x1000804,  0x1D00E874, 0x92A0954A,
		0x10008040, 0x9BE0DF6F, 0x1280944A, 0x1F40FA7D, 0x8EA0753A, 0x91E08F47, 0x87E03F1F, 0x14C0A653,
		0x88E04723, 0x80E00703, 0x94E0A753, 0x1F80FC7E, 0x9E60F379, 0x8E607339, 0x82E0170B, 0x1740BA5D,
		0x90608341, 0x8B20592C, 0x7803C1E,  0x8320190C, 0x1CC0E673, 0x90A08542, 0x89E04F27, 0x1500A854,
		0xD006834,  0x8D606B35, 0x90208140, 0x1640B259, 0x8E207138, 0xC806432,  0x1B40DA6D, 0x91608B45,
		0x1F00F87C, 0x9D60EB75, 0x81E00F07, 0x89604B25, 0xE007038,  0xAC0562B,  0x93A09D4E, 0x86A0351A,
		0x3C01E0F,  0x4802412,  0x1C00E07,  0xBC05E2F,  0x8C606331, 0xB00582C,  0x9A20D168, 0x1440A251,
		0x84A02512, 0x4402211,  0xF807C3E,  0x87603B1D, 0x80200100, 0x84202110, 0xF00783C,  0x90E08743,
		0x1A80D46A, 0x00000000, 0x8C04623,  0x8AE0572B, 0x93E09F4F, 0x9A60D369, 0x84E02713, 0xA405229,
		0x9804C26,  0x6C0361B,  0x400201,   0x9CE0E773, 0x1400A050, 0x1880C462, 0x1900C864, 0x13C09E4F,
		0x1D40EA75, 0x97E0BF5F, 0x11408A45, 0x1A40D269, 0x8004020,  0x98E0C763, 0x700381C,  0x96A0B55A,
		0x9460A351, 0x9EE0F77B, 0x1E40F279, 0x19C0CE67, 0x9F20F97C, 0x8C206130, 0x82A0150A, 0x9420A150,
		0x1C00E070, 0x15C0AE57, 0x8BA05D2E, 0x1480A452, 0x93609B4D, 0x680341A,  0x3401A0D,  0x8AA0552A,
		0x95A0AD56, 0x92609349, 0x6403219,  0x6003018,  0x9EA0F57A, 0x11808C46, 0x9620B158, 0x9C60E371,
		0x83A01D0E, 0x1EC0F67B, 0x1C40E271, 0x5C02E17,  0x10408241, 0xCC06633,  0x1940CA65, 0xC006030,
		0x1800C060, 0x85202914, 0x84602311, 0x9560AB55, 0x81A00D06, 0x8A605329, 0x9C04E27,  0x8DE06F37,
		0x9AA0D56A, 0x9B60DB6D, 0x86E0371B, 0x88A04522, 0x1BC0DE6F, 0x9FA0FD7E, 0x11C08E47, 0x85E02F17,
		0x80600301, 0x9FE0FF7F, 0xD406A35,  0xE407239,  0x8DA06D36, 0xD806C36,  0x8B605B2D, 0x8A205128,
		0x91A08D46, 0x83601B0D, 0x95E0AF57, 0x12409249, 0x9760BB5D, 0x9BA0DD6E, 0x1780BC5E, 0x8FE07F3F,
		0x82201108, 0x9B20D96C, 0xB805C2E,  0x88204120, 0x83E01F0F, 0x2001008,  0xB405A2D,  0x1B00D86C,
		0x1400A05,  0x9820C160, 0x86203118, 0x11008844, 0x94A0A552, 0x99A0CD66, 0x8F607B3D, 0x97A0BD5E,
		0x85A02D16, 0xE80743A,  0x1A00D068, 0x2401209,  0x1700B85C, 0x9CA0E572, 0x1680B45A, 0x1600B058,
		0x91208944, 0x8D206934, 0x92E0974B, 0x9404A25,  0x1800C06,  0x12C0964B, 0x8EE0773B, 0xFC07E3F,
		0x8CA06532, 0x9720B95C, 0x9E20F178, 0x81200904, 0x98A0C562, 0xDC06E37,  0x18C0C663, 0x10808442,
		0x300180C,  0x1E00F078, 0x8FA07D3E, 0x1D80EC76, 0x7403A1D,  0x1B80DC6E, 0x89A04D26, 0x4002010,
		0x8F20793C, 0x1DC0EE77, 0x8BE05F2F, 0x7C03E1F,  0x9AE0D76B, 0x9960CB65, 0x8720391C, 0x9004824
	};
	const DWORD rk_A3[256] = {
		0x6B1AC0D6, 0x48120090, 0x749D20E9, 0x7F1FC0FE, 0x661980CC, 0x709C20E1, 0x1E87A03D, 0x5B96E0B7,
		0xB02C016,  0x5B16C0B6, 0xA028014,  0x611840C2, 0x14050028, 0x7D9F60FB, 0x1605802C, 0x280A005,
		0x1585602B, 0x338CE067, 0x4D13409A, 0x3B0EC076, 0x1505402A, 0x5F17C0BE, 0x2008004,  0x619860C3,
		0x551540AA, 0x22088044, 0x9826013,  0x1304C026, 0x24892049, 0x4310C086, 0x300C006,  0x4C932099,
		0x4E13809C, 0x21084042, 0x280A0050, 0x7A1E80F4, 0x48922091, 0x779DE0EF, 0x4C130098, 0x3D0F407A,
		0x19866033, 0x2A0A8054, 0x581600B,  0x21886043, 0x769DA0ED, 0x6799E0CF, 0x561580AC, 0x310C4062,
		0x721C80E4, 0x599660B3, 0xE03801C,  0x549520A9, 0x649920C9, 0x4010008,  0x741D00E8, 0x4A92A095,
		0x40100080, 0x6F9BE0DF, 0x4A128094, 0x7D1F40FA, 0x3A8EA075, 0x4791E08F, 0x1F87E03F, 0x5314C0A6,
		0x2388E047, 0x380E007,  0x5394E0A7, 0x7E1F80FC, 0x799E60F3, 0x398E6073, 0xB82E017,  0x5D1740BA,
		0x41906083, 0x2C8B2059, 0x1E07803C, 0xC832019,  0x731CC0E6, 0x4290A085, 0x2789E04F, 0x541500A8,
		0x340D0068, 0x358D606B, 0x40902081, 0x591640B2, 0x388E2071, 0x320C8064, 0x6D1B40DA, 0x4591608B,
		0x7C1F00F8, 0x759D60EB, 0x781E00F,  0x2589604B, 0x380E0070, 0x2B0AC056, 0x4E93A09D, 0x1A86A035,
		0xF03C01E,  0x12048024, 0x701C00E,  0x2F0BC05E, 0x318C6063, 0x2C0B0058, 0x689A20D1, 0x511440A2,
		0x1284A025, 0x11044022, 0x3E0F807C, 0x1D87603B, 0x802001,   0x10842021, 0x3C0F0078, 0x4390E087,
		0x6A1A80D4, 0x00000000, 0x2308C046, 0x2B8AE057, 0x4F93E09F, 0x699A60D3, 0x1384E027, 0x290A4052,
		0x2609804C, 0x1B06C036, 0x1004002,  0x739CE0E7, 0x501400A0, 0x621880C4, 0x641900C8, 0x4F13C09E,
		0x751D40EA, 0x5F97E0BF, 0x4511408A, 0x691A40D2, 0x20080040, 0x6398E0C7, 0x1C070038, 0x5A96A0B5,
		0x519460A3, 0x7B9EE0F7, 0x791E40F2, 0x6719C0CE, 0x7C9F20F9, 0x308C2061, 0xA82A015,  0x509420A1,
		0x701C00E0, 0x5715C0AE, 0x2E8BA05D, 0x521480A4, 0x4D93609B, 0x1A068034, 0xD03401A,  0x2A8AA055,
		0x5695A0AD, 0x49926093, 0x19064032, 0x18060030, 0x7A9EA0F5, 0x4611808C, 0x589620B1, 0x719C60E3,
		0xE83A01D,  0x7B1EC0F6, 0x711C40E2, 0x1705C02E, 0x41104082, 0x330CC066, 0x651940CA, 0x300C0060,
		0x601800C0, 0x14852029, 0x11846023, 0x559560AB, 0x681A00D,  0x298A6053, 0x2709C04E, 0x378DE06F,
		0x6A9AA0D5, 0x6D9B60DB, 0x1B86E037, 0x2288A045, 0x6F1BC0DE, 0x7E9FA0FD, 0x4711C08E, 0x1785E02F,
		0x1806003,  0x7F9FE0FF, 0x350D406A, 0x390E4072, 0x368DA06D, 0x360D806C, 0x2D8B605B, 0x288A2051,
		0x4691A08D, 0xD83601B,  0x5795E0AF, 0x49124092, 0x5D9760BB, 0x6E9BA0DD, 0x5E1780BC, 0x3F8FE07F,
		0x8822011,  0x6C9B20D9, 0x2E0B805C, 0x20882041, 0xF83E01F,  0x8020010,  0x2D0B405A, 0x6C1B00D8,
		0x501400A,  0x609820C1, 0x18862031, 0x44110088, 0x5294A0A5, 0x6699A0CD, 0x3D8F607B, 0x5E97A0BD,
		0x1685A02D, 0x3A0E8074, 0x681A00D0, 0x9024012,  0x5C1700B8, 0x729CA0E5, 0x5A1680B4, 0x581600B0,
		0x44912089, 0x348D2069, 0x4B92E097, 0x2509404A, 0x601800C,  0x4B12C096, 0x3B8EE077, 0x3F0FC07E,
		0x328CA065, 0x5C9720B9, 0x789E20F1, 0x4812009,  0x6298A0C5, 0x370DC06E, 0x6318C0C6, 0x42108084,
		0xC030018,  0x781E00F0, 0x3E8FA07D, 0x761D80EC, 0x1D07403A, 0x6E1B80DC, 0x2689A04D, 0x10040020,
		0x3C8F2079, 0x771DC0EE, 0x2F8BE05F, 0x1F07C03E, 0x6B9AE0D7, 0x659960CB, 0x1C872039, 0x24090048
	};
}
//=========================================================================================================