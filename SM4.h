#pragma once
#include "Config.h"
#define HEX_DWORD_BLOCK_SIZE 8														// ����� 32-������ ����� � ���������������� ������
#define C_SHL(x, k) (((x) << (k)) | ((x) >> (sizeof(x)*8L - (k))))

//=========================================================================================================
void SM4Process(string& initialtext, bool is_encrypt, bool is_opt, ofstream& out);	// ������� ��������� ��������� Strumok �� ������ ���� ���������
void fill_text(string& text);														// ���������� ���������� ����� ������ ������
void translate_text_to_hex(string& text, const char* path);							// ����������� �� ��������� ������ � ���������������� ������ � ����
void translate_hex_to_text(string& text, const char* path);							// ����������� �� ��������� ������ � ����������� ������ � ����
//=========================================================================================================