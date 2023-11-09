#pragma once
#include "Config.h"
#define HEX_DWORD_BLOCK_SIZE 8														// Розбір 32-бітного блока у шістнадцятковому вигляді
#define C_SHL(x, k) (((x) << (k)) | ((x) >> (sizeof(x)*8L - (k))))

//=========================================================================================================
void SM4Process(string& initialtext, bool is_encrypt, bool is_opt, ofstream& out);	// Функція виконання алгоритму Strumok із заміром часу виконання
void fill_text(string& text);														// Заповнення останнього блоку тексту нулями
void translate_text_to_hex(string& text, const char* path);							// Конвертація та зберігання тексту у шістнадцятковому вигляді у файл
void translate_hex_to_text(string& text, const char* path);							// Конвертація та зберігання тексту у символьному вигляді у файл
//=========================================================================================================