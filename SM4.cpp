#include "SM4.h"
#include "Config.h"

using namespace SM4_Consts;
using namespace SM4_Consts_opt;

//=========================================================================================================
// Заповнення останнього блоку тексту нулями
void fill_text(string& text) {
	BYTE init_length_mod = text.length() % (HEX_DWORD_BLOCK_SIZE * 2);
	DWORD zero_count = init_length_mod ? HEX_DWORD_BLOCK_SIZE * 2 - init_length_mod : 0;
	text.insert(text.end(), zero_count, 0);
}
//=========================================================================================================
// Конвертація та зберігання тексту у символьному вигляді у файл
void translate_hex_to_text(string& text, const char* path) {
	ofstream out(path);
	string ascii_string;
	for (size_t i = 0; i < text.length(); i += 2) {
		string byte_string = text.substr(i, 2);
		char byte = (char)strtol(byte_string.c_str(), NULL, 16);
		ascii_string.push_back(byte);
	}
	out << ascii_string;
	out.close();
}
//=========================================================================================================
// Конвертація та зберігання тексту у шістнадцятковому вигляді у файл
void translate_text_to_hex(string& text, const char* path) {
	FILE* t_hex = fopen(path, "w");
	for (size_t i = 0; i < text.length(); i++)
		fprintf(t_hex, "%02x", text.c_str()[i]);
	fclose(t_hex);
}
//=========================================================================================================
// Функція, яка бере шістнадцяткове значення з рядка та присвоює (X0, X1, X2, Х3)
void take_hex_value_for_dword(DWORD X[], string& hex_text, size_t index) {
	for (BYTE n = 0; n < 4; n++) {
		DWORD value = 0;
		for (size_t j = 0; j < HEX_DWORD_BLOCK_SIZE; j++) {
			char hex_char = hex_text[index + j + (size_t)n * 8];
			if (hex_char >= '0' && hex_char <= '9')
				value = (value << 4) | (hex_char - '0');
			else if (hex_char >= 'A' && hex_char <= 'F')
				value = (value << 4) | (hex_char - 'A' + 10);
			else if (hex_char >= 'a' && hex_char <= 'f')
				value = (value << 4) | (hex_char - 'a' + 10);
		}
		X[n] = value;
	}
}
//=========================================================================================================
// Функція заміни Т
DWORD T(DWORD x, bool is_encrypt) {
	// 1. SBox()
	BYTE q[4] = {};
	DWORD tau = 0;
	for (BYTE n = 0, j = 0; n <= 24 && j < 4; n += 8, j++) {
		q[j] = (BYTE)((x >> n) & 0xFF);
		q[j] = SBox[q[j]];
		tau ^= q[j] << n;
	}

	// 2. L(tau)
	if (is_encrypt)
		return tau ^ C_SHL(tau, 2) ^ C_SHL(tau, 10) ^ C_SHL(tau, 18) ^ C_SHL(tau, 24);
	else
		return tau ^ C_SHL(tau, 13) ^ C_SHL(tau, 23);
}
//=========================================================================================================
// Функція заміни Т для оптимізованого алгоритму
DWORD T_opt(DWORD B, bool is_encrypt) {
	if (is_encrypt)
		return X_A0[(B >> 24) & 0xFF] ^ X_A1[(B >> 16) & 0xFF] ^ X_A2[(B >> 8) & 0xFF] ^ X_A3[B & 0xff];
	else
		return rk_A0[(B >> 24) & 0xFF] ^ rk_A1[(B >> 16) & 0xFF] ^ rk_A2[(B >> 8) & 0xFF] ^ rk_A3[B & 0xff];
}
//=========================================================================================================
// Генерація раундових ключів
void Key_Expansion(DWORD MK[], DWORD rk[], bool is_opt) {
	DWORD K[4] = {};
	K[0] = MK[0] ^ FK[0];
	K[1] = MK[1] ^ FK[1];
	K[2] = MK[2] ^ FK[2];
	K[3] = MK[3] ^ FK[3];

	for (BYTE i = 0; i < 32; i++) {
		is_opt ? rk[i] = K[0] ^ T_opt(K[1] ^ K[2] ^ K[3] ^ CK[i], false) : rk[i] = K[0] ^ T(K[1] ^ K[2] ^ K[3] ^ CK[i], false);

		K[0] = K[1];
		K[1] = K[2];
		K[2] = K[3];
		K[3] = rk[i];
	}
}
//=========================================================================================================
// Раунд шифрування блоку
void SM4_Block(DWORD X[], DWORD rk[], bool is_encrypt, bool is_opt) {
	DWORD Xtemp = 0;
	for (BYTE i = 0; i < 32; i++) {
		if (is_encrypt)
			is_opt ? Xtemp = X[0] ^ T_opt(X[1] ^ X[2] ^ X[3] ^ rk[i], true) : Xtemp = X[0] ^ T(X[1] ^ X[2] ^ X[3] ^ rk[i], true);
		else
			is_opt ? Xtemp = X[0] ^ T_opt(X[1] ^ X[2] ^ X[3] ^ rk[31 - i], true) : Xtemp = X[0] ^ T(X[1] ^ X[2] ^ X[3] ^ rk[31 - i], true);
		X[0] = X[1];
		X[1] = X[2];
		X[2] = X[3];
		X[3] = Xtemp;
	}
}
//=========================================================================================================
// Функція виконання алгоритму Strumok із заміром часу виконання
void SM4Process(string& initialtext, bool is_encrypt, bool is_opt, ofstream& out) {
	// Задання ключа
	DWORD MK[] = { 0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210 };
	
	// Обчислення кількості блоків, на які ділиться текст повідомлення
	DWORD block_count = (DWORD)initialtext.length() / (HEX_DWORD_BLOCK_SIZE * 4);
	DWORD X[4] = {}, rk[32];

	FILE* finaltext = fopen("SM4_HEX_OUTPUT.txt", "w");

	duration<double, std::milli> difference;
	double gen_sum_difference = 0., ex_sum_difference = 0.;
	
	// Тут виконуються COUNT_EX (за замовчуванням 100) запусків алгоритму.
	// Під час кожного запуску відбувається замір часу виконання.
	// На екран виводиться середній час виконанння алгоритму
	for (BYTE num_ex = 0; num_ex < COUNT_EX; num_ex++) {
		// 1. Замір часу генерації ключів
		auto start_KE = high_resolution_clock::now();
		Key_Expansion(MK, rk, is_opt);
		auto end_KE = high_resolution_clock::now();
		
		difference = end_KE - start_KE;
		ex_sum_difference = difference.count();

		// 2. Замір часу шифрування блоку
		for (size_t i = 0; i < block_count; i++) {
			auto start = high_resolution_clock::now();
			
			take_hex_value_for_dword(X, initialtext, i * 32);
			SM4_Block(X, rk, is_encrypt, is_opt);
			
			auto end = high_resolution_clock::now();
			difference = end - start;
			ex_sum_difference += difference.count();

			for (BYTE j = 0; j < 4; j++)
				fprintf(finaltext, "%08x", X[3 - j]);
		}
		gen_sum_difference += ex_sum_difference;
	}
	fclose(finaltext);

	// Вивід середнього часу виконання у файл 
	is_opt ? out << "Optimized SM4 " : out << "SM4 ";
	out << "average runtime: " << gen_sum_difference / COUNT_EX << " ms\n";

	// Вивід кінцевого тексту
	ifstream in("SM4_HEX_OUTPUT.txt");
	string str;
	getline(in, str);
	translate_hex_to_text(str, "CT_CHECK.txt");
	in.close();
}
//=========================================================================================================