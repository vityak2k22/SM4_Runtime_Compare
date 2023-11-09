#include "Main.h"

//=========================================================================================================
int main() {
	string text_in = "INITIALTEXT.txt";
	ifstream in(text_in);
	string text = Input_from_File(in);
	
	fill_text(text);
	translate_text_to_hex(text, "HEX_INPUT.txt");

	string hex_text = {};
	ifstream in_hex("HEX_INPUT.txt");
	hex_text = Input_from_File(in_hex);

	ofstream out("RUNTIME RESULTS.txt");
	for (BYTE i = 0; i < COUNT_RUNS; i++) {
		SM4Process(hex_text, true, false, out);
		SM4Process(hex_text, true, true, out);
		out << "\n";
	}

	in.close();
	in_hex.close();
	out.close();
	return 0;
}
//=========================================================================================================
