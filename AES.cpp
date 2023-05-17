#include<string>
#include <iostream>

using namespace std;

class AES {
public:
	string *splittxt, newkey[11], A[16], K[16], B[16], C[16];
	string sbox[16][16] = {
		{"63", "7C", "77", "7B", "F2", "6B", "6F", "C5", "30", "01", "67", "2B", "FE", "D7", "AB", "76"}, //0
		{"CA", "82", "C9", "7D", "FA", "59", "47", "F0", "AD", "D4", "A2", "AF", "9C", "A4", "72", "C0"}, //1
		{"B7", "FD", "93", "26", "36", "3F", "F7", "CC", "34", "A5", "E5", "F1", "71", "D8", "31", "15"}, //2
		{"04", "C7", "23", "C3", "18", "96", "05", "9A", "07", "12", "80", "E2", "EB", "27", "B2", "75"}, //3
		{"09", "83", "2C", "1A", "1B", "6E", "5A", "A0", "52", "3B", "D6", "B3", "29", "E3", "2F", "84"}, //4
		{"53", "D1", "00", "ED", "20", "FC", "B1", "5B", "6A", "CB", "BE", "39", "4A", "4C", "58", "CF"}, //5
		{"D0", "EF", "AA", "FB", "43", "4D", "33", "85", "45", "F9", "02", "7F", "50", "3C", "9F", "A8"}, //6
		{"51", "A3", "40", "8F", "92", "9D", "38", "F5", "BC", "B6", "DA", "21", "10", "FF", "F3", "D2"}, //7
		{"CD", "0C", "13", "EC", "5F", "97", "44", "17", "C4", "A7", "7E", "3D", "64", "5D", "19", "73"}, //8
		{"60", "81", "4F", "DC", "22", "2A", "90", "88", "46", "EE", "B8", "14", "DE", "5E", "0B", "DB"}, //9
		{"E0", "32", "3A", "0A", "49", "06", "24", "5C", "C2", "D3", "AC", "62", "91", "95", "E4", "79"}, //A
		{"E7", "C8", "37", "6D", "8D", "D5", "4E", "A9", "6C", "56", "F4", "EA", "65", "7A", "AE", "08"}, //B
		{"BA", "78", "25", "2E", "1C", "A6", "B4", "C6", "E8", "DD", "74", "1F", "4B", "BD", "8B", "8A"}, //C
		{"70", "3E", "B5", "66", "48", "03", "F6", "0E", "61", "35", "57", "B9", "86", "C1", "1D", "9E"}, //D
		{"E1", "F8", "98", "11", "69", "D9", "8E", "94", "9B", "1E", "87", "E9", "CE", "55", "28", "DF"}, //E
		{"8C", "A1", "89", "0D", "BF", "E6", "42", "68", "41", "99", "2D", "0F", "B0", "54", "BB", "16"} //F
	};
	string RC[10] = {
		"00000001","00000010","00000100","00001000","00010000","00100000","01000000","10000000","00011011","00110110"
	};
	string multof2[16][16] = 
	{
		{"00","02","04","06","08","0A","0C","0E","10","12","14","16","18","1A","1C","1E"},
		{"20","22","24","26","28","2A","2C","2E","30","32","34","36","38","3A","3C","3E"},
		{"40","42","44","46","48","4A","4C","4E","50","52","54","56","58","5A","5C","5E"},
		{"60","62","64","66","68","6A","6C","6E","70","72","74","76","78","7A","7C","7E"},
		{"80","82","84","86","88","8A","8C","8E","90","92","94","96","98","9A","9C","9E"},
		{"A0","A2","A4","A6","A8","AA","AC","AE","B0","B2","B4","B6","B8","BA","BC","BE"},
		{"C0","C2","C4","C6","C8","CA","CC","CE","D0","D2","D4","D6","D8","DA","DC","DE"},
		{"E0","E2","E4","E6","E8","EA","EC","EE","F0","F2","F4","F6","F8","FA","FC","FE"},
		{"1B","19","1F","1D","13","11","17","15","0B","09","0F","0D","03","01","07","05"},
		{"3B","39","3F","3D","33","31","37","35","2B","29","2F","2D","23","21","27","25"},
		{"5B","59","5F","5D","53","51","57","55","4B","49","4F","4D","43","41","47","45"},
		{"7B","79","7F","7D","73","71","77","75","6B","69","6F","6D","63","61","67","65"},
		{"9B","99","9F","9D","93","91","97","95","8B","89","8F","8D","83","81","87","85"},
		{"BB","B9","BF","BD","B3","B1","B7","B5","AB","A9","AF","AD","A3","A1","A7","A5"},
		{"DB","D9","DF","DD","D3","D1","D7","D5","CB","C9","CF","CD","C3","C1","C7","C5"},
		{"FB","F9","FF","FD","F3","F1","F7","F5","EB","E9","EF","ED","E3","E1","E7","E5"}
	};
	string multof3[16][16] = 
	{
		{"00","03","06","05","0C","0F","0A","09","18","1B","1E","1D","14","17","12","11"},
		{"30","33","36","35","3C","3F","3A","39","28","2B","2E","2D","24","27","22","21"},
		{"60","63","66","65","6C","6F","6A","69","78","7B","7E","7D","74","77","72","71"},
		{"50","53","56","55","5C","5F","5A","59","48","4B","4E","4D","44","47","42","41"},
		{"C0","C3","C6","C5","CC","CF","CA","C9","D8","DB","DE","DD","D4","D7","D2","D1"},
		{"F0","F3","F6","F5","FC","FF","FA","F9","E8","EB","EE","ED","E4","E7","E2","E1"},
		{"A0","A3","A6","A5","AC","AF","AA","A9","B8","BB","BE","BD","B4","B7","B2","B1"},
		{"90","93","96","95","9C","9F","9A","99","88","8B","8E","8D","84","87","82","81"},
		{"9B","98","9D","9E","97","94","91","92","83","80","85","86","8F","8C","89","8A"},
		{"AB","A8","AD","AE","A7","A4","A1","A2","B3","B0","B5","B6","BF","BC","B9","BA"},
		{"FB","F8","FD","FE","F7","F4","F1","F2","E3","E0","E5","E6","EF","EC","E9","EA"},
		{"CB","C8","CD","CE","C7","C4","C1","C2","D3","D0","D5","D6","DF","DC","D9","DA"},
		{"5B","58","5D","5E","57","54","51","52","43","40","45","46","4F","4C","49","4A"},
		{"6B","68","6D","6E","67","64","61","62","73","70","75","76","7F","7C","79","7A"},
		{"3B","38","3D","3E","37","34","31","32","23","20","25","26","2F","2C","29","2A"},
		{"0B","08","0D","0E","07","04","01","02","13","10","15","16","1F","1C","19","1A"}
	};
	string invsbox[16][16] = {
		{"52", "09", "6A", "D5", "30", "36", "A5", "38", "BF", "40", "A3", "9E", "81", "F3", "D7", "FB"},
		{"7C", "E3", "39", "82", "9B", "2F", "FF", "87", "34", "8E", "43", "44", "C4", "DE", "E9", "CB"},
		{"54", "7B", "94", "32", "A6", "C2", "23", "3D", "EE", "4C", "95", "0B", "42", "FA", "C3", "4E"},
		{"08", "2E", "A1", "66", "28", "D9", "24", "B2", "76", "5B", "A2", "49", "6D", "8B", "D1", "25"},
		{"72", "F8", "F6", "64", "86", "68", "98", "16", "D4", "A4", "5C", "CC", "5D", "65", "B6", "92"},
		{"6C", "70", "48", "50", "FD", "ED", "B9", "DA", "5E", "15", "46", "57", "A7", "8D", "9D", "84"},
		{"90", "D8", "AB", "00", "8C", "BC", "D3", "0A", "F7", "E4", "58", "05", "B8", "B3", "45", "06"},
		{"D0", "2C", "1E", "8F", "CA", "3F", "0F", "02", "C1", "AF", "BD", "03", "01", "13", "8A", "6B"},
		{"3A", "91", "11", "41", "4F", "67", "DC", "EA", "97", "F2", "CF", "CE", "F0", "B4", "E6", "73"},
		{"96", "AC", "74", "22", "E7", "AD", "35", "85", "E2", "F9", "37", "E8", "1C", "75", "DF", "6E"},
		{"47", "F1", "1A", "71", "1D", "29", "C5", "89", "6F", "B7", "62", "0E", "AA", "18", "BE", "1B"},
		{"FC", "56", "3E", "4B", "C6", "D2", "79", "20", "9A", "DB", "C0", "FE", "78", "CD", "5A", "F4"},
		{"1F", "DD", "A8", "33", "88", "07", "C7", "31", "B1", "12", "10", "59", "27", "80", "EC", "5F"},
		{"60", "51", "7F", "A9", "19", "B5", "4A", "0D", "2D", "E5", "7A", "9F", "93", "C9", "9C", "EF"},
		{"A0", "E0", "3B", "4D", "AE", "2A", "F5", "B0", "C8", "EB", "BB", "3C", "83", "53", "99", "61"},
		{"17", "2B", "04", "7E", "BA", "77", "D6", "26", "E1", "69", "14", "63", "55", "21", "0C", "7D"}
	};
	string multof9[16][16] =
	{
	{"00","09","12","1B","24","2D","36","3F","48","41","5A","53","6C","65","7E","77"},
	{"90","99","82","8B","B4","BD","A6","AF","D8","D1","CA","C3","FC","F5","EE","E7"},
	{"3B","32","29","20","1F","16","0D","04","73","7A","61","68","57","5E","45","4C"},
	{"AB","A2","B9","B0","8F","86","9D","94","E3","EA","F1","F8","C7","CE","D5","DC"},
	{"76","7F","64","6D","52","5B","40","49","3E","37","2C","25","1A","13","08","01"},
	{"E6","EF","F4","FD","C2","CB","D0","D9","AE","A7","BC","B5","8A","83","98","91"},
	{"4D","44","5F","56","69","60","7B","72","05","0C","17","1E","21","28","33","3A"},
	{"DD","D4","CF","C6","F9","F0","EB","E2","95","9C","87","8E","B1","B8","A3","AA"},
	{"EC","E5","FE","F7","C8","C1","DA","D3","A4","AD","B6","BF","80","89","92","9B"},
	{"7C","75","6E","67","58","51","4A","43","34","3D","26","2F","10","19","02","0B"},
	{"D7","DE","C5","CC","F3","FA","E1","E8","9F","96","8D","84","BB","B2","A9","A0"},
	{"47","4E","55","5C","63","6A","71","78","0F","06","1D","14","2B","22","39","30"},
	{"9A","93","88","81","BE","B7","AC","A5","D2","DB","C0","C9","F6","FF","E4","ED"},
	{"0A","03","18","11","2E","27","3C","35","42","4B","50","59","66","6F","74","7D"},
	{"A1","A8","B3","BA","85","8C","97","9E","E9","E0","FB","F2","CD","C4","DF","D6"},
	{"31","38","23","2A","15","1C","07","0E","79","70","6B","62","5D","54","4F","46"}
	};

	string multofB[16][16] =
	{
	{"00","0B","16","1D","2C","27","3A","31","58","53","4E","45","74","7F","62","69"},
	{"B0","BB","A6","AD","9C","97","8A","81","E8","E3","FE","F5","C4","CF","D2","D9"},
	{"7B","70","6D","66","57","5C","41","4A","23","28","35","3E","0F","04","19","12"},
	{"CB","C0","DD","D6","E7","EC","F1","FA","93","98","85","8E","BF","B4","A9","A2"},
	{"F6","FD","E0","EB","DA","D1","CC","C7","AE","A5","B8","B3","82","89","94","9F"},
	{"46","4D","50","5B","6A","61","7C","77","1E","15","08","03","32","39","24","2F"},
	{"8D","86","9B","90","A1","AA","B7","BC","D5","DE","C3","C8","F9","F2","EF","E4"},
	{"3D","36","2B","20","11","1A","07","0C","65","6E","73","78","49","42","5F","54"},
	{"F7","FC","E1","EA","DB","D0","CD","C6","AF","A4","B9","B2","83","88","95","9E"},
	{"47","4C","51","5A","6B","60","7D","76","1F","14","09","02","33","38","25","2E"},
	{"8C","87","9A","91","A0","AB","B6","BD","D4","DF","C2","C9","F8","F3","EE","E5"},
	{"3C","37","2A","21","10","1B","06","0D","64","6F","72","79","48","43","5E","55"},
	{"01","0A","17","1C","2D","26","3B","30","59","52","4F","44","75","7E","63","68"},
	{"B1","BA","A7","AC","9D","96","8B","80","E9","E2","FF","F4","C5","CE","D3","D8"},
	{"7A","71","6C","67","56","5D","40","4B","22","29","34","3F","0E","05","18","13"},
	{"CA","C1","DC","D7","E6","ED","F0","FB","92","99","84","8F","BE","B5","A8","A3"}
	};
	string multofD[16][16] =
	{
		{"00","0D","1A","17","34","39","2E","23","68","65","72","7F","5C","51","46","4B"},
		{"D0","DD","CA","C7","E4","E9","FE","F3","B8","B5","A2","AF","8C","81","96","9B"},
		{"BB","B6","A1","AC","8F","82","95","98","D3","DE","C9","C4","E7","EA","FD","F0"},
		{"6B","66","71","7C","5F","52","45","48","03","0E","19","14","37","3A","2D","20"},
		{"6D","60","77","7A","59","54","43","4E","05","08","1F","12","31","3C","2B","26"},
		{"BD","B0","A7","AA","89","84","93","9E","D5","D8","CF","C2","E1","EC","FB","F6"},
		{"D6","DB","CC","C1","E2","EF","F8","F5","BE","B3","A4","A9","8A","87","90","9D"},
		{"06","0B","1C","11","32","3F","28","25","6E","63","74","79","5A","57","40","4D"},
		{"DA","D7","C0","CD","EE","E3","F4","F9","B2","BF","A8","A5","86","8B","9C","91"},
		{"0A","07","10","1D","3E","33","24","29","62","6F","78","75","56","5B","4C","41"},
		{"61","6C","7B","76","55","58","4F","42","09","04","13","1E","3D","30","27","2A"},
		{"B1","BC","AB","A6","85","88","9F","92","D9","D4","C3","CE","ED","E0","F7","FA"},
		{"B7","BA","AD","A0","83","8E","99","94","DF","D2","C5","C8","EB","E6","F1","FC"},
		{"67","6A","7D","70","53","5E","49","44","0F","02","15","18","3B","36","21","2C"},
		{"0C","01","16","1B","38","35","22","2F","64","69","7E","73","50","5D","4A","47"},
		{"DC","D1","C6","CB","E8","E5","F2","FF","B4","B9","AE","A3","80","8D","9A","97"}
	};
	string multofE[16][16] =
	{
		{"00","0E","1C","12","38","36","24","2A","70","7E","6C","62","48","46","54","5A" },
		{"E0","EE","FC","F2","D8","D6","C4","CA","90","9E","8C","82","A8","A6","B4","BA"},
		{"DB","D5","C7","C9","E3","ED","FF","F1","AB","A5","B7","B9","93","9D","8F","81"},
		{"3B","35","27","29","03","0D","1F","11","4B","45","57","59","73","7D","6F","61"},
		{"AD","A3","B1","BF","95","9B","89","87","DD","D3","C1","CF","E5","EB","F9","F7"},
		{"4D","43","51","5F","75","7B","69","67","3D","33","21","2F","05","0B","19","17"},
		{"76","78","6A","64","4E","40","52","5C","06","08","1A","14","3E","30","22","2C"},
		{"96","98","8A","84","AE","A0","B2","BC","E6","E8","FA","F4","DE","D0","C2","CC"},
		{"41","4F","5D","53","79","77","65","6B","31","3F","2D","23","09","07","15","1B"},
		{"A1","AF","BD","B3","99","97","85","8B","D1","DF","CD","C3","E9","E7","F5","FB"},
		{"9A","94","86","88","A2","AC","BE","B0","EA","E4","F6","F8","D2","DC","CE","C0"},
		{"7A","74","66","68","42","4C","5E","50","0A","04","16","18","32","3C","2E","20"},
		{"EC","E2","F0","FE","D4","DA","C8","C6","9C","92","80","8E","A4","AA","B8","B6"},
		{"0C","02","10","1E","34","3A","28","26","7C","72","60","6E","44","4A","58","56"},
		{"37","39","2B","25","0F","01","13","1D","47","49","5B","55","7F","71","63","6D"},
		{"D7","D9","CB","C5","EF","E1","F3","FD","A7","A9","BB","B5","9F","91","83","8D"}
	};


	string XOR(string x, string y)
	{
		int n = x.size();
		string newtxt = "";
		for (int i = 0; i < n; i++) {
			if (x[i] != y[i])
				newtxt += "1";
			else
				newtxt += "0";
		}
		return newtxt;
	}
	string checkbin(char s1, char s2, char s3, char s4) {
		string newtxt = "";
		switch (s1) {
		case '0':
			switch (s2) {
			case '0':
				if (s3 == '0')
					if (s4 == '0')
						newtxt = "0";
					else
						newtxt = "1";
				else
					if (s4 == '0')
						newtxt = "2";
					else
						newtxt = "3";
				break;
			case '1':
				if (s3 == '0')
					if (s4 == '0')
						newtxt = "4";
					else
						newtxt = "5";
				else
					if (s4 == '0')
						newtxt = "6";
					else
						newtxt = "7";
				break;
			}
			break;
		case '1':
			switch (s2) {
			case '0':
				if (s3 == '0')
					if (s4 == '0')
						newtxt = "8";
					else
						newtxt = "9";
				else
					if (s4 == '0')
						newtxt = "A";
					else
						newtxt = "B";
				break;
			case '1':
				if (s3 == '0')
					if (s4 == '0')
						newtxt = "C";
					else
						newtxt = "D";
				else
					if (s4 == '0')
						newtxt = "E";
					else
						newtxt = "F";
				break;
			}
		}
		return newtxt;
	}
	string convertBH(string txt) {
		int n = txt.size();
		string newtxt = "";
		for (int i = 0; i < n; i += 4) {
			newtxt += checkbin(txt[i], txt[i + 1], txt[i + 2], txt[i + 3]);
		}
		return newtxt;
	}
	string checkhex(char txt) {
		string newtxt = "";
		switch (txt) {
		case '0':
			newtxt = "0000";
			break;
		case '1':
			newtxt = "0001";
			break;
		case '2':
			newtxt = "0010";
			break;
		case '3':
			newtxt = "0011";
			break;
		case '4':
			newtxt = "0100";
			break;
		case '5':
			newtxt = "0101";
			break;
		case '6':
			newtxt = "0110";
			break;
		case '7':
			newtxt = "0111";
			break;
		case '8':
			newtxt = "1000";
			break;
		case '9':
			newtxt = "1001";
			break;
		case 'A':
			newtxt = "1010";
			break;
		case 'B':
			newtxt = "1011";
			break;
		case 'C':
			newtxt = "1100";
			break;
		case 'D':
			newtxt = "1101";
			break;
		case 'E':
			newtxt = "1110";
			break;
		case 'F':
			newtxt = "1111";
			break;
		}
		return newtxt;
	}
	string convertHB(string txt) {
		char newtxt = ' ';
		string result = "";
		int n = txt.size();
		for (int i = 0; i < n; i++) {
			newtxt = txt[i];
			result += checkhex(newtxt);
		}
		return  result;
	}
	string convertDH(string txt) {
		int m = txt.size();
		string newtxt = "", tmp;
		int n = 0;
		for (int i = 0; i < m; i++) {
			n = int(char(txt[i]));
			while (n != 0) {
				int rem = 0;
				char ch;
				rem = n % 16;
				if (rem < 10) {
					ch = rem + 48;
				}
				else {
					ch = rem + 55;
				}
				tmp += ch;
				n = n / 16;
			}
			int start = 0, end = tmp.size() - 1;
			while (start <= end)
			{
				swap(tmp[start], tmp[end]);
				start++;
				end--;
			}
			newtxt += tmp;
			tmp = "";
		}
		return newtxt;
	}
	int decblocks(string txt) {
		string newtxt = "";
		int i = txt.size() / 64;
		splittxt = new string[i];
		for (int j = 0; j < i; j++) {
			newtxt = "";
			for (int k = 64 * j; k < 64 * (j + 1); k++) {
				newtxt += txt[k];
			}
			splittxt[j] = newtxt;
		}
		return (i);
	}
	int convertHD(string txt)
	{
		int base = 1;
		int newtxt = 0;
		for (int i = txt.size() - 1; i >= 0; i--) {
			if (txt[i] >= '0' && txt[i] <= '9') {
				newtxt += (int(txt[i]) - 48) * base;
				base = base * 16;
			}
			else if (txt[i] >= 'A' && txt[i] <= 'F') {
				newtxt += (int(txt[i]) - 55) * base;
				base = base * 16;
			}
		}
		return newtxt;
	}
	/*string hexdec(string n)
	{
		string x[2] = {"",""};
		for (int i = 0; i < 2; i++) {
			switch (n[i]) {
			case 'A':
				x[i] = 10;
				break;
			case 'B':
				x[i] = 11;
				break;
			case 'C':
				x[i] = 12;
				break;
			case 'D':
				x[i] = 13;
				break;
			case 'E':
				x[i] = 14;
				break;
			case 'F':
				x[i] = 15;
				break;
			default:
				break;
			}
		}
		if (x[0] == "" || x[1] == "") {
			x[0] = n[0];
			x[1] = n[1];
		}
		string word = x[0] + x[1];
		return word;
	}*/
	int minus7(int n1)
	{
		if (n1 > 9)
			n1 = n1 - 7;
		else 
			n1 = n1;
		return n1;
	}
	string convertHA(string txt) {
		string newtxt = "", asci = "";
		for (int i = 0; i < txt.length(); i += 2) {
			newtxt = txt.substr(i, 2);
			char a = convertHD(newtxt);
			asci += a;
		}
		cout << asci;
		return asci;
	}
	int blocks(string txt) {
		string newtxt = "", combine = "";
		int reminder = txt.size() % 128;
		int n = txt.size() - reminder;
		int sub = 128 - reminder;
		if (reminder != 0) {
			for (int k = 0; k < sub; k++) {
				newtxt += "0";
			}
		}
		combine = txt + newtxt;
		int i = n / 128;
		splittxt = new string[i + 1];
		for (int j = 0; j < i + 1; j++) {
			newtxt = "";
			for (int k = 128 * j; k < 128 * (j + 1); k++) {
				newtxt += combine[k];
			}
			splittxt[j] = newtxt;
		}
		return (i + 1);
	}
	string g(string w, int n) {
		string tmp[4], newword, newtmp[4], boxhex;
		int j = 0;
		for (int i = 0; i < 4; i ++) {
			tmp[i] = w.substr(i*8, 8);
			//cout << "tmp w[ "<<i <<"]  "<< tmp[i] << endl;
			newtmp[i] = convertBH(tmp[i]);
			//cout << "newtmp BH[ " << i << "]  " << newtmp[i] << endl;
			int n1 = int(newtmp[i][0]-'0'), n2 = int(newtmp[i][1]-'0');
			n1 = minus7(n1);//if n1>9 minus 7 to get its value because hex -48 for <9 -55 for (A,B,C,D,E,F)
			n2 = minus7(n2);
			//cout << "tmp 0 " << n1 << " tmp 1 " << n2 << endl;
			boxhex = sbox[n1][n2];
			//cout << "boxhex [" <<  boxhex << "]  " << endl;
			newtmp[i] = convertHB(boxhex);
			//cout << "newtmp HB [" << i << "]  " << newtmp[i] << endl;
		}
		tmp[0] = newtmp[1];
		//cout << "tmp 0 " << tmp[0];
		tmp[1] = newtmp[2];		
		//cout << "\ntmp 1 " << tmp[1];
		tmp[2] = newtmp[3];
		//cout << "\ntmp 2 " << tmp[2];
		tmp[3] = newtmp[0];
		//cout << "\ntmp 3 " << tmp[3];
		tmp[0] = XOR(tmp[0], RC[n - 1]);
		//cout << "\ntmp 0 " << tmp[0];
		newword = tmp[0] + tmp[1] + tmp[2] + tmp[3];
		//cout << "\nnewword: " << convertBH(newword) << endl;
		return newword;
	}
	void wordsplit(string k) {
		string Word[44];
		for (int i = 0; i < 4; i++) {
			Word[i] = k.substr(i * 32, 32);
			//cout << "word key " << i <<Word[i] << endl;
		}
		for (int i = 1; i < 11; i++) {
			Word[4 * i] = XOR(Word[4 * (i - 1)] , g(Word[(4 * i) - 1], i));
			//cout <<"word: " <<4*i<< convertBH(Word[4 * i])<<endl;
			for (int m = 1; m < 4; m++) {
				Word[4 * i + m] = XOR(Word[4 * i + m - 1], Word[4 * (i - 1) + m]);
			}
			newkey[i] = Word[4 * i] + Word[4 * i + 1] + Word[4 * i + 2] + Word[4 * i + 3];
			//cout <<"key "<<i<<"  "<< convertBH(newkey[i]) << endl;
		}
	}
	void txtsplit(string txt) {
		for (int i = 0; i < 16; i++) {
			A[i] = txt.substr(i * 8, 8);
		}
	}
	void keyaddition(int j) {
		for (int i = 0; i < 16; i++) {
			K[i] = newkey[j].substr(i * 8, 8);
		}
	}
	void SubBytes() {
		string newA;
		for (int i = 0; i < 16; i++) {
			newA = convertBH(A[i]);
			int n1 = int(newA[0] - '0'), n2 = int(newA[1] - '0');
			n1 = minus7(n1);//if n1>9 minus 7 to get its value because hex -48 for <9 -55 for (A,B,C,D,E,F)
			n2 = minus7(n2);
			newA = sbox[n1][n2];
			A[i] = convertHB(newA);
		}
	}
	void ShiftRows() {
		B[0] = convertBH(A[0]);
		B[4] = convertBH(A[4]);
		B[8] = convertBH(A[8]);
		B[12] = convertBH(A[12]);
		B[1] = convertBH(A[5]);
		B[5] = convertBH(A[9]);
		B[9] = convertBH(A[13]);
		B[13] = convertBH(A[1]);
		B[2] = convertBH(A[10]);
		B[6] = convertBH(A[14]);
		B[10] = convertBH(A[2]);
		B[14] = convertBH(A[6]);
		B[3] = convertBH(A[15]);
		B[7] = convertBH(A[3]);
		B[11] = convertBH(A[7]);
		B[15] = convertBH(A[11]);
	}/*
	void matmult(int b0, int b1, int b2, int b3) {
		string columns[4];
		int newcolumns[4];
		int mult[4];
		columns[0]= convertBH(B[b0]);
		int n1 = int(columns[0][0] - '0'), n2 = int(columns[0][1] - '0');
		n1 = minus7(n1);//if n1>9 minus 7 to get its value because hex -48 for <9 -55 for (A,B,C,D,E,F)
		n2 = minus7(n2);
		newcolumns[0] = n1 + n2;
		columns[1] = convertBH(B[b1]);
		n1 = int(columns[1][0] - '0');
		n2 = int(columns[1][1] - '0');
		n1 = minus7(n1);//if n1>9 minus 7 to get its value because hex -48 for <9 -55 for (A,B,C,D,E,F)
		n2 = minus7(n2);
		newcolumns[1] = n1 + n2;
		columns[2] = convertBH(B[b2]);
		n1 = int(columns[2][0] - '0');
		n2 = int(columns[2][1] - '0');
		n1 = minus7(n1);//if n1>9 minus 7 to get its value because hex -48 for <9 -55 for (A,B,C,D,E,F)
		n2 = minus7(n2);
		newcolumns[2] = n1 + n2;
		columns[3] = convertBH(B[b3]);
		n1 = int(columns[3][0] - '0');
		n2 = int(columns[3][1] - '0');
		n1 = minus7(n1);//if n1>9 minus 7 to get its value because hex -48 for <9 -55 for (A,B,C,D,E,F)
		n2 = minus7(n2);
		newcolumns[3] = n1 + n2;
		int mat[4][4] = { 
			{2, 3, 1, 1},
			{1, 2, 3, 1},
			{1, 1, 2, 3},
			{3, 1, 1, 2}
		};
		cout << "dfghjkl";
		for (int i = 0; i < 4; i++)
		{
			for (int j = 0; j < 4; j++)
			{
				mult[i] += mat[i][j] * newcolumns[i];
			}
		}
		C[b0] = to_string(mult[0]);
		C[b0] = convertHB(C[b0]);
		C[b1] = to_string(mult[1]);
		C[b1] = convertHB(C[b1]);
		C[b2] = to_string(mult[2]);
		C[b2] = convertHB(C[b2]);
		C[b3] = to_string(mult[3]);
		C[b3] = convertHB(C[b3]);
	}
	void MixColumns() {
		matmult(0, 1, 2, 3);
		cout << "dfghj";
		matmult(4, 5, 6, 7);
		matmult(8, 9, 10, 11);
		matmult(12, 13, 14, 15);
	}*/
	void mixcolumns() {
		string c[4];
		int n1, n2;
		for (int i = 0; i < 4; i++) {//first row in mix matrix c[0,4,8,12]
		n1 = minus7(int(B[i*4][0] - '0'));
		n2 = minus7(int(B[i*4][1] - '0'));
		c[0] = convertHB(multof2[n1][n2]);
		n1 = minus7(int(B[i*4+1][0] - '0'));
		n2 = minus7(int(B[i*4+1][1] - '0'));
		c[1] = convertHB(multof3[n1][n2]);
		c[2] = convertHB(B[i*4+2]);
		c[3] = convertHB(B[i*4+3]);
		c[0] = XOR(c[0], c[1]);
		c[1] = XOR(c[2], c[3]);
		C[i*4] = XOR(c[0], c[1]);
		//cout << "C["<<4*i<<"]:   "<<convertBH(C[i*4]);
		}
		for (int i = 0; i < 4; i++) {//2nd row c[1,5,9,13]
			c[0] = convertHB(B[i*4]);
			n1 = minus7(int(B[i*4+1][0] - '0'));
			n2 = minus7(int(B[i*4+1][1] - '0'));
			c[1] = convertHB(multof2[n1][n2]);
			n1 = minus7(int(B[i*4+2][0] - '0'));
			n2 = minus7(int(B[i*4+2][1] - '0'));
			c[2] = convertHB(multof3[n1][n2]);
			c[3] = convertHB(B[i*4+3]);
			c[0] = XOR(c[0], c[1]);
			c[1] = XOR(c[2], c[3]);
			C[i*4+1] = XOR(c[0], c[1]);
			//cout << "c[" << i * 4 + 1 << "]:  " << convertBH(C[i * 4 + 1]);
		}

		for (int i = 0; i < 4; i++) {//3rd row c[2,6,10,14]
			c[0] = convertHB(B[i * 4]);
			c[1] = convertHB(B[i * 4 + 1]);
			n1 = minus7(int(B[i * 4 + 2][0] - '0'));
			n2 = minus7(int(B[i * 4 + 2][1] - '0'));
			c[2] = convertHB(multof2[n1][n2]);
			n1 = minus7(int(B[i * 4 + 3][0] - '0'));
			n2 = minus7(int(B[i * 4 + 3][1] - '0'));
			c[3] = convertHB(multof3[n1][n2]);
			c[0] = XOR(c[0], c[1]);
			c[1] = XOR(c[2], c[3]);
			C[i * 4 + 2] = XOR(c[0], c[1]);
			//cout << "c[" << i * 4 + 2 << "]:  " << convertBH(C[i * 4 + 2]);
		}
		for (int i = 0; i < 4; i++) {//last row c[3,7,11,15]
			n1 = minus7(int(B[i * 4 ][0] - '0'));
			n2 = minus7(int(B[i * 4 ][1] - '0'));
			c[0] = convertHB(multof3[n1][n2]);
			c[1] = convertHB(B[i * 4 + 1]);
			c[2] = convertHB(B[i * 4 + 2]);
			n1 = minus7(int(B[i * 4 + 3][0] - '0'));
			n2 = minus7(int(B[i * 4 + 3][1] - '0'));
			c[3] = convertHB(multof2[n1][n2]);
			c[0] = XOR(c[0], c[1]);
			c[1] = XOR(c[2], c[3]);
			C[i * 4 + 3] = XOR(c[0], c[1]);
			//cout << "c[" << i * 4 + 3 << "]:  " << convertBH(C[i * 4 + 3]);
		}
	}
	string Encryption(string txt){
		string newtxt="";
		txtsplit(txt);
		keyaddition(0);
		for (int i = 0; i < 16; i++) {
			A[i] = XOR(A[i], K[i]);
		}
		cout << "\ncipher after round 0 " << "  ";
		for (int j = 0; j < 16; j++) {
			cout << convertBH(A[j]);
		}
		for (int i = 0; i < 9; i++) {
			SubBytes();
			ShiftRows();
			mixcolumns();
			keyaddition(i+1);
			cout << "\ncipher after round " << i+1 << "  ";
			for (int j = 0; j < 16; j++) {
				A[j] = XOR(C[j], K[j]);
				 cout<< convertBH(A[j]);
			}
		}
		SubBytes();
		ShiftRows();
		keyaddition(10);
		cout << "\ncipher after round " << 10 << "  ";
		for (int j = 0; j < 16; j++) {
			A[j] = XOR(convertHB(B[j]), K[j]);
			cout << convertBH(A[j]);
		}
		for (int i = 0; i < 16; i++) {
			newtxt += A[i];
		}
		return newtxt;
	}
	void invShiftRows() {
		B[0] = convertBH(A[0]);
		B[4] = convertBH(A[4]);
		B[8] = convertBH(A[8]);
		B[12] = convertBH(A[12]);
		B[1] = convertBH(A[13]);
		B[5] = convertBH(A[1]);
		B[9] = convertBH(A[5]);
		B[13] = convertBH(A[9]);
		B[2] = convertBH(A[10]);
		B[6] = convertBH(A[14]);
		B[10] = convertBH(A[2]);
		B[14] = convertBH(A[6]);
		B[3] = convertBH(A[7]);
		B[7] = convertBH(A[11]);
		B[11] = convertBH(A[15]);
		B[15] = convertBH(A[3]);
	}
	void invSubBytes() {
		string newA;
		for (int i = 0; i < 16; i++) {
			newA = B[i];
			int n1 = int(newA[0] - '0'), n2 = int(newA[1] - '0');
			n1 = minus7(n1);//if n1>9 minus 7 to get its value because hex -48 for <9 -55 for (A,B,C,D,E,F)
			n2 = minus7(n2);
			newA = invsbox[n1][n2];
			//cout << i <<"   "<<newA << endl;
			C[i] = convertHB(newA);
		}
	}
	void invmixcolumns(){
		string a[4];
		int n1, n2;
		for (int i = 0; i < 4; i++) {//first row in mix matrix a[0,4,8,12]
			n1 = minus7(int(C[i * 4][0] - '0'));
			n2 = minus7(int(C[i * 4][1] - '0'));
			a[0] = convertHB(multofE[n1][n2]);
			n1 = minus7(int(C[i * 4 + 1][0] - '0'));
			n2 = minus7(int(C[i * 4 + 1][1] - '0'));
			a[1] = convertHB(multofB[n1][n2]);
			n1 = minus7(int(C[i * 4 + 2][0] - '0'));
			n2 = minus7(int(C[i * 4 + 2][1] - '0'));
			a[2] = convertHB(multofD[n1][n2]);
			n1 = minus7(int(C[i * 4 + 3][0] - '0'));
			n2 = minus7(int(C[i * 4 + 3][1] - '0'));
			a[3] = convertHB(multof9[n1][n2]);
			a[0] = XOR(a[0], a[1]);
			a[1] = XOR(a[2], a[3]);
			A[i * 4] = XOR(a[0], a[1]);
			//cout << "A["<<4*i<<"]:   "<<convertBH(A[i*4]);
		}
		for (int i = 0; i < 4; i++) {//2nd row a[1,5,9,13]
			n1 = minus7(int(C[i * 4][0] - '0'));
			n2 = minus7(int(C[i * 4][1] - '0'));
			a[0] = convertHB(multof9[n1][n2]);
			n1 = minus7(int(C[i * 4 + 1][0] - '0'));
			n2 = minus7(int(C[i * 4 + 1][1] - '0'));
			a[1] = convertHB(multofE[n1][n2]);
			n1 = minus7(int(C[i * 4 + 2][0] - '0'));
			n2 = minus7(int(C[i * 4 + 2][1] - '0'));
			a[2] = convertHB(multofB[n1][n2]);
			n1 = minus7(int(C[i * 4 + 3][0] - '0'));
			n2 = minus7(int(C[i * 4 + 3][1] - '0'));
			a[3] = convertHB(multofD[n1][n2]);
			a[0] = XOR(a[0], a[1]);
			a[1] = XOR(a[2], a[3]);
			A[i * 4 + 1] = XOR(a[0], a[1]);
			//cout << "a[" << i * 4 + 1 << "]:  " << convertBH(A[i * 4 + 1]);
		}

		for (int i = 0; i < 4; i++) {//3rd row a[2,6,10,14]
			n1 = minus7(int(C[i * 4][0] - '0'));
			n2 = minus7(int(C[i * 4][1] - '0'));
			a[0] = convertHB(multofD[n1][n2]);
			n1 = minus7(int(C[i * 4 + 1][0] - '0'));
			n2 = minus7(int(C[i * 4 + 1][1] - '0'));
			a[1] = convertHB(multof9[n1][n2]);
			n1 = minus7(int(C[i * 4 + 2][0] - '0'));
			n2 = minus7(int(C[i * 4 + 2][1] - '0'));
			a[2] = convertHB(multofE[n1][n2]);
			n1 = minus7(int(C[i * 4 + 3][0] - '0'));
			n2 = minus7(int(C[i * 4 + 3][1] - '0'));
			a[3] = convertHB(multofB[n1][n2]);
			a[0] = XOR(a[0], a[1]);
			a[1] = XOR(a[2], a[3]);
			A[i * 4 + 2] = XOR(a[0], a[1]);
			//cout << "a[" << i * 4 + 2 << "]:  " << convertBH(A[i * 4 + 2]);
		}
		for (int i = 0; i < 4; i++) {//last row a[3,7,11,15]
			n1 = minus7(int(C[i * 4][0] - '0'));
			n2 = minus7(int(C[i * 4][1] - '0'));
			a[0] = convertHB(multofB[n1][n2]);
			n1 = minus7(int(C[i * 4 + 1][0] - '0'));
			n2 = minus7(int(C[i * 4 + 1][1] - '0'));
			a[1] = convertHB(multofD[n1][n2]);
			n1 = minus7(int(C[i * 4 + 2][0] - '0'));
			n2 = minus7(int(C[i * 4 + 2][1] - '0'));
			a[2] = convertHB(multof9[n1][n2]);
			n1 = minus7(int(C[i * 4 + 3][0] - '0'));
			n2 = minus7(int(C[i * 4 + 3][1] - '0'));
			a[3] = convertHB(multofE[n1][n2]);
			a[0] = XOR(a[0], a[1]);
			a[1] = XOR(a[2], a[3]);
			A[i * 4 + 3] = XOR(a[0], a[1]);
			//cout << "a[" << i * 4 + 3 << "]:  " << convertBH(A[i * 4 + 3]);
		}
	}
	string Decryption(string txt) {
		string newtxt = "";
		txtsplit(txt);
		keyaddition(10);
		for (int j = 0; j < 16; j++) {
			A[j] = XOR(A[j], K[j]);
		}
		invShiftRows();
		invSubBytes();
		cout << endl << "round 10 "<< "  ";
		for (int k = 0; k < 16; k++) {
			cout << convertBH(C[k]);
		}
		for (int i = 9; i > 0; i--) {
			cout << endl << "round  " << i<<"   ";
			keyaddition(i);
			for (int j = 0; j < 16; j++) {
				C[j] = XOR(C[j], K[j]);
				C[j] = convertBH(C[j]);
				//cout <<endl<< convertBH(C[j]);
			}
			invmixcolumns();
			invShiftRows();
			invSubBytes();	
			for (int k = 0; k < 16; k++) {
				cout << convertBH(C[k]);
			}
		}
		keyaddition(0);
		cout << endl << "round  0 " << "   ";
		for (int j = 0; j < 16; j++) {
			B[j] = XOR(C[j], K[j]);
			cout << convertBH(B[j]);
		}
		for (int i = 0; i < 16; i++) {
			newtxt += B[i];
		}
		return newtxt;
	}
};

int main()
{
	AES encrypt, decrypt;
	string txt, newtxt, K[11], original;
	int size, rounds;
	txt = "Information technology department";
	//cin >> txt;
	//cout << "Please enter a key: ";
	string key="abcdefghabcdefgh";
	original = key;
	//cin >> key;
	while (key.size() != 16) {
		cout << "\nInvalid input. enter another key ";
		cin >> key;
	}
	key = encrypt.convertDH(key); //convert key to hex "comment if key is hex"
	cout <<"DH key: "<< key << endl;
	key = encrypt.convertHB(key); //convert from hex to binary
	cout << "HB key: " << key << endl;
	encrypt.newkey[0] = key;
	encrypt.wordsplit(key);
	string encryptedtxt = "", cipher = "";
	if (txt.size() != 16) {
		newtxt = encrypt.convertDH(txt); //convert ascii to hex
		string bin = encrypt.convertHB(newtxt); //convert hex to binary
		int x = encrypt.blocks(bin); //adds characters for <16 splits >16
		for (int i = 0; i < x; i++) {
			encryptedtxt = encrypt.Encryption(encrypt.splittxt[i]);
			cipher += encryptedtxt;
		}
	}
	else {
		newtxt = encrypt.convertDH(txt);//use if it's ascii characters
		cout << "plain: " << newtxt;
		string bin = encrypt.convertHB(newtxt);//use parameter txt if it's in hex, newtxt if it's in ascii
		cipher = encrypt.Encryption(bin);
	}
	cout << "\n\nCipher Text: " << cipher << endl;
	cout << "\ncipher hex: " << encrypt.convertBH(cipher)<<endl;
	/*string ha = "";
	for (int i = 0; i < cipher.length(); i += 2)
	{
		string sub = cipher.substr(i, 2);
		// change it into base 16 and typecast as the character
		char ch = stoul(sub, nullptr, 16);
		ha += ch;
	}
	cout << endl<<ha;
	*/

	key = decrypt.convertDH(original); //convert key to hex "comment if key is hex"
	//cout << "DH key: " << key << endl;
	key = decrypt.convertHB(key); //convert from hex to binary
	//cout << "HB key: " << key << endl;
	decrypt.newkey[0] = key;
	decrypt.wordsplit(key);
	string decryptedtxt, plaintxt;
	if (cipher.length() > 128) {
		int x = decrypt.blocks(cipher); 
		for (int i = 0; i < x; i++) {
			decryptedtxt = decrypt.Decryption(decrypt.splittxt[i]);
			plaintxt += decryptedtxt;
		}
	}
	else {
		decryptedtxt = decrypt.Decryption(cipher);
		plaintxt = decryptedtxt;
	}
	//cout << "plain text in binary: " << plaintxt;
	plaintxt = decrypt.convertBH(plaintxt);
	//cout << "\nplain text in hex:" << plaintxt;
	string ha = "";
	for (int i = 0; i < plaintxt.length(); i += 2)
	{
		string sub = plaintxt.substr(i, 2);
		// change it into base 16 and typecast as the character
		char ch = stoul(sub, nullptr, 16);
		ha += ch;
	}
	cout << endl<<"\nPlain text: " << ha;
}