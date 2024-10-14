#include <iostream>
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <string>
#include <array>
#include <vector>
using namespace std;
std::string exec(const char* cmd) {
    std::array<char, 128> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
    if (!pipe) {
        throw std::runtime_error("popen() failed!");
    }
    while(fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr)
    	result += buffer.data();
    if (!result.empty()) {
    	result.erase(std::prev(result.end()));
    }
    return result;
}
vector<string> split (string s, string delimiter) {
    size_t pos_start = 0, pos_end, delim_len = delimiter.length();
    string token;//CodeBy FarnoodID
    vector<string> res;

    while ((pos_end = s.find (delimiter, pos_start)) != string::npos) {
        token = s.substr (pos_start, pos_end - pos_start);
        pos_start = pos_end + delim_len;
        res.push_back (token);
    }

    res.push_back (s.substr (pos_start));
    return res;
}
int main(){	
	std::string s;
	std::cin>> s;
	s = "dig "+s+" +short";
	s = exec(s.c_str());
	cout<<"IP: "<<endl<< s <<endl;
	cout<<"Domain: "<<endl;
	vector<string> v = split (s, "\n");
	for (auto i : v) {
		if (i[0]<'9' && i[0] >'0')
		{
            //CodeBy FarnoodID
			string l = "dig -x "+i+" +short";
			l = exec(l.c_str());
			cout << l << endl;
		}
	}

}
