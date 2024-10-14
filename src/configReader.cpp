#include "configReader.h"
#include <map>
#include <string>
#include <fstream>
#include <sstream>
#include <regex>
#include "Log.h"

ConfigReader::ConfigReader(){logger.log("configReader instance",5);}
ConfigReader::ConfigReader(const ConfigReader& config_reader) : settings(config_reader.settings) { logger.log("configReader instance",5);}

void ConfigReader::parse(std::string file_name)
{
	logger.log("configReader.parse() start",5);
	std::ifstream configFile(file_name);
	std::string line;
	//read buffer_size, port, log_level //CodeBy FarnoodID
	//set settinng[key] = value
	while (std::getline(configFile, line))
	{
		size_t posComment = line.find('#');
		if (posComment != std::string::npos) line = line.substr(0, posComment);
		line = std::regex_replace(line, std::regex("^[ \t]*"), "");
		if (line.size() == 0) continue;
		line = std::regex_replace(line, std::regex("[ \t]+"), " ");
		std::istringstream string_reader(line);
		std::string key, value;
		string_reader >> key >> value;
		settings[key] = value;
	}
	
	logger.log("configReader.parse() end",5);
}

//check if key exists
bool ConfigReader::check_key(const std::string& key)
{
	logger.log("configReader.check_key() start",5);
	auto it = settings.find(key);
	if (it == settings.end()) return false;
	logger.log("configReader.check_key() end",5);
	return true;
}

//return value for key
const char* ConfigReader::get_key_value(const std::string& key)
{
	logger.log("configReader.get_key_value() call",5);
	return settings[key].c_str();
	//CodeBy FarnoodID
}
std::map<std::string, std::string> settings;
