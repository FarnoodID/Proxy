#include "Log.h"
#include <string>
#include "spdlog/spdlog.h"
#include "spdlog/sinks/stdout_color_sinks.h"
#include "include/Log.h"
#include <json-c/json.h>
#include <sstream>
#include <thread>
#include <mutex>
#include <chrono>
#include <iostream>
#include <cstdio>
#include <memory>
#include <array>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <bits/stdc++.h>
#include <set>

namespace pt = boost::property_tree;
using namespace std;

int Log::count;


//values should be printed every minute
/****************/
int nPassedPackets;
long sPassedPackets;
vector<int> ActiveSessions;
set<int> UpdatedSessions;
int nClosedSessions;
int nNewSessions;
int nFilteredPackets;
long sFilteredPackets;
map<string,int> nTargetDomains;
map<string,long> sTargetDomains;
/****************/

//sets values
Log::Log(){
	nPassedPackets = 0;
	sPassedPackets = 0;
	nClosedSessions = 0;
	nNewSessions = 0;
	nFilteredPackets = 0;
	sFilteredPackets = 0;
	set_target_domains();
}

//read target domains from config file 'target_domains.json' //CodeBy FarnoodID
void Log::set_target_domains(){
	pt::read_json("/home/farnood/Desktop/final-advanced/config/target_domains.json", root);
	for (pt::ptree::value_type &dom : root.get_child("domains"))
        {
                nTargetDomains.insert({dom.second.data(),0});
		sTargetDomains.insert({dom.second.data(),0});
        }
}

//print target domains' number of sessions and size
void Log::print_target_domains(){
	logger.log("Number of target domain sessions:",3);
	for (auto itr = nTargetDomains.begin(); itr != nTargetDomains.end(); ++itr) {
        	logger.log("\t"+itr->first+": " + to_string(itr->second),3);
    	}
	logger.log("Size of target domain sessions:",3);
	for (auto itr = sTargetDomains.begin(); itr != sTargetDomains.end(); ++itr) {
		logger.log("\t"+itr->first+": " +check_size(itr->second),3);
        }
}

// return answer for cmd in shell
string Log::shell(const char* cmd) {
	array<char, 128> buffer;
 	string result;
    	unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
	if (!pipe) {
		logger.log("popen() failed!",4);
		return "";
    	}
    	fgets(buffer.data(), buffer.size(), pipe.get());
    	result += buffer.data();
    	if (!result.empty()) {
        	result.erase(std::prev(result.end()));
    	}
    	return result;
}

//returns string of size and its unit concatenated
string Log::check_size(long length){
	double tempForThis = double(length);
	if (tempForThis < 1024){
		return to_string(length)+" Bytes";
	}//CodeBy FarnoodID
	else if (tempForThis < 1048576){
		tempForThis /= 1024;
		char buffer[50];
		sprintf (buffer, "%.2f",tempForThis);
		return string(buffer)+" KB";
	}
	else {
		tempForThis /= 1048576;
		char buffer[50];
                sprintf (buffer, "%.2f",tempForThis);
                return string(buffer)+" MB";
	}
}

//set how often statics be shown and make second thread for printing that often
void Log::setSecs(int s){
	secs = s;
	std::thread logThread(&Log::print, this);
	logThread.detach();
}

//log every minute
//lock it with mutex
//and change and reset some values after each print
void Log::print(){
	mutex mx;
	while (1){
		std::this_thread::sleep_for(std::chrono::seconds(secs));
		mx.lock();
		logger,log("",3);
		logger,log("",3);
		logger.log("           $$$$$$$$$$",3);
		logger.log("      ********************",3);
		logger.log("################################",3);
		logger.log("Number of passed packets: "+to_string(nPassedPackets),3);
		logger.log("Size of passed packets: "+check_size(sPassedPackets),3);
		logger.log("Number of active sessions: "+to_string(ActiveSessions.size()),3);
		logger.log("Number of updated sessions: "+to_string(UpdatedSessions.size()),3);
		logger.log("Number of closed sessions: "+to_string(nClosedSessions),3);
		logger.log("Number of new sessions: "+to_string(nNewSessions),3);
		logger.log("Number of filtered packets: "+to_string(nFilteredPackets),3);
		logger.log("Size of filtered packets: "+to_string(sFilteredPackets)+ " Bytes",3);
		print_target_domains();
		logger.log("################################",3);
		logger.log("      ********************",3);
		logger.log("           $$$$$$$$$$",3);
		logger,log("",3);
		logger,log("",3);
		nNewSessions = 0;
		UpdatedSessions.clear();
		for (int x : ActiveSessions) UpdatedSessions.insert(x);
		mx.unlock();
	}
}

//loggs msg with level of 'level'
void Log::log(string msg,int level){
	count+=1;
	stringstream ss;
	ss<<count;
	string str;
	ss>>str;
	string logMsg="["+str+"] ";
	logMsg=logMsg+msg;
	static auto console = spdlog::stdout_color_mt("console");
	switch(level){
		case 0:
			console->critical(logMsg);
			//spdlog::critical(logMsg);
			break;
		case 1:
			console->error(logMsg);
			//spdlog::error(logMsg);
			break;
		case 2:
			console->warn(logMsg);
			//spdlog::warn(logMsg);
			break;//CodeBy FarnoodID
		case 3:
			console->info(logMsg);
			//spdlog::info(logMsg);
			break;
		case 4:
			console->debug(logMsg);
			//spdlog::debug(logMsg);
			break;
		case 5: 
			console->trace(logMsg);
			//spdlog::trace(logMsg);
			break;
	}
}

//takes int and sets log_level sensivity 
void Log::setLogLevel(int sensivity){
	switch (sensivity){
		case 0:
			//critical
			spdlog::set_level(spdlog::level::critical);
			break;
		case 1:
			//error
			spdlog::set_level(spdlog::level::err);
			break;
		case 2:
			//warning
			spdlog::set_level(spdlog::level::warn);
			break;
		case 3:
			//info
			spdlog::set_level(spdlog::level::info);
			break;
		case 4:
			//debug
			spdlog::set_level(spdlog::level::debug);
			break;
		case 5:
			//trace
			spdlog::set_level(spdlog::level::trace);
			break;
	}
}
