#include "filterReader.h"
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <vector>
#include <iostream>
#include <regex>
#include <string>
#include "Log.h"
namespace pt = boost::property_tree;
using namespace std;

//read json file and call capture()
FilterReader::FilterReader(){
	logger.log("FilterReader instance",5);
	pt::read_json(address, root);
	capture();
}

//capture filtered items from config file 'filter.json' //CodeBy FarnoodID
void FilterReader::capture()
{
	logger.log("FilterReader.capture() start",5);
	for (pt::ptree::value_type &ips : root.get_child("ips"))
	{
		ip.push_back(ips.second.data());
	}
	for (pt::ptree::value_type &ip_ports : root.get_child("ip_ports"))
	{
		ip_port.push_back(ip_ports.second.data());
	}
	for (pt::ptree::value_type &ports : root.get_child("ports"))
	{
		port.push_back(ports.second.data());
	}
	for (pt::ptree::value_type &domains : root.get_child("domains"))
	{
		domain.push_back(domains.second.data());
	}
	for (pt::ptree::value_type &protocols : root.get_child("protocols"))
	{
		protocol.push_back(protocols.second.data());
	}
	logger.log("FilterReader.capture() end",5);
}

//print filtered IP, port, IP:port, protocol and domains
void FilterReader::print()
{
	//CodeBy FarnoodID
	logger.log("FilterReader.print() start",5);
	cout<<"ip: ";
	for (auto i = ip.begin(); i != ip.end(); ++i)
		cout << *i << ", ";
	cout<<endl;
	cout<<"ip_port: ";
        for (auto i = ip_port.begin(); i != ip_port.end(); ++i)
                cout << *i << ", ";
        cout<<endl;
	cout<<"port: ";
        for (auto i = port.begin(); i != port.end(); ++i)
                cout << *i << ", ";
        cout<<endl;
	cout<<"domain: ";
        for (auto i = domain.begin(); i != domain.end(); ++i)
                cout << *i << ", ";
        cout<<endl;
	cout<<"protocol: ";
        for (auto i = protocol.begin(); i != protocol.end(); ++i)
                cout << *i << ", ";
        cout<<endl;
	logger.log("FilterReader.print() end",5);
}

//check if this file must be filtered
//by calling check_ip(), check_ip_port(),
// check_port(), check_domain(), check_protocol()
int FilterReader::be_filtered(string this_host, string this_port, string this_protocol, string this_domain = ""){
	logger.log("FilterReader.be_filtered() start",5);
	if (check_ip(this_host))
		return 1;
	if (check_ip_port(this_host+":"+this_port))
		return 1;
	if (check_port(this_port))
		return 1;
	if (check_domain(this_domain))
		return 1;
	if (check_protocol(this_protocol))
		return 1;
	logger.log("FilterReader.be_filtered() end",5);
	return 0;
}

//check if given ip match filtered IPs
int FilterReader::check_ip(string str){
	for (auto i = ip.begin(); i != ip.end(); ++i)
	{
                if (str.compare(*i)== 0)
			return 1;
	}
	return 0;
}

//check if given ip:port match filtered IP and ports
int FilterReader::check_ip_port(string str){
        for (auto i = ip_port.begin(); i != ip_port.end(); ++i)
	{
                if (str.compare(*i)== 0)
                        return 1;
						//CodeBy FarnoodID
	}
        return 0;
}

//check if given port match filtered ports
int FilterReader::check_port(string str){
        for (auto i = port.begin(); i != port.end(); ++i)
	{
                if (str.compare(*i)== 0)
                        return 1;
	}
        return 0;
}

//check if given domain match filtered domain by regex
int FilterReader::check_domain(string s){
        for (auto i = domain.begin(); i != domain.end(); ++i)
	{
		regex e(*i);
		if(regex_match (s,e))
			return 1;
	}
        return 0;
}

//check if given protocol match filtered protocols
int FilterReader::check_protocol(string str){
        for (auto i = protocol.begin(); i != protocol.end(); ++i)
	{
                if (str.compare(*i)== 0)
                        return 1;
	}
        return 0;
}

// Create a root
pt::ptree root;

//config file address
string address = "/home/farnood/Desktop/final-advanced/config/filter.json";
//string address = "filter.json";
vector<string> ip;
vector<string> ip_port;
vector<string> port;
vector<string> domain;
vector<string> protocol;

