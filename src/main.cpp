#include <cstdlib>
#include <iostream>
#include <string>
#include <memory>
#include <utility>
#include <boost/asio.hpp>
#include <fstream>
#include "configReader.h"
#include "Session.h"
#include "Server.h"
#include "filterReader.h"
#include "Log.h"

using boost::asio::ip::tcp;
Log logger;

//daryaft file connection.conf be onvan-e arg[1]
int main(int argc, char* argv[])
{
	try
	{
		if (argc != 2)
		{
			logger.log("Usage: connection <config_file>",0);
			return 1;
		}

		//parse file  config  //CodeBy FarnoodID
		ConfigReader conf;
		conf.parse(argv[1]);
		
		//check if port, buffer_size, log_leveli, log_every exist in connnection.conf
		//gives them value otherwise their default value
		short port = conf.check_key("port") ? std::atoi(conf.get_key_value("port")) : 1080; // Default port_
		size_t buffer_size = conf.check_key("buffer_size") ? std::atoi(conf.get_key_value("buffer_size")) : 8192; // Default buffer_size
		int log_sensivity = conf.check_key("log_level")? std::atoi(conf.get_key_value("log_level")) : 3; // Default log_level
		int logEvery = conf.check_key("log_every")? std::atoi(conf.get_key_value("log_every")) : 60; //Default log_every
		
		//set log_level
		logger.setLogLevel(log_sensivity);
		//set how often to log statistics
		logger.setSecs(logEvery);

		logger.log("main",5);
		boost::asio::io_service io_service;

		//call server with values
		Server server(io_service, port, buffer_size);
		io_service.run();
	}
	catch (std::exception& e)
	{	
		//CodeBy FarnoodID
		logger.log(string(e.what()),0);
	}
	catch (...)
	{
		logger.log("exception...",0);
	}

	return 0;
}
