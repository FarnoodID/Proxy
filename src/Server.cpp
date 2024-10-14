#include "Server.h"
#include <iostream>
#include <boost/asio.hpp>
#include "Log.h"
size_t buffer_size_;
unsigned session_id_2;

//daryaft etelaat-e estekhraj shode az connection.conf va meghdar dehi
Server::Server(boost::asio::io_service& io_service, short port, unsigned buffer_size)
        : acceptor_(io_service, tcp::endpoint(tcp::v4(), port)),
        in_socket_(io_service), buffer_size_(buffer_size),  session_id_2(0)
{
	logger.log("Server instance",5);
        do_accept();
}
//CodeBy FarnoodID
//ba async_accept session jadid ra rah mindaze va dobare do_accept ro seda mizane
void Server::do_accept()
{
	logger.log("Server.do_accept() call",5);
	acceptor_.async_accept(in_socket_,
		[this](boost::system::error_code ec)
        {
        	if (!ec)
                {
                	std::make_shared<Session>(std::move(in_socket_), session_id_2++, buffer_size_)->start();
                }
                else
			logger.log("session ["+to_string(session_id_2)+"] socket accept error " + string(ec.message()),4);
                do_accept();
        });
}
