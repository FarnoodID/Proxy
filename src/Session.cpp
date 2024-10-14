#include "Session.h"
#include <boost/asio.hpp>
#include <inttypes.h>
#include "filterReader.h"
#include "Log.h"
#include <iostream>
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <string>
#include <array>
using boost::asio::ip::tcp;

FilterReader filter;
std::string remote_host_;
std::string remote_port_;
std::string remote_domain_ip = "";
std::vector<char> in_buf_;
std::vector<char> out_buf_;
int session_id_;

//meghdar dehi avalie 
Session::Session(tcp::socket in_socket, unsigned session_id, size_t buffer_size)
	:	in_socket_(std::move(in_socket)), 
		out_socket_(in_socket.get_io_service()), 
		resolver(in_socket.get_io_service()),
		in_buf_(buffer_size), 
		out_buf_(buffer_size), 
		session_id_(session_id)
{
	logger.log("Session instance",5);
}

//call handshake
void Session::start()
{
	logger.log("Session.start() call",5);
	read_socks5_handshake();
}

//read handshake from client side (in_buf_) //CodeBy FarnoodID
void Session::read_socks5_handshake()
{
	logger.log("Session.read_socks5_handshake() start",5);
	auto self(shared_from_this());

	//with asyinc_recieve recieve bytes from in_buf_ of client
	in_socket_.async_receive(boost::asio::buffer(in_buf_),
		[this, self](boost::system::error_code ec, std::size_t length)
		{
			if (!ec)
			{
/*
The client connects to the server, and sends a version
identifier/method selection message:
+----+----------+----------+
|VER | NMETHODS | METHODS  |
+----+----------+----------+
| 1  |    1     | 1 to 255 |
+----+----------+----------+
The values currently defined for METHOD are:
o  X'00' NO AUTHENTICATION REQUIRED
o  X'01' GSSAPI
o  X'02' USERNAME/PASSWORD
o  X'03' to X'7F' IANA ASSIGNED
o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
o  X'FF' NO ACCEPTABLE METHODS
*/
				//check if it is socks5 and  packet has valid length
				if (length < 3 || in_buf_[0] != 0x05)
				{
					logger.log("session ["+std::to_string(session_id_)+"] SOCKS5 handshake request is invalid. Closing session.",4);
					return;
				}
				uint8_t num_methods = in_buf_[1];
				// Prepare request
				in_buf_[1] = 0xFF;

				// Only 0x00 - 'NO AUTHENTICATION REQUIRED' is now support_ed
				for (uint8_t method = 0; method < num_methods; ++method)
					if (in_buf_[2 + method] == 0x00) { in_buf_[1] = 0x00; break; }
				
				//write handshake answer for client side
				write_socks5_handshake();
			}
			else
				logger.log("session ["+std::to_string(session_id_)+"] SOCKS5 handshake request"+string(ec.message()),4);
		});
	logger.log("Session.read_socks5_handshake() end",5);
}

//write handshake answer for client side
void Session::write_socks5_handshake()
{
	logger.log("Session.write_socks5_handshake() call",5);
	auto self(shared_from_this());

	//with async_write wite in in_buf_ for client side
	boost::asio::async_write(in_socket_, boost::asio::buffer(in_buf_, 2), // Always 2-byte according to RFC1928
		[this, self](boost::system::error_code ec, std::size_t length)
		{
			if (!ec)
			{	
				
				if (in_buf_[1] == 0xFF) return; // No appropriate auth method found. Close session.
				//CodeBy FarnoodID
				//if no error; read requests from client
				read_socks5_request();
			}
			else
				logger.log("session ["+std::to_string(session_id_)+"] SOCKS5 handshake response write" + string(ec.message()),4);

		});
}

//read requests from client side
void Session::read_socks5_request()
{
	logger.log("Session.read_socks5_request() start",5);
	auto self(shared_from_this());
	in_socket_.async_receive(boost::asio::buffer(in_buf_),
		[this, self](boost::system::error_code ec, std::size_t length)
		{
			if (!ec)
			{
/*
The SOCKS request is formed as follows:
+----+-----+-------+------+----------+----------+
|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
+----+-----+-------+------+----------+----------+
| 1  |  1  | X'00' |  1   | Variable |    2     |
+----+-----+-------+------+----------+----------+
Where:
o  VER    protocol version: X'05'
o  CMD
o  CONNECT X'01'
o  BIND X'02'
o  UDP ASSOCIATE X'03'
o  RSV    RESERVED
o  ATYP   address type of following address
o  IP V4 address: X'01'
o  DOMAINNAME: X'03'
o  IP V6 address: X'04'
o  DST.ADDR       desired destination address
o  DST.PORT desired destination port_ in network octet
order
The SOCKS server will typically evaluate the request based on source
and destination addresses, and return one or more reply messages, as
appropriate for the request type.
*/
				//check if  lenght is ok and sock5 is used, and connect is used
				if (length < 5 || in_buf_[0] != 0x05 || in_buf_[1] != 0x01)
				{
					logger.log("session ["+std::to_string(session_id_)+"] SOCKS5 request is invalid. Closing session.",4);
					return;
				}

				uint8_t addr_type = in_buf_[3], host_length;
				string prot = "";
				string temp_ip = "";
				map<string, int>::iterator it;
				switch (addr_type)
				{
				case 0x01: // IP V4 addres
					if (length != 10) { logger.log("session ["+std::to_string(session_id_)+"] SOCKS5 request length is invalid. Closing session.",4); return; }
					remote_host_ = boost::asio::ip::address_v4(ntohl(*((uint32_t*)&in_buf_[4]))).to_string();
					remote_port_ = std::to_string(ntohs(*((uint16_t*)&in_buf_[8])));
					prot = remote_port_ == "443" ? "https" :remote_port_=="80"?"http":"";

					// take domain for this remote_host
					temp_ip = "dig -x "+ remote_host_ + " +short";
					remote_domain_ip = logger.shell(temp_ip.c_str());

					//if this session must be filtered, return this session
					if (filter.be_filtered(remote_host_,remote_port_,prot,remote_domain_ip))
					{
						logger.log("Filtered "+remote_host_+":"+remote_port_+" "+prot+" "+ remote_domain_ip,3);
						nFilteredPackets += 1;
						return;
					}
					// add it to active Sessions
					ActiveSessions.push_back(session_id_);//CodeBy FarnoodID
					nNewSessions += 1;

					//check if this Session is related to target domains
					it = nTargetDomains.begin();
					while (it != nTargetDomains.end()){
						string target = it->first;
						int nSessions = it->second;
						regex e(target);
						if(regex_match (remote_domain_ip,e))
						{
							nSessions += 1;
							it->second = nSessions;
							break;
						}
						it ++;
					}
					logger.log("IPv4 host: "+remote_host_+" port:"+remote_port_,4);
					break;
				case 0x03: // DOMAINNAME
					host_length = in_buf_[4];
					if (length != (size_t)(5 + host_length + 2)) { logger.log("session ["+std::to_string(session_id_)+"] SOCKS5 request length is invalid. Closing session.",4); return; }
					remote_host_ = std::string(&in_buf_[5], host_length);
					remote_port_ = std::to_string(ntohs(*((uint16_t*)&in_buf_[5 + host_length])));
					prot = (remote_port_ == "443")? "https" :remote_port_=="80"?"http":"";

					// take IP for this remote_host
					temp_ip = "dig "+ remote_host_ + " +short";
					remote_domain_ip = logger.shell(temp_ip.c_str());

					//if this session must be filtered, return this session
					if (filter.be_filtered(remote_domain_ip,remote_port_,prot,remote_host_))
					{
						logger.log("Filtered "+remote_domain_ip +":"+remote_port_+" "+prot+" "+ remote_host_,4);
						nFilteredPackets += 1;
                                                return;
					}
					ActiveSessions.push_back(session_id_);
					nNewSessions += 1;

					//check if this Session is related to target domains
                                        it = nTargetDomains.begin();
                                        while (it != nTargetDomains.end()){
                                                string target = it->first;
                                                int nSessions = it->second;
                                                regex e(target);
                                                if(regex_match (remote_domain_ip,e))
                                                {
                                                        nSessions += 1;
                                                        it->second = nSessions;
							break;
                                                }
						it ++;
                                        }
					logger.log("domain host: "+remote_host_+" port:"+remote_port_,4);
					break;
				default:
					logger.log("session ["+std::to_string(session_id_)+"] unsupport_ed address type in SOCKS5 request. Closing session.",4);
					break;
				}

				//resolve domain to ip address and call connect
				do_resolve();
			}
			else
				logger.log("session ["+std::to_string(session_id_)+"] SOCKS5 request read "+string(ec.message()),4);

		});
	logger.log("Session.read_socks5_request() end",5);
}

// resolve domain to ip address and call connect
void Session::do_resolve()
{
	logger.log("Session.do_resolve() call",5);
	auto self(shared_from_this());

	resolver.async_resolve(tcp::resolver::query({ remote_host_, remote_port_ }),
		[this, self](const boost::system::error_code& ec, tcp::resolver::iterator it)
		{
			if (!ec)
			{
				do_connect(it);
			}
			else
			{
				//CodeBy FarnoodID
				std::ostringstream what; what << "failed to resolve " << remote_host_ << ":" << remote_port_;
				logger.log("session ["+std::to_string(session_id_)+"] "+string(what.str())+" "+string(ec.message()),4);
				vector<int>::iterator p = find(ActiveSessions.begin(), ActiveSessions.end(), session_id_);
				if (p != ActiveSessions.end()){
	    				ActiveSessions.erase(p);
					nClosedSessions += 1;
					updateSess(session_id_);
				}
			}
		});
}

// connect clinet to server
void Session::do_connect(tcp::resolver::iterator& it)
{
	logger.log("Session.do_connect() call",5);
	auto self(shared_from_this());
	//async_connect connect to server
	out_socket_.async_connect(*it, 
		[this, self](const boost::system::error_code& ec)
		{
			if (!ec)
			{
				std::ostringstream what; what << "connected to " << remote_host_ << ":" << remote_port_;
				logger.log("session ["+std::to_string(session_id_)+"] "+string(what.str()),4);

				//write answer for clinet side
				write_socks5_response();
			}
			else
			{
				std::ostringstream what; what << "failed to connect " << remote_host_ << ":" << remote_port_;
				logger.log("session ["+std::to_string(session_id_)+"] "+string(what.str())+" "+string(ec.message()),4);
				vector<int>::iterator p = find(ActiveSessions.begin(), ActiveSessions.end(), session_id_);
				if (p != ActiveSessions.end()){
                                        ActiveSessions.erase(p);
                                        nClosedSessions += 1;
                                        updateSess(session_id_);
                                }
			}
		});

}	

//write answer for clinet side
void Session::write_socks5_response()
{
	logger.log("Session.write_socks5_response() start",5);
	auto self(shared_from_this());

/*
The SOCKS request information is sent by the client as soon as it has
established a connection to the SOCKS server, and completed the
authentication negotiations.  The server evaluates the request, and
returns a reply formed as follows:
+----+-----+-------+------+----------+----------+
|VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
+----+-----+-------+------+----------+----------+
| 1  |  1  | X'00' |  1   | Variable |    2     |
+----+-----+-------+------+----------+----------+
Where:
o  VER    protocol version: X'05'
o  REP    Reply field:
o  X'00' succeeded
o  X'01' general SOCKS server failure
o  X'02' connection not allowed by ruleset
o  X'03' Network unreachable
o  X'04' Host unreachable
o  X'05' Connection refused
o  X'06' TTL expired		//CodeBy FarnoodID
o  X'07' Command not support_ed
o  X'08' Address type not support_ed
o  X'09' to X'FF' unassigned
o  RSV    RESERVED
o  ATYP   address type of following address
o  IP V4 address: X'01'
o  DOMAINNAME: X'03'
o  IP V6 address: X'04'
o  BND.ADDR       server bound address
o  BND.PORT       server bound port_ in network octet order
Fields marked RESERVED (RSV) must be set to X'00'.
*/
	in_buf_[0] = 0x05; in_buf_[1] = 0x00; in_buf_[2] = 0x00; in_buf_[3] = 0x01;
	uint32_t realRemoteIP = out_socket_.remote_endpoint().address().to_v4().to_ulong();
	uint16_t realRemoteport = htons(out_socket_.remote_endpoint().port());
	
	std::memcpy(&in_buf_[4], &realRemoteIP, 4);
	std::memcpy(&in_buf_[8], &realRemoteport, 2);
	
	//with async_write write answer for client in in_buf_
	boost::asio::async_write(in_socket_, boost::asio::buffer(in_buf_, 10), // Always 10-byte according to RFC1928
		[this, self](boost::system::error_code ec, std::size_t length)
		{
			if (!ec)
			{
				do_read(3); // Read both sockets
			}
			else{
				logger.log("session ["+std::to_string(session_id_)+"] SOCKS5 response write"+string(ec.message()),4);
				vector<int>::iterator p = find(ActiveSessions.begin(), ActiveSessions.end(), session_id_);
                                if (p != ActiveSessions.end()){
                                        ActiveSessions.erase(p);
                                        nClosedSessions += 1;
					updateSess(session_id_);
                                }
			}
		});
	logger.log("Session.write_socks5_response() end",5);
}


void Session::do_read(int direction)
{
	logger.log("Session.do_read() start",5);
	auto self(shared_from_this());
	// We must divide reads by direction to not permit second read call on the same socket.
	// at first by direction 3 we read from both client and server 
	// then it continues to read and write in both directions
	if (direction & 0x1)
		//read from client
		in_socket_.async_receive(boost::asio::buffer(in_buf_),
			[this, self](boost::system::error_code ec, std::size_t length)
			{
				if (!ec)
				{
					nPassedPackets += 1;
					sPassedPackets += long(length);

					//check if this Session is related to target domains
                                        map<string, long>::iterator it = sTargetDomains.begin();
                                        while (it != sTargetDomains.end()){
                                                string target = it->first;
                                                long sDomain = it->second;
                                                regex e(target);
                                                if(regex_match (remote_domain_ip,e))
                                                {
                                                        sDomain += long(length);
                                                        it->second = sDomain;
							break;
                                                }
						it ++;
                                        }
					std::ostringstream what; what << "--> " << std::to_string(length) << " bytes";
					logger.log("session ["+std::to_string(session_id_)+"] "+string(what.str()),4);
					//write in client side
					do_write(1, length);
				}
				else //if (ec != boost::asio::error::eof)
				{
					logger.log("session ["+std::to_string(session_id_)+"] closing session. Client socket read error "+string(ec.message()),4);
					// Most probably client closed socket. Let's close both sockets and exit session.
					in_socket_.close(); out_socket_.close();
					vector<int>::iterator p = find(ActiveSessions.begin(), ActiveSessions.end(), session_id_);
                                	if (p != ActiveSessions.end()){
                                        	ActiveSessions.erase(p);
	                                        nClosedSessions += 1;
						updateSess(session_id_);//CodeBy FarnoodID
        	                        }
				}

			});
	if (direction & 0x2)
		//read  from server
		out_socket_.async_receive(boost::asio::buffer(out_buf_),
			[this, self](boost::system::error_code ec, std::size_t length)
			{
				if (!ec)
				{
					nPassedPackets += 1;
					sPassedPackets += long(length);

					//check if this Session is related to target domains
                                        map<string, long>::iterator it = sTargetDomains.begin();
                                        while (it != sTargetDomains.end()){
                                                string target = it->first;
                                                long sDomain = it->second;
                                                regex e(target);
                                                if(regex_match (remote_domain_ip,e))
                                                {
                                                        sDomain += long(length);
                                                        it->second = sDomain;
							break;
                                                }
						it ++;
                                        }
					std::ostringstream what; what << "<-- " << std::to_string(length) << " bytes";
					logger.log("session ["+std::to_string(session_id_)+"] "+string(what.str()),4);
					//write in server side
					do_write(2, length);
				}
				else //if (ec != boost::asio::error::eof)
				{
					logger.log("session ["+std::to_string(session_id_)+"] closing session. Remote socket read error "+string(ec.message()),4);
					// Most probably remote server closed socket. Let's close both sockets and exit session.
					vector<int>::iterator p = find(ActiveSessions.begin(), ActiveSessions.end(), session_id_);
                                	if (p != ActiveSessions.end()){
                                        	ActiveSessions.erase(p);
	                                        nClosedSessions += 1;
						updateSess(session_id_);
        	                        }
					in_socket_.close(); out_socket_.close();
				}
			});
	logger.log("Session.do_read() end",5);
}

void Session::do_write(int direction, std::size_t Length)
{
	logger.log("Session.do_write() start",5);
	auto self(shared_from_this());

	switch (direction)
	{
	case 1:
		//write in client side
		boost::asio::async_write(out_socket_, boost::asio::buffer(in_buf_, Length),
			[this, self, direction](boost::system::error_code ec, std::size_t length)
			{
				if (!ec)
					//call do_read to read from client side again
					do_read(direction);
				else
				{
					logger.log("session ["+std::to_string(session_id_)+"] closing session. Client socket write error "+string(ec.message()),4);
					// Most probably client closed socket. Let's close both sockets and exit session.
					vector<int>::iterator p = find(ActiveSessions.begin(), ActiveSessions.end(), session_id_);
                                	if (p != ActiveSessions.end()){
                                        	ActiveSessions.erase(p);
	                                        nClosedSessions += 1;
						updateSess(session_id_);
        	                        }//CodeBy FarnoodID
					in_socket_.close(); out_socket_.close();
				}
			});
		break;
	case 2:
		//write in server side
		boost::asio::async_write(in_socket_, boost::asio::buffer(out_buf_, Length),
			[this, self, direction](boost::system::error_code ec, std::size_t length)
			{
				if (!ec)
					//call do_read to read from server side again
					do_read(direction);
				else
				{
					logger.log("session ["+std::to_string(session_id_)+"] closing session. Remote socket write error  "+string(ec.message()),4);
					// Most probably remote server closed socket. Let's close both sockets and exit session.
					vector<int>::iterator p = find(ActiveSessions.begin(), ActiveSessions.end(), session_id_);
                                	if (p != ActiveSessions.end()){
                                        	ActiveSessions.erase(p);
	                                        nClosedSessions += 1;
						updateSess(session_id_);
        	                        }
					in_socket_.close(); out_socket_.close();
				}
			});
		break;
	}
	logger.log("Session.do_write() end",5);
}

//if a session from UpdatedSessions is closed, remove it
void Session::updateSess(int id){
	auto pos = UpdatedSessions.find(id);
	if (pos !=  UpdatedSessions.end())
		 UpdatedSessions.erase(pos);
}
//CodeBy FarnoodID
