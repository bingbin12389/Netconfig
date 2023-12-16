# Netopeer2
- Simple Practice how to use libyang, libnetconf and sysrepo
- Example with yang module

# Setup and install netopeer2 on linux system
- Netopeer2 v2.1.71 release depends on libyang (v2.1.111), libnetconf2 (v2.1.37) and sysrepo (v2.2.105)
- Download netopeer2  : https://github.com/CESNET/netopeer2/releases/tag/v2.1.71
- Download libyang    : https://github.com/CESNET/libyang/releases/tag/v2.1.111
- Download libnetconf2: https://github.com/CESNET/libnetconf2/releases/tag/v2.1.37
- Download sysrepo    : https://github.com/sysrepo/sysrepo/releases/tag/v2.2.105

# Install Netopeer2 on Ubuntu 20.04 

- sudo apt-get update
- sudo apt-get install git cmake build-essential bison flex libpcre3-dev libev-dev libavl-dev libprotobuf-c-dev protobuf-c-compiler swig python-dev lua5.2 pkg-config libpcre++-dev openssl libssl-dev libcrypto++-dev zlib1g-dev

* Install libssh 0.8.6 since the system installed libssh0.9.3 won't work with Netopeer2
Install libssh 0.8.6

- wget https://git.libssh.org/projects/libssh.git/snapshot/libssh-0.8.6.tar.gz
- tar -xf libssh-0.8.6.tar.gz
- rm libssh-0.8.6.tar.gz
- cd libssh-0.8.6
- mkdir build && cd build
- cmake ..
- make
- sudo make install

On Ubuntu, become root:
- sudo -i
- mkdir NetConfServer
- cd NetConfServer

1. Install libyang
- git clone https://github.com/CESNET/libyang.git
- cd libyang
- mkdir build && cd build && cmake .. && make && make install

2. Install sysrepo
- cd ..
- git clone https://github.com/sysrepo/sysrepo.git
- cd sysrepo
- mkdir build && cd build && cmake .. && make && make install

3. Install libnetconf2
- cd ..
- git clone https://github.com/CESNET/libnetconf2.git
- cd libnetconf2
- mkdir build && cd build && cmake .. && make && make install

4. Install Netopeer2
- cd ..
- git clone https://github.com/CESNET/netopeer2.git
- cd netopeer2
- mkdir build && cd build && cmake .. && make && make install

5. To ensure that all libraries that have been installed are now available, execute:
- ldconfig
