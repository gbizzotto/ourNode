CXX=g++

all:
	$(CXX) -std=c++2a -g -o ourNode ourNode.cpp  -lboost_fiber-mt -lboost_context-mt
	@#-finstrument-functions

test:
	$(CXX) -std=c++2a -O3 -o test_blockchain test_blockchain.cpp
	./test_blockchain
	@echo 
	@echo Success