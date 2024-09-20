#pragma once


#include "module.h"


namespace controlplane::module
{

class protoBus : public cModule
{
public:
	protoBus();
	~protoBus() override;

	eResult init() override;
	void stop() override;

protected:
	void serverThread();
	void clientThread(int clientSocket);

protected:
	int serverSocket;
};

}

