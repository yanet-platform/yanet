#pragma once

#include "module.h"

namespace controlplane::module
{

class bus : public cModule
{
public:
	bus();
	~bus() override;

	eResult init() override;
	void stop() override;

protected:
	void serverThread();
	void clientThread(int clientSocket);

protected:
	int serverSocket;
};

}
