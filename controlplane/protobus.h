#pragma once

#include "common/icp.h"

#include "module.h"

namespace controlplane
{
namespace module
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
}
