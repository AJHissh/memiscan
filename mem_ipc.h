#pragma once

#include <string>
#include <functional>

namespace mem { struct ScanParams; }

namespace memipc {

struct GuiHooks {
    std::function<void(const mem::ScanParams&)> syncScan;
    std::function<void(unsigned long long)>     selectAddr;
    std::function<void(const std::string&)>     status;
};
void setGuiHooks(const GuiHooks& hooks);

bool start(unsigned short port, std::string& err);

void stop();

bool               running();
unsigned short     port();
int                connectionCount();
unsigned long long requestCount();
std::string        tokenPath();

void poll();

}
