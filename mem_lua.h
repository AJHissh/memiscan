#pragma once
#include <string>
#include <vector>

namespace memlua {
bool                       runScript(const std::string& source);
bool                       isRunning();
void                       requestStop();
void                       joinIfStopped();
void                       shutdown();
std::vector<std::string>   snapshotLog();
void                       clearLog();
}
