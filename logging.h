#pragma once

#include <cstdio>
#include <fcntl.h>
#include <ctime>
#include <string>
#include <iostream>
#include <unistd.h>
#include <libgen.h>
#include <sys/time.h>

#define UDA_LOG_DEBUG 1
#define UDA_CODE_ERROR_TYPE 1
#define UDA_SYSTEM_ERROR_TYPE 1
#define UDA_LOG(LEVEL, FMT, ...) printf(FMT, ##__VA_ARGS__);
#define UDA_ADD_ERROR(CODE, MSG) std::cerr << MSG << std::endl;
#define UDA_THROW_ERROR(CODE, MSG) { std::cerr << MSG << std::endl; return CODE; }
#define UDA_ADD_SYS_ERROR(MSG) std::cerr << MSG << std::endl;

inline void addIdamError(int type, const char* location, int code, const char* msg)
{
    UDA_LOG(UDA_LOG_DEBUG, "%s: %s\n", location, msg);
}