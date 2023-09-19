/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "file_descriptor.h"

namespace Hdc {
static const int SECONDS_TIMEOUT = 5;

HdcFileDescriptor::HdcFileDescriptor(uv_loop_t *loopIn, int fdToRead, void *callerContextIn,
                                     CallBackWhenRead callbackReadIn, CmdResultCallback callbackFinishIn)
{
    loop = loopIn;
    workContinue = true;
    callbackFinish = callbackFinishIn;
    callbackRead = callbackReadIn;
    fdIO = fdToRead;
    refIO = 0;
    callerContext = callerContextIn;
    ioWriteThread = std::thread(IOWriteThread, this);
}

HdcFileDescriptor::~HdcFileDescriptor()
{
    workContinue = false;
    NotifyWrite();
    ioWriteThread.join();
    WRITE_LOG(LOG_FATAL, "~HdcFileDescriptor refIO:%d", refIO);
}

bool HdcFileDescriptor::ReadyForRelease()
{
    return refIO == 0;
}

// just tryCloseFdIo = true, callback will be effect
void HdcFileDescriptor::StopWorkOnThread(bool tryCloseFdIo, std::function<void()> closeFdCallback)
{
    workContinue = false;
    callbackCloseFd = closeFdCallback;
    if (tryCloseFdIo && refIO > 0) {
        if (callbackCloseFd != nullptr) {
            callbackCloseFd();
        }
    }
}

void HdcFileDescriptor::FileIOOnThread(CtxFileIO *ctxIO, int bufSize, bool isWrite)
{
    HdcFileDescriptor *thisClass = ctxIO->thisClass;
    uint8_t *buf = ctxIO->bufIO;
    bool bFinish = false;
    bool fetalFinish = false;
    ssize_t nBytes;
    fd_set rset;
    struct timeval timeout;
    timeout.tv_sec = SECONDS_TIMEOUT;
    timeout.tv_usec = 0;

    while (true) {
        if (thisClass->workContinue == false) {
            WRITE_LOG(LOG_INFO, "FileIOOnThread fdIO:%d workContinue false", thisClass->fdIO);
            bFinish = true;
            break;
        }

        if (isWrite) {
            nBytes = write(thisClass->fdIO, buf, bufSize);
            if (nBytes < 0 && (errno == EINTR || errno == EAGAIN)) {
                WRITE_LOG(LOG_WARN, "FileIOOnThread fdIO:%d write interrupt", thisClass->fdIO);
                continue;
            }
            bufSize -= nBytes;
        } else {
            if (memset_s(buf, bufSize, 0, bufSize) != EOK) {
                WRITE_LOG(LOG_DEBUG, "FileIOOnThread buf memset_s fail.");
                break;
            }
            FD_ZERO(&rset);
            FD_SET(thisClass->fdIO, &rset);
            int rc = select(thisClass->fdIO + 1, &rset, nullptr, nullptr, &timeout);
            if (rc < 0) {
                WRITE_LOG(LOG_FATAL, "FileIOOnThread select fdIO:%d error:%d", thisClass->fdIO, errno);
                break;
            } else if (rc == 0) {
                continue;
            }
            nBytes = read(thisClass->fdIO, buf, bufSize);
            if (nBytes < 0 && (errno == EINTR || errno == EAGAIN)) {
                WRITE_LOG(LOG_WARN, "FileIOOnThread fdIO:%d read interrupt", thisClass->fdIO);
                continue;
            }
        }
        if (nBytes > 0) {
            if (isWrite && bufSize == 0) {
                break;
            } else if (!isWrite && !thisClass->callbackRead(thisClass->callerContext, buf, nBytes)) {
                WRITE_LOG(LOG_WARN, "FileIOOnThread fdIO:%d callbackRead false", thisClass->fdIO);
                bFinish = true;
                break;
            }
            continue;
        } else {
            if (nBytes != 0) {
                char buffer[BUF_SIZE_DEFAULT] = { 0 };
#ifdef HOST_MINGW
                strerror_s(buffer, BUF_SIZE_DEFAULT, errno);
#else
                strerror_r(errno, buffer, BUF_SIZE_DEFAULT);
#endif
                WRITE_LOG(LOG_DEBUG, "FileIOOnThread fd:%d failed:%s", thisClass->fdIO, buffer);
            }
            WRITE_LOG(LOG_INFO, "FileIOOnThread fd:%d nBytes:%u", thisClass->fdIO, nBytes);
            bFinish = true;
            fetalFinish = true;
            break;
        }
    }
    if (buf != nullptr) {
        delete[] buf;
        buf = nullptr;
    }
    delete ctxIO;

    --thisClass->refIO;
    if (bFinish) {
        thisClass->workContinue = false;
        thisClass->callbackFinish(thisClass->callerContext, fetalFinish, STRING_EMPTY);
    }
}

int HdcFileDescriptor::LoopReadOnThread()
{
    int readMax = Base::GetMaxBufSize() * 1.2;
    auto contextIO = new(std::nothrow) CtxFileIO();
    auto buf = new(std::nothrow) uint8_t[readMax]();
    if (!contextIO || !buf) {
        if (contextIO) {
            delete contextIO;
        }
        if (buf) {
            delete[] buf;
        }
        WRITE_LOG(LOG_FATAL, "Memory alloc failed");
        callbackFinish(callerContext, true, "Memory alloc failed");
        return -1;
    }
    contextIO->bufIO = buf;
    contextIO->thisClass = this;
    ++refIO;
    ioReadThread = std::thread(FileIOOnThread, contextIO, readMax, false);
    ioReadThread.detach();
    return 0;
}

bool HdcFileDescriptor::StartWorkOnThread()
{
    if (LoopReadOnThread() < 0) {
        return false;
    }
    return true;
}

int HdcFileDescriptor::Write(uint8_t *data, int size)
{
    if (size > static_cast<int>(HDC_BUF_MAX_BYTES - 1)) {
        size = static_cast<int>(HDC_BUF_MAX_BYTES - 1);
    }
    if (size <= 0) {
        WRITE_LOG(LOG_WARN, "Write failed, size:%d", size);
        return -1;
    }
    auto buf = new(std::nothrow) uint8_t[size];
    if (!buf) {
        return -1;
    }
    (void)memcpy_s(buf, size, data, size);
    return WriteWithMem(buf, size);
}

// Data's memory must be Malloc, and the callback FREE after this function is completed
int HdcFileDescriptor::WriteWithMem(uint8_t *data, int size)
{
    auto contextIO = new(std::nothrow) CtxFileIO();
    if (!contextIO) {
        delete[] data;
        WRITE_LOG(LOG_FATAL, "Memory alloc failed");
        callbackFinish(callerContext, true, "Memory alloc failed");
        return -1;
    }
    contextIO->bufIO = data;
    contextIO->size = static_cast<size_t>(size);
    contextIO->thisClass = this;
    PushWrite(contextIO);
    NotifyWrite();
    return size;
}

void HdcFileDescriptor::IOWriteThread(void *object)
{
    HdcFileDescriptor *hfd = reinterpret_cast<HdcFileDescriptor *>(object);
    while (hfd->workContinue) {
        hfd->HandleWrite();
        hfd->WaitWrite();
    }
}

void HdcFileDescriptor::PushWrite(CtxFileIO *cfio)
{
    std::unique_lock<std::mutex> lock(writeMutex);
    writeQueue.push(cfio);
}

CtxFileIO *HdcFileDescriptor::PopWrite()
{
    std::unique_lock<std::mutex> lock(writeMutex);
    CtxFileIO *cfio = nullptr;
    if (!writeQueue.empty()) {
        cfio = writeQueue.front();
        writeQueue.pop();
    }
    return cfio;
}

void HdcFileDescriptor::NotifyWrite()
{
    std::unique_lock<std::mutex> lock(writeMutex);
    writeCond.notify_one();
}

void HdcFileDescriptor::WaitWrite()
{
    std::unique_lock<std::mutex> lock(writeMutex);
    writeCond.wait(lock, [&]() { return !writeQueue.empty() || !workContinue; });
}

void HdcFileDescriptor::HandleWrite()
{
    CtxFileIO *cfio = nullptr;
    while ((cfio = PopWrite()) != nullptr) {
        CtxFileIOWrite(cfio);
        delete cfio;
    }
}

void HdcFileDescriptor::CtxFileIOWrite(CtxFileIO *cfio)
{
    std::unique_lock<std::mutex> lock(writeMutex);
    uint8_t *buf = cfio->bufIO;
    uint8_t *data = buf;
    size_t cnt = cfio->size;
    while (cnt > 0) {
        ssize_t rc = write(fdIO, data, cnt);
        if (rc < 0 ) {
            if (errno == EINTR || errno == EAGAIN) {
                WRITE_LOG(LOG_WARN, "CtxFileIOWrite fdIO:%d interrupt or again", fdIO);
                continue;
            } else {
                WRITE_LOG(LOG_FATAL, "CtxFileIOWrite fdIO:%d rc:%d error:%d", fdIO, rc, errno);
                break;
            }
        }
        data += rc;
        cnt -= static_cast<size_t>(rc);
    }
    delete[] buf;
}
}  // namespace Hdc
