/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "hdc_connect.h"
#include "hdc_jdwp.h"

namespace Hdc {

std::unique_ptr<ConnectManagement> g_connectManagement = nullptr;
static HdcJdwpSimulator *g_clsHdcJdwpSimulator = nullptr;

void ConnectManagement::SetProcessName(const std::string &processName)
{
    processName_ = processName;
}

std::string ConnectManagement::GetProcessName() const
{
    return processName_;
}

void ConnectManagement::SetPkgName(const std::string &pkgName)
{
    pkgName_ = pkgName;
}

std::string ConnectManagement::GetPkgName() const
{
    return pkgName_;
}

void ConnectManagement::SetDebug(bool isDebug)
{
    isDebug_ = isDebug;
}

bool ConnectManagement::GetDebug() const
{
    return isDebug_;
}

void ConnectManagement::SetCallback(Callback cb)
{
    cb_ = cb;
}

Callback ConnectManagement::GetCallback() const
{
    return cb_;
}

void FreeInstance()
{
    if (g_clsHdcJdwpSimulator == nullptr) {
        return;
    }
    g_clsHdcJdwpSimulator->Disconnect();
    delete g_clsHdcJdwpSimulator;
    g_clsHdcJdwpSimulator = nullptr;
}

void Stop(int signo)
{
    FreeInstance();
    _exit(0);
}

void StopConnect()
{
#ifdef JS_JDWP_CONNECT
    FreeInstance();
#endif // JS_JDWP_CONNECT
}

void* HdcConnectRun(void* pkgContent)
{
    if (signal(SIGINT, Stop) == SIG_ERR) {
        OHOS::HiviewDFX::HiLog::Fatal(LOG_LABEL, "jdwp_process signal fail.");
    }
    std::string processName = static_cast<ConnectManagement*>(pkgContent)->GetProcessName();
    std::string pkgName = static_cast<ConnectManagement*>(pkgContent)->GetPkgName();
    bool isDebug = static_cast<ConnectManagement*>(pkgContent)->GetDebug();
    Callback cb = static_cast<ConnectManagement*>(pkgContent)->GetCallback();
    g_clsHdcJdwpSimulator = new (std::nothrow) HdcJdwpSimulator(processName, pkgName, isDebug, cb);
    if (!g_clsHdcJdwpSimulator->Connect()) {
        OHOS::HiviewDFX::HiLog::Fatal(LOG_LABEL, "Connect fail.");
        return nullptr;
    }
    return nullptr;
}

void StartConnect(const std::string& processName, const std::string& pkgName, bool isDebug, Callback cb)
{
    if (g_clsHdcJdwpSimulator != nullptr) {
        return;
    }
    pthread_t tid;
    g_connectManagement = std::make_unique<ConnectManagement>();
    g_connectManagement->SetProcessName(processName);
    g_connectManagement->SetPkgName(pkgName);
    g_connectManagement->SetDebug(isDebug);
    g_connectManagement->SetCallback(cb);
    if (pthread_create(&tid, nullptr, &HdcConnectRun, static_cast<void*>(g_connectManagement.get())) != 0) {
        OHOS::HiviewDFX::HiLog::Fatal(LOG_LABEL, "pthread_create fail!");
        return;
    }
}
} // namespace Hdc
