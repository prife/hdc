/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
//! shell

#[allow(unused_imports)]
use hdc::common::hdcfile;
#[allow(unused_imports)]
use hdc::common::forward;
use hdc::config::ConnectType;
use hdc::transfer::UsbMap;
use hdc::transfer::TcpMap;
use hdc::transfer::buffer;
// use super::shell;
#[allow(unused_imports)]
use super::daemon_app;

pub async fn free_session(connect_type: ConnectType, session_id: u32) {
    
    match connect_type {
        ConnectType::Bt => {

        }
        ConnectType::Tcp => {
            TcpMap::end(session_id).await;
        }
        ConnectType::Uart => {
            
        }
        ConnectType::Usb(_) => {
            UsbMap::end(session_id).await;
        }

        ConnectType::HostUsb(_) => {
            // add to avoid warning
        }
    }
    stop_task(session_id).await;
}

pub async fn stop_task(session_id: u32) {
    hdcfile::stop_task(session_id).await;
    // shell::stop_task(session_id).await;
    daemon_app::stop_task(session_id).await;
    forward::stop_task(session_id).await;
}

pub async fn dump_running_task_info() -> String {
    let mut result = "\n".to_string();
    result.push_str(&format!("{:#}", buffer::dump_session().await));
    result.push_str(&format!("{:#}", hdcfile::dump_task().await));
    // result.push_str(&format!("{:#}", shell::dump_task().await));
    result.push_str(&format!("{:#}", daemon_app::dump_task().await));
    result.push_str(&format!("{:#}", forward::dump_task().await));
    result.push_str("# ");
    result.to_string()
}
