/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
use super::mount;
use crate::jdwp::Jdwp;
use crate::transfer;
use hdc::common::hdctransfer;
use hdc::config::TaskMessage;
use hdc::config::{self, HdcCommand};
use hdc::utils::execute_shell_cmd;
use libc::sync;

extern "C" {
    fn Restart();
}

async fn hdc_restart() {
    unsafe {
        Restart();
    }
}

async fn echo_client(session_id: u32, channel_id: u32, message: &str) {
    let echo_message = TaskMessage {
        channel_id,
        command: HdcCommand::KernelEchoRaw,
        payload: message.as_bytes().to_vec(),
    };
    transfer::put(session_id, echo_message).await;
}

async fn echo_device_mode_result(session_id: u32, channel_id: u32, result: bool, message: Vec<u8>) {
    if result {
        echo_client(session_id, channel_id, "Set device run mode successful.").await;
    } else {
        let msg = format!(
            "Set device run mode failed: {}",
            String::from_utf8(message).unwrap()
        );
        echo_client(session_id, channel_id, msg.as_str()).await;
    }
    task_finish(session_id, channel_id).await;
}

async fn echo_reboot_result(session_id: u32, channel_id: u32, result: bool, message: Vec<u8>) {
    if result {
        echo_client(session_id, channel_id, "Reboot successful.").await;
    } else {
        let msg = format!("Reboot failed: {}", String::from_utf8(message).unwrap());
        echo_client(session_id, channel_id, msg.as_str()).await;
    }
    task_finish(session_id, channel_id).await;
}

async fn echo_root_run_mode_result(
    session_id: u32,
    channel_id: u32,
    result: bool,
    message: Vec<u8>,
) {
    if result {
        echo_client(session_id, channel_id, "Set root run mode successful.").await;
    } else {
        let msg = format!(
            "Set root run mode failed: {}",
            String::from_utf8(message).unwrap()
        );
        echo_client(session_id, channel_id, msg.as_str()).await;
    }
    task_finish(session_id, channel_id).await;
}

async fn set_root_run_enable(session_id: u32, channel_id: u32, force: bool) {
    let arg = if force { "0" } else { "1" };
    let shell_command = format!(
        "{} {} {}",
        config::SHELL_PARAM_SET,
        config::ENV_ROOT_RUN_MODE,
        arg
    );
    let (result, message) = execute_shell_cmd(shell_command);
    echo_root_run_mode_result(session_id, channel_id, result, message).await;
    if result {
        hdc_restart().await;
    }
}

async fn set_root_run(session_id: u32, channel_id: u32, _payload: &[u8]) {
    let shell_command = format!("{} {}", config::SHELL_PARAM_GET, config::ENV_DEBUGGABLE,);
    let (result, message) = execute_shell_cmd(shell_command);
    if !result || message[0] != b'1' {
        return;
    }

    if _payload.is_empty() {
        set_root_run_enable(session_id, channel_id, false).await;
    } else if _payload == [b'r'] {
        set_root_run_enable(session_id, channel_id, true).await;
    } else {
        echo_root_run_mode_result(
            session_id,
            channel_id,
            false,
            String::from("Unknown command").as_bytes().to_vec(),
        )
        .await;
    }
}

async fn reboot_device(session_id: u32, channel_id: u32, _payload: &[u8]) {
    mount::remount_device();
    unsafe {
        sync();
    };

    let param = String::from_utf8(_payload.to_vec()).unwrap();
    let mut cmd = String::from("reboot");
    if !param.is_empty() {
        cmd.push(',');
        cmd.push_str(param.as_str());
    }

    let shell_command = format!(
        "{} {} {}",
        config::SHELL_PARAM_SET,
        config::ENV_STARTUP,
        cmd
    );
    let (result, message) = execute_shell_cmd(shell_command);
    echo_reboot_result(session_id, channel_id, result, message).await;
}

async fn remount_device(session_id: u32, channel_id: u32) {
    let ret = mount::remount_device();
    if ret {
        echo_client(session_id, channel_id, "Remount successful.").await;
    } else {
        echo_client(session_id, channel_id, "Remount failed.").await;
    }
    task_finish(session_id, channel_id).await;
}

async fn set_device_mode(session_id: u32, channel_id: u32, _payload: &[u8]) {
    let param = String::from_utf8(_payload.to_vec()).unwrap();
    match param.as_str() {
        config::MODE_USB => {
            let shell_command = format!(
                "{} {} {}",
                config::SHELL_PARAM_SET,
                config::ENV_HDC_MODE,
                config::MODE_USB
            );
            let (result, message) = execute_shell_cmd(shell_command);
            echo_device_mode_result(session_id, channel_id, result, message).await;
            if result {
                hdc_restart().await
            }
        }
        str if str.starts_with(config::PREFIX_PORT) => {
            let shell_command = format!(
                "{} {} {}",
                config::SHELL_PARAM_SET,
                config::ENV_HDC_MODE,
                config::MODE_TCP
            );
            let (ret, msg) = execute_shell_cmd(shell_command);
            if !ret {
                echo_device_mode_result(session_id, channel_id, ret, msg).await;
                return;
            }

            let port = &str[config::PREFIX_PORT.len()..];
            let port =
                port.trim_end_matches(|c: char| c.is_ascii_control() || c.is_ascii_whitespace());
            let set_port_command = format!(
                "{} {} {}",
                config::SHELL_PARAM_SET,
                config::ENV_HOST_PORT,
                port
            );
            let (result, message) = execute_shell_cmd(set_port_command);
            echo_device_mode_result(session_id, channel_id, result, message).await;
            if result {
                hdc_restart().await
            }
        }
        _ => {
            echo_device_mode_result(
                session_id,
                channel_id,
                false,
                String::from("Unknown command").as_bytes().to_vec(),
            )
            .await;
        }
    }
}

async fn do_jdwp_list(session_id: u32, channel_id: u32) {
    println!("do_jdwp_list");
    let jdwp = Jdwp::get_instance().clone();
    let process_list = jdwp.get_process_list().await;
    if process_list.is_empty() {
        echo_client(session_id, channel_id, "[Empty]").await;
    } else {
        echo_client(session_id, channel_id, process_list.as_str()).await;
    }
    task_finish(session_id, channel_id).await;
}

async fn do_jdwp_track(session_id: u32, channel_id: u32, payload: &[u8]) {
    let mut debug_or_release = true;
    if !payload.is_empty() && payload[0] == b'p' {
        debug_or_release = false;
    }
    println!("do_jdwp_track");
    let jdwp = Jdwp::get_instance().clone();
    jdwp.add_tracker(channel_id, session_id, debug_or_release)
        .await;
}

pub async fn command_dispatch(
    session_id: u32,
    channel_id: u32,
    _command: HdcCommand,
    _payload: &[u8],
    _payload_size: u16,
) -> bool {
    println!("DaemonUnityTask: command:{:#?}", _command);
    match _command {
        HdcCommand::UnityReboot => {
            reboot_device(session_id, channel_id, _payload).await;
        }
        HdcCommand::UnityRunmode => {
            set_device_mode(session_id, channel_id, _payload).await;
        }
        HdcCommand::UnityRootrun => {
            set_root_run(session_id, channel_id, _payload).await;
        }
        HdcCommand::JdwpList => {
            do_jdwp_list(session_id, channel_id).await;
        }
        HdcCommand::JdwpTrack => {
            do_jdwp_track(session_id, channel_id, _payload).await;
        }
        HdcCommand::UnityRemount => {
            remount_device(session_id, channel_id).await;
        }
        _ => {
            println!("other command");
        }
    }
    true
}

async fn task_finish(session_id: u32, channel_id: u32) {
    hdctransfer::transfer_task_finish(channel_id, session_id).await;
}
