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
//! auth
#![allow(missing_docs)]

use hdc::config::{self, *};
use hdc::serializer::native_struct;
use hdc::serializer::serialize::Serialization;
use hdc::transfer;

use openssl::base64;
use openssl::rsa::{Padding, Rsa};
use ylong_runtime::sync::RwLock;

use super::sys_para::*;
use crate::utils::hdc_log::*;
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, prelude::*, Error, ErrorKind, Write};
use std::path::Path;
use std::process::Command;
use std::string::ToString;
use std::sync::Arc;

#[derive(Clone, PartialEq, Eq)]
pub enum AuthStatus {
    Init(String),           // with plain
    Pubk((String, String)), // with (plain, pk)
    Ok,
    Fail,
}

pub enum UserPermit {
    Refuse = 0,
    AllowOnce = 1,
    AllowForever = 2,
}

type AuthStatusMap_ = Arc<RwLock<HashMap<u32, AuthStatus>>>;

pub struct AuthStatusMap {}
impl AuthStatusMap {
    fn get_instance() -> AuthStatusMap_ {
        static mut AUTH_STATUS_MAP: Option<AuthStatusMap_> = None;
        unsafe {
            AUTH_STATUS_MAP
                .get_or_insert_with(|| Arc::new(RwLock::new(HashMap::new())))
                .clone()
        }
    }

    pub async fn get(session_id: u32) -> AuthStatus {
        let instance = Self::get_instance();
        let map = instance.read().await;
        map.get(&session_id).unwrap().clone()
    }

    async fn put(session_id: u32, auth_status: AuthStatus) {
        let instance = Self::get_instance();
        let mut map = instance.write().await;
        map.insert(session_id, auth_status);
    }
}

pub async fn handshake_init(task_message: TaskMessage) -> io::Result<(u32, TaskMessage)> {
    if task_message.command != HdcCommand::KernelHandshake {
        return Err(Error::new(ErrorKind::Other, "unknown command flag"));
    }

    let mut recv = native_struct::SessionHandShake::default();
    recv.parse(task_message.payload)?;

    hdc::info!("recv handshake: {:#?}", recv);
    if recv.banner != HANDSHAKE_MESSAGE {
        return Err(Error::new(ErrorKind::Other, "Recv server-hello failed"));
    }

    hdc::info!(
        "client version({}) for session:{}",
        recv.version.as_str(),
        recv.session_id
    );
    if recv.version.as_str() < "Ver: 3.0.0b" {
        hdc::info!(
            "client version({}) is too low, return OK for session:{}",
            recv.version.as_str(),
            recv.session_id
        );
        return Ok((
            recv.session_id,
            make_ok_message(recv.session_id, task_message.channel_id).await,
        ));
    }
    if !is_auth_enable() {
        hdc::info!(
            "auth enable is false, return OK for session:{}",
            recv.session_id
        );
        return Ok((
            recv.session_id,
            make_ok_message(recv.session_id, task_message.channel_id).await,
        ));
    }

    // auth is required
    let buf = generate_token_wait().await;

    AuthStatusMap::put(recv.session_id, AuthStatus::Init(buf.clone())).await;

    let send = native_struct::SessionHandShake {
        banner: HANDSHAKE_MESSAGE.to_string(),
        session_id: recv.session_id,
        connect_key: "".to_string(),
        buf,
        auth_type: AuthType::Publickey as u8,
        version: get_version(),
    };

    hdc::info!("send handshake: {:#?}", send);
    let message = TaskMessage {
        channel_id: task_message.channel_id,
        command: HdcCommand::KernelHandshake,
        payload: send.serialize(),
    };
    Ok((recv.session_id, message))
}

async fn make_sign_message(session_id: u32, token: String, channel_id: u32) -> TaskMessage {
    let send = native_struct::SessionHandShake {
        banner: HANDSHAKE_MESSAGE.to_string(),
        session_id,
        connect_key: "".to_string(),
        buf: token,
        auth_type: AuthType::Signature as u8,
        version: get_version(),
    };
    TaskMessage {
        channel_id,
        command: HdcCommand::KernelHandshake,
        payload: send.serialize(),
    }
}

async fn make_ok_message(session_id: u32, channel_id: u32) -> TaskMessage {
    AuthStatusMap::put(session_id, AuthStatus::Ok).await;

    let devname = String::from("devname         9               localhost");
    let authret = String::from("daemonauthstatus7               SUCCESS");
    let succmsg = format!("{}{}", devname, authret);

    let send = native_struct::SessionHandShake {
        banner: HANDSHAKE_MESSAGE.to_string(),
        session_id,
        connect_key: "".to_string(),
        auth_type: AuthType::OK as u8,
        version: get_version(),
        buf: succmsg,
    };
    TaskMessage {
        channel_id,
        command: HdcCommand::KernelHandshake,
        payload: send.serialize(),
    }
}

pub fn get_host_pubkey_info(buf: &str) -> (String, String) {
    if let Some((hostname, pubkey)) = buf.split_once(HDC_HOST_DAEMON_BUF_SEPARATOR) {
        (hostname.to_string(), pubkey.to_string())
    } else {
        ("".to_string(), "".to_string())
    }
}

pub async fn get_new_session_id(task_message: &TaskMessage) -> io::Result<u32> {
    let mut recv = native_struct::SessionHandShake::default();
    recv.parse(task_message.payload.clone())?;
    Ok(recv.session_id)
}

pub async fn handshake_task(task_message: TaskMessage, session_id: u32) -> io::Result<()> {
    if let AuthStatus::Ok = AuthStatusMap::get(session_id).await {
        hdc::info!("session {} already auth ok", session_id);
        return Ok(());
    }

    let channel_id = task_message.channel_id;

    if !is_auth_enable() {
        hdc::info!("auth enable is false, return OK for session:{}", session_id);
        transfer::put(session_id, make_ok_message(session_id, channel_id).await).await;
        return Ok(());
    }

    let mut recv = native_struct::SessionHandShake::default();
    recv.parse(task_message.payload)?;
    hdc::info!("recv handshake: {:#?}", recv);

    if recv.auth_type == AuthType::Publickey as u8 {
        let plain = if let AuthStatus::Init(buf) = AuthStatusMap::get(session_id).await {
            hdc::info!("get plain success for session {}", session_id);
            buf
        } else {
            hdc::error!("get plain failed for session {}", session_id);
            handshake_fail(session_id, channel_id, "auth failed".to_string()).await;
            return Ok(());
        };
        let token = plain.clone();

        let (hostname, pubkey) = get_host_pubkey_info(recv.buf.trim());
        if pubkey.is_empty() {
            hdc::error!("get public key from host failed");
            handshake_fail(
                session_id,
                channel_id,
                "no public key, you may need update your hdc client".to_string(),
            )
            .await;
            return Ok(());
        }
        if hostname.is_empty() {
            hdc::error!("get hostname from host failed");
            handshake_fail(
                session_id,
                channel_id,
                "no hostname, you may need update your hdc client".to_string(),
            )
            .await;
            return Ok(());
        }

        let known_hosts = read_known_hosts_pubkey();
        if known_hosts.contains(&pubkey) {
            hdc::info!("pubkey matches known host({})", hostname);
            AuthStatusMap::put(session_id, AuthStatus::Pubk((plain, pubkey))).await;
            transfer::put(
                session_id,
                make_sign_message(session_id, token, channel_id).await,
            )
            .await;
            return Ok(());
        }
        match require_user_permittion(&hostname).await {
            UserPermit::AllowForever => {
                hdc::info!("allow forever");
                if write_known_hosts_pubkey(&pubkey).is_err() {
                    handshake_fail(
                        session_id,
                        channel_id,
                        "write public key failed".to_string(),
                    )
                    .await;

                    hdc::error!("write public key failed");
                    return Ok(());
                }
                AuthStatusMap::put(session_id, AuthStatus::Pubk((plain, pubkey))).await;
                transfer::put(
                    session_id,
                    make_sign_message(session_id, token, channel_id).await,
                )
                .await;
            }
            UserPermit::AllowOnce => {
                hdc::info!("allow once");
                AuthStatusMap::put(session_id, AuthStatus::Pubk((plain, pubkey))).await;
                transfer::put(
                    session_id,
                    make_sign_message(session_id, token, channel_id).await,
                )
                .await;
            }
            _ => {
                hdc::info!("user refuse");
                handshake_fail(
                    session_id,
                    channel_id,
                    "public key refused by device".to_string(),
                )
                .await;
                return Ok(());
            }
        }
    } else if recv.auth_type == AuthType::Signature as u8 {
        match validate_signature(recv.buf, session_id).await {
            Ok(()) => {
                transfer::put(session_id, make_ok_message(session_id, channel_id).await).await;
                transfer::put(
                    session_id,
                    TaskMessage {
                        channel_id,
                        command: HdcCommand::KernelChannelClose,
                        payload: vec![0],
                    },
                )
                .await;
            }
            Err(e) => {
                let errlog = e.to_string();
                hdc::error!("validate signature failed: {}", &errlog);
                handshake_fail(session_id, channel_id, errlog).await;
            }
        }
    } else {
        hdc::error!(
            "invalid auth_type: {} for session {}",
            recv.auth_type,
            session_id
        );
        // handshake_fail session_id, channel_id auth failed await
        // transfer::put(session_id, make_ok_message(session_id, channel_id).await).await;
    }
    Ok(())
}

async fn validate_signature(signature: String, session_id: u32) -> io::Result<()> {
    let (plain, pubkey) =
        if let AuthStatus::Pubk((plain, pubkey)) = AuthStatusMap::get(session_id).await {
            (plain, pubkey)
        } else {
            return Err(Error::new(ErrorKind::Other, "auth failed"));
        };

    let signature_bytes = if let Ok(bytes) = base64::decode_block(&signature) {
        bytes
    } else {
        return Err(Error::new(ErrorKind::Other, "signature decode failed"));
    };

    let rsa = if let Ok(cipher) = Rsa::public_key_from_pem(pubkey.as_bytes()) {
        cipher
    } else {
        return Err(Error::new(ErrorKind::Other, "pubkey convert failed"));
    };

    let mut buf = vec![0_u8; config::RSA_BIT_NUM];
    let dec_size = rsa
        .public_decrypt(&signature_bytes, &mut buf, Padding::PKCS1)
        .unwrap_or(0);

    if plain.as_bytes() == &buf[..dec_size] {
        Ok(())
    } else {
        Err(Error::new(ErrorKind::Other, "signature not match"))
    }
}

pub fn clear_auth_pub_key_file() {
    return;

    if !is_auth_enable() {
        return;
    }

    let (_, auth_cancel) = get_dev_item("persist.hdc.daemon.auth_cancel", "_");
    if auth_cancel.trim().to_lowercase() != "true" {
        hdc::info!("auth_cancel is {}, no need clear pubkey file", auth_cancel);
        return;
    }

    if !set_dev_item("persist.hdc.daemon.auth_cancel", "false") {
        hdc::error!("clear param auth_cancel failed.");
    }

    let file_name = Path::new(config::RSA_PUBKEY_PATH).join(config::RSA_PUBKEY_NAME);
    match std::fs::remove_file(&file_name) {
        Ok(_) => {
            hdc::info!("remove pubkey file {:#?} success", file_name);
        },
        Err(err) => {
            hdc::error!("remove pubkey file {:#?} failed: {}", file_name, err);
        },
    }
}

fn read_known_hosts_pubkey() -> Vec<String> {
    let file_name = Path::new(config::RSA_PUBKEY_PATH).join(config::RSA_PUBKEY_NAME);
    if let Ok(keys) = std::fs::read_to_string(&file_name) {
        let mut key_vec = vec![];
        let mut tmp_vec = vec![];

        for line in keys.split('\n') {
            if line.contains("BEGIN PUBLIC KEY") {
                tmp_vec.clear();
            }
            tmp_vec.push(line);
            if line.contains("END PUBLIC KEY") {
                key_vec.push(tmp_vec.join("\n"));
            }
        }

        hdc::debug!("read {} known hosts from file", key_vec.len());
        key_vec
    } else {
        hdc::info!("pubkey file {:#?} not exists", file_name);
        vec![]
    }
}

fn write_known_hosts_pubkey(pubkey: &String) -> io::Result<()> {
    let file_name = Path::new(config::RSA_PUBKEY_PATH).join(config::RSA_PUBKEY_NAME);
    if !file_name.exists() {
        hdc::info!("will create pubkeys file at {:#?}", file_name);

        if let Err(e) = std::fs::create_dir_all(config::RSA_PUBKEY_PATH) {
            log::error!("create pubkeys dir: {}", e.to_string());
        }
        if let Err(e) = std::fs::File::create(&file_name) {
            log::error!("create pubkeys file: {}", e.to_string());
        }
    }

    let _ = match std::fs::File::options().append(true).open(file_name) {
        Ok(mut f) => writeln!(&mut f, "{}", pubkey),
        Err(e) => {
            hdc::error!("write pubkey err: {}", e.to_string());
            return Err(e);
        }
    };
    Ok(())
}

fn show_permit_dialog() -> bool {
    let cmd = "/system/bin/hdcd_user_permit";
    let result = Command::new(cmd).output();
    match result {
        Ok(output) => {
            let msg = [output.stdout, output.stderr].concat();
            let mut str = String::from_utf8(msg).unwrap();
            str = str.replace('\n', " ");
            hdc::error!("show dialog over, {}.", str);
            true
        }
        Err(e) => {
            hdc::error!("show dialog failed, {}.", e.to_string());
            false
        }
    }
}

pub fn is_auth_enable() -> bool {
    return false;

    let (_, auth_enable) = get_dev_item("const.hdc.secure", "_");
    hdc::error!("const.hdc.secure is {}.", auth_enable);
    if auth_enable.trim().to_lowercase() != "1" {
        return false;
    }

    // if persist.hdc.auth_bypass is set "1", will not auth,
    // otherwhise must be auth
    // the auto upgrade test will set persist.hdc.auth_bypass 1
    let (_, auth_bypass) = get_dev_item("persist.hdc.auth_bypass", "_");
    hdc::error!("persist.hdc.auth_bypass is {}.", auth_bypass);
    auth_bypass.trim().to_lowercase() != "1"
}

async fn require_user_permittion(hostname: &str) -> UserPermit {
    // todo debug
    let default_permit = "auth_result_none";
    // clear result first
    if !set_dev_item("persist.hdc.daemon.auth_result", default_permit) {
        hdc::error!("debug auth result failed, so refuse this connect.");
        return UserPermit::Refuse;
    }

    // then write para for setting
    if !set_dev_item("persist.hdc.client.hostname", hostname) {
        hdc::error!("set param({}) failed.", hostname);
        return UserPermit::Refuse;
    }
    if !show_permit_dialog() {
        hdc::error!("show dialog failed, so refuse this connect.");
        return UserPermit::Refuse;
    }
    let permit_result = match get_dev_item("persist.hdc.daemon.auth_result", "_") {
        (false, _) => {
            hdc::error!("get_dev_item auth_result failed");
            UserPermit::Refuse
        }
        (true, auth_result) => {
            hdc::error!("user permit result is:({})", auth_result);
            match auth_result.strip_prefix("auth_result:").unwrap().trim() {
                "1" => UserPermit::AllowOnce,
                "2" => UserPermit::AllowForever,
                _ => UserPermit::Refuse,
            }
        }
    };
    permit_result
}

async fn handshake_fail(session_id: u32, channel_id: u32, msg: String) {
    AuthStatusMap::put(session_id, AuthStatus::Fail).await;
    let send = native_struct::SessionHandShake {
        banner: HANDSHAKE_MESSAGE.to_string(),
        session_id,
        auth_type: AuthType::Fail as u8,
        buf: msg,
        ..Default::default()
    };
    transfer::put(
        session_id,
        TaskMessage {
            channel_id,
            command: config::HdcCommand::KernelHandshake,
            payload: send.serialize(),
        },
    )
    .await;
}

async fn generate_token() -> io::Result<String> {
    let mut random_file = File::open("/dev/random")?;
    let mut buffer = [0; HDC_HANDSHAKE_TOKEN_LEN];
    random_file.read_exact(&mut buffer)?;
    let random_vec: Vec<_> = buffer.iter().map(|h| format!("{:02X}", h)).collect();
    let token = random_vec.join("");
    Ok(token)
}
async fn generate_token_wait() -> String {
    loop {
        match generate_token().await {
            Ok(token) => {
                break token;
            }
            Err(e) => {
                let errlog = e.to_string();
                hdc::error!("generate token failed: {}", &errlog);
            }
        }
    }
}
