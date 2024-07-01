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
//! forward
#![allow(missing_docs)]
#[cfg(feature = "host")]
// extern crate ylong_runtime_static as ylong_runtime;

#[cfg(not(feature = "host"))]
use libc::SOCK_STREAM;
#[cfg(not(target_os = "windows"))]
use libc::{AF_LOCAL, AF_UNIX, FD_CLOEXEC, F_SETFD};
use std::collections::HashMap;
use std::fs;
#[cfg(not(target_os = "windows"))]
use std::fs::File;
#[cfg(not(target_os = "windows"))]
use std::io::Read;
use std::io::{self, Error, ErrorKind};
use ylong_runtime::sync::{Mutex, RwLock};

use crate::common::base::Base;
use crate::common::hdctransfer::transfer_task_finish;
use crate::common::hdctransfer::{self, HdcTransferBase};
#[cfg(not(feature = "host"))]
use crate::common::jdwp::Jdwp;
#[cfg(not(target_os = "windows"))]
use crate::common::uds::{UdsAddr, UdsClient, UdsServer};
#[cfg(not(feature = "host"))]
use crate::common::context::ContextMap;
use crate::{config, utils};
#[cfg(not(feature = "host"))]
use crate::config::ContextType;
use crate::config::HdcCommand;
use crate::config::MessageLevel;
use crate::config::TaskMessage;
use crate::transfer;
#[allow(unused)]
use crate::utils::hdc_log::*;
use std::sync::Arc;
#[cfg(not(feature = "host"))]
use std::time::Duration;
use ylong_runtime::io::AsyncReadExt;
use ylong_runtime::io::AsyncWriteExt;
use ylong_runtime::net::{SplitReadHalf, SplitWriteHalf, TcpListener, TcpStream};
use ylong_runtime::task::JoinHandle;

pub const ARG_COUNT2: u32 = 2;
pub const BUF_SIZE_SMALL: usize = 256;
pub const SOCKET_BUFFER_SIZE: usize = 65535;
pub const HARMONY_RESERVED_SOCKET_PREFIX: &str = "/dev/socket";
pub const FILE_SYSTEM_SOCKET_PREFIX: &str = "/tmp/";

#[cfg(feature = "host")]
#[derive(Clone, Debug)]
pub struct HdcForwardInfo {
    pub session_id: u32,
    pub channel_id: u32,
    pub forward_direction: bool,
    pub task_string: String,
    pub connect_key: String,
}

#[cfg(feature = "host")]
impl HdcForwardInfo {
    fn new(
        session_id: u32,
        channel_id: u32,
        forward_direction: bool,
        task_string: String,
        connect_key: String,
    ) -> Self {
        Self {
            session_id,
            channel_id,
            forward_direction,
            task_string,
            connect_key,
        }
    }
}

#[cfg(feature = "host")]
type HdcForwardInfo_ = Arc<Mutex<HdcForwardInfo>>;
#[cfg(feature = "host")]
type HdcForwardInfoMap_ = Arc<Mutex<HashMap<String, HdcForwardInfo_>>>;
#[cfg(feature = "host")]
pub struct HdcForwardInfoMap {}
#[cfg(feature = "host")]
impl HdcForwardInfoMap {
    fn get_instance() -> HdcForwardInfoMap_ {
        static mut MAP: Option<HdcForwardInfoMap_> = None;
        unsafe {
            MAP.get_or_insert_with(|| Arc::new(Mutex::new(HashMap::new())))
                .clone()
        }
    }

    async fn put(forward_info: HdcForwardInfo) {
        let instance = Self::get_instance();
        let mut map = instance.lock().await;
        map.insert(
            forward_info.task_string.clone(),
            Arc::new(Mutex::new(forward_info)),
        );
    }

    pub async fn get_all_forward_infos() -> Vec<HdcForwardInfo> {
        let instance = Self::get_instance();
        let map = instance.lock().await;
        let mut result = Vec::new();
        for (_key, value) in map.iter() {
            let info = value.lock().await;
            result.push((*info).clone());
        }
        result
    }

    pub async fn remove_forward(task_string: String, forward_direction: bool) -> bool {
        crate::info!(
            "remove_forward task_string:{}, direction:{}",
            task_string,
            forward_direction
        );
        let instance = Self::get_instance();
        let map = instance.lock().await;
        let mut remove_key = String::new();
        let prefix = if forward_direction {
            "1|".to_string()
        } else {
            "0|".to_string()
        };
        let mut task_string1 = prefix;
        task_string1.push_str(task_string.as_str());
        for (key, value) in map.iter() {
            let info = value.lock().await;
            if info.task_string.contains(&task_string1)
                && info.forward_direction == forward_direction
            {
                remove_key = (*key.clone()).to_string();
                break;
            }
        }
        drop(map);
        if remove_key.is_empty() {
            return false;
        }

        let mut map = instance.lock().await;
        let result = map.remove(&remove_key);
        result.is_some()
    }
}

type TcpRead = Arc<Mutex<SplitReadHalf>>;
type TcpReadMap_ = Arc<RwLock<HashMap<u32, TcpRead>>>;
pub struct TcpReadStreamMap {}
impl TcpReadStreamMap {
    fn get_instance() -> TcpReadMap_ {
        static mut TCP_MAP: Option<TcpReadMap_> = None;
        unsafe {
            TCP_MAP
                .get_or_insert_with(|| Arc::new(RwLock::new(HashMap::new())))
                .clone()
        }
    }
    #[allow(unused)]
    async fn put(id: u32, rd: SplitReadHalf) {
        let instance = Self::get_instance();
        let mut map = instance.write().await;
        let arc_rd = Arc::new(Mutex::new(rd));
        map.insert(id, arc_rd);
    }
    #[allow(unused)]
    async fn read(session_id: u32, channel_id: u32, cid: u32) {
        let arc_map = Self::get_instance();
        let map = arc_map.read().await;
        let Some(arc_rd) = map.get(&cid) else {
            crate::error!("TcpReadStreamMap failed to get cid {:#?}", cid);
            return;
        };
        let rd = &mut arc_rd.lock().await;
        let mut data = vec![0_u8; SOCKET_BUFFER_SIZE];
        loop {
            match rd.read(&mut data).await {
                Ok(recv_size) => {
                    if recv_size == 0 {
                        free_context(session_id, channel_id, 0, true).await;
                        crate::info!("tcp close shutdown, channel_id = {:#?}", channel_id);
                        return;
                    }
                    if send_to_task(
                        session_id,
                        channel_id,
                        HdcCommand::ForwardData,
                        &data[0..recv_size],
                        recv_size,
                        cid,
                    )
                    .await
                    {
                        crate::info!("send task success");
                    }
                }
                Err(_e) => {
                    crate::error!("tcp stream rd read failed");
                }
            }
        }
    }
}

type TcpWriter = Arc<Mutex<SplitWriteHalf>>;
type TcpWriterMap_ = Arc<RwLock<HashMap<u32, TcpWriter>>>;
pub struct TcpWriteStreamMap {}
impl TcpWriteStreamMap {
    fn get_instance() -> TcpWriterMap_ {
        static mut TCP_MAP: Option<TcpWriterMap_> = None;
        unsafe {
            TCP_MAP
                .get_or_insert_with(|| Arc::new(RwLock::new(HashMap::new())))
                .clone()
        }
    }
    #[allow(unused)]
    async fn put(id: u32, wr: SplitWriteHalf) {
        let instance = Self::get_instance();
        let mut map = instance.write().await;
        let arc_wr = Arc::new(Mutex::new(wr));
        map.insert(id, arc_wr);
    }
    #[allow(unused)]
    async fn write(id: u32, data: Vec<u8>) {
        let arc_map = Self::get_instance();
        let map = arc_map.write().await;
        let Some(arc_wr) = map.get(&id) else {
            crate::error!("TcpReadStreamMap failed to get id {:#?}", id);
            return;
        };
        let mut wr = arc_wr.lock().await;
        let _ = wr.write_all(data.as_slice()).await;
    }

    pub async fn end(id: u32) {
        let instance = Self::get_instance();
        let mut map = instance.write().await;
        if let Some(arc_wr) = map.remove(&id) {
            let mut wr = arc_wr.lock().await;
            let _ = wr.shutdown().await;
        }
    }
}

type TcpListener_ = Arc<Mutex<JoinHandle<()>>>;
type TcpListenerMap_ = Arc<RwLock<HashMap<u32, TcpListener_>>>;
pub struct TcpListenerMap {}
impl TcpListenerMap {
    fn get_instance() -> TcpListenerMap_ {
        static mut TCP_MAP: Option<TcpListenerMap_> = None;
        unsafe {
            TCP_MAP
                .get_or_insert_with(|| Arc::new(RwLock::new(HashMap::new())))
                .clone()
        }
    }
    #[allow(unused)]
    async fn put(id: u32, listener: JoinHandle<()>) {
        let instance = Self::get_instance();
        let mut map = instance.write().await;
        let arc_listener = Arc::new(Mutex::new(listener));
        map.insert(id, arc_listener);
        crate::info!("forward tcp put listener id = {id}");
    }

    pub async fn end(id: u32) {
        let instance = Self::get_instance();
        let mut map = instance.write().await;
        if let Some(arc_listener) = map.remove(&id) {
            let join_handle = arc_listener.lock().await;
            join_handle.cancel();
        }
    }
}

#[derive(Default, Eq, PartialEq, Clone, Debug)]
enum ForwardType {
    #[default]
    Tcp = 0,
    Device,
    Abstract,
    FileSystem,
    Jdwp,
    Ark,
    Reserved,
}

#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct ContextForward {
    session_id: u32,
    channel_id: u32,
    check_order: bool,
    id: u32,
    fd: i32,
    target_fd: i32,
    remote_parameters: String,
    last_error: String,
    forward_type: ForwardType,
}

type MapForward_ = Arc<Mutex<HashMap<(u32, u32), HdcForward>>>;
pub struct ForwardTaskMap {}
impl ForwardTaskMap {
    fn get_instance() -> MapForward_ {
        static mut FORWARD_MAP: Option<MapForward_> = None;
        unsafe {
            FORWARD_MAP
                .get_or_insert_with(|| Arc::new(Mutex::new(HashMap::new())))
                .clone()
        }
    }

    pub async fn update(session_id: u32, channel_id: u32, value: HdcForward) {
        let map = Self::get_instance();
        let mut map = map.lock().await;
        map.insert((session_id, channel_id), value.clone());
        #[cfg(not(feature = "host"))]
        ContextMap::put(session_id, channel_id, ContextType::Forward).await;
    }

    pub async fn remove(session_id: u32, channel_id: u32) {
        crate::info!("remove, session:{}, channel:{}", session_id, channel_id);
        let map = Self::get_instance();
        let mut map = map.lock().await;
        let _ = map.remove(&(session_id, channel_id));
    }

    pub async fn get(session_id: u32, channel_id: u32) -> Option<HdcForward> {
        let arc = Self::get_instance();
        let map = arc.lock().await;
        let task = map.get(&(session_id, channel_id));
        match task {
            Some(task) => Some(task.clone()),
            None => {
                crate::error!(
                    "ForwardTaskMap result:is none,session_id={:#?}, channel_id={:#?}",
                    session_id,
                    channel_id
                );
                Option::None
            }
        }
    }

    pub async fn get_channel_id(session_id: u32, task_string: String) -> Option<u32> {
        let arc = Self::get_instance();
        let map = arc.lock().await;
        for ((_session_id, _channel_id), value) in map.iter() {
            if *_session_id == session_id && task_string.contains(&value.task_command) {
                return Some(*_channel_id);
            }
        }
        None
    }

    pub async fn clear(session_id: u32) {
        let arc = Self::get_instance();
        let mut channel_list = Vec::new();
        {
            let map = arc.lock().await;
            if map.is_empty() {
                return;
            }
            for (&key, _) in map.iter() {
                if key.0 == session_id {
                    let id = key;
                    channel_list.push(id);
                }
            }
        }
        for id in channel_list {
            free_channel_task(id.0, id.1).await;
        }
    }

    pub async fn dump_task() -> String {
        let arc = Self::get_instance();
        let map = arc.lock().await;
        let mut result = String::new();
        for (_id, forward_task) in map.iter() {
            let forward_type = match forward_task.remote_args.len() {
                0 => "fport".to_string(),
                2 => "rport".to_string(),
                _ => "unknown".to_string(),
            };
            let first_args = match forward_task.remote_args.len() {
                0 => "unknown".to_string(),
                2 => format!(
                    "{}:{}",
                    forward_task.local_args[0], forward_task.local_args[1]
                ),
                _ => "unknown".to_string(),
            };
            let second_args = match forward_task.remote_args.len() {
                0 => format!(
                    "{}:{}",
                    forward_task.local_args[0], forward_task.local_args[1]
                ),
                2 => format!(
                    "{}:{}",
                    forward_task.remote_args[0], forward_task.remote_args[1]
                ),
                _ => "unknown".to_string(),
            };
            result.push_str(&format!(
                "session_id:{},\tchannel_id:{},\tcommand:{:#} {:#} {:#}\n",
                forward_task.session_id,
                forward_task.channel_id,
                forward_type,
                first_args,
                second_args
            ));
        }
        result
    }
}

pub async fn free_channel_task(session_id: u32, channel_id: u32) {
    let Some(task) = ForwardTaskMap::get(session_id, channel_id).await else {
        return;
    };
    crate::info!("free_context session_id:{session_id}, channel_id:{channel_id}");
    let task = &mut task.clone();
    match task.forward_type {
        ForwardType::Tcp => {
            TcpWriteStreamMap::end(channel_id).await;
            TcpListenerMap::end(channel_id).await;
        }
        ForwardType::Jdwp | ForwardType::Ark => {
            TcpWriteStreamMap::end(channel_id).await;
            let ret = unsafe { libc::close(task.context_forward.fd) };
            crate::debug!(
                "close context_forward fd, ret={}, session_id={}, channel_id={}",
                ret,
                session_id,
                channel_id,
            );
            let target_fd_ret = unsafe { libc::close(task.context_forward.target_fd) };
            crate::debug!(
                "close context_forward target fd, ret={}, session_id={}, channel_id={}",
                target_fd_ret,
                session_id,
                channel_id,
            );
            TcpListenerMap::end(channel_id).await;
        }        
        ForwardType::Abstract | ForwardType::FileSystem | ForwardType::Reserved => {
            #[cfg(not(target_os = "windows"))]
            UdsServer::wrap_close(task.context_forward.fd);
        }
        ForwardType::Device => {
            return;
        }
    }
    ForwardTaskMap::remove(session_id, channel_id).await;
}

pub async fn stop_task(session_id: u32) {
    crate::info!("forward free task session_id: {}", session_id);
    ForwardTaskMap::clear(session_id).await;
}

pub async fn dump_task() -> String {
    ForwardTaskMap::dump_task().await
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct HdcForward {
    session_id: u32,
    channel_id: u32,
    is_master: bool,
    local_args: Vec<String>,
    remote_args: Vec<String>,
    remote_parameters: String,
    task_command: String,
    forward_type: ForwardType,
    context_forward: ContextForward,
    map_ctx_point: HashMap<u32, ContextForward>,
    pub transfer: HdcTransferBase,
}

impl HdcForward {
    pub fn new(session_id: u32, channel_id: u32) -> Self {
        Self {
            session_id,
            channel_id,
            is_master: Default::default(),
            local_args: Default::default(),
            remote_args: Default::default(),
            task_command: Default::default(),
            remote_parameters: Default::default(),
            forward_type: Default::default(),
            context_forward: Default::default(),
            map_ctx_point: HashMap::new(),
            transfer: HdcTransferBase::new(session_id, channel_id),
        }
    }
}

pub fn get_id(_payload: &[u8]) -> u32 {
    let mut id_bytes = [0u8; 4];
    id_bytes.copy_from_slice(&_payload[0..4]);
    let id: u32 = u32::from_be_bytes(id_bytes);
    id
}

pub async fn check_node_info(value: &String, arg: &mut Vec<String>) -> bool {
    crate::info!("check cmd args value is: {:#?}", value);
    if !value.contains(':') {
        return false;
    }
    let array = value.split(':').collect::<Vec<&str>>();

    if array[0] == "tcp" {
        if array[1].len() > config::MAX_PORT_LEN {
            crate::error!(
                "forward port = {:#?} it'slength is wrong, can not more than five",
                array[1]
            );
            return false;
        }

        match array[1].parse::<u32>() {
            Ok(port) => {
                if port == 0 || port > config::MAX_PORT_NUM {
                    crate::error!("port can not greater than: 65535");
                    return false;
                }
            }
            Err(_) => {
                crate::error!("port must is int type, port is: {:#?}", array[1]);
                return false;
            }
        }
    }
    for item in array.iter() {
        arg.push(String::from(item.to_owned()));
    }
    true
}

#[cfg(feature = "host")]
pub async fn on_forward_success(task_message: TaskMessage, session_id: u32) -> io::Result<()> {
    crate::info!("on_forward_success");
    let channel_id = task_message.channel_id;
    let payload = task_message.payload;
    let forward_direction = payload[0] == b'1';
    let task_string = String::from_utf8(payload);
    let connect_key = "unknow key".to_string();
    if task_string.is_ok() {
        let info = HdcForwardInfo::new(
            session_id,
            channel_id,
            forward_direction,
            task_string.unwrap(),
            connect_key,
        );
        HdcForwardInfoMap::put(info).await;
    }
    transfer::TcpMap::end(task_message.channel_id).await;
    Ok(())
}

pub async fn check_command(session_id: u32, channel_id: u32, _payload: &[u8]) -> bool {
    let Some(task) = ForwardTaskMap::get(session_id, channel_id).await else {
        crate::error!("check_command task is none");
        return false;
    };
    let task = &mut task.clone();
    if !_payload.is_empty() {
        echo_client(
            session_id,
            channel_id,
            "Forwardport result:OK",
            MessageLevel::Ok,
        )
        .await;
        let map_info = String::from(if task.transfer.server_or_daemon {
            "1|"
        } else {
            "0|"
        }) + &task.task_command;

        let mut command_string = vec![0_u8; map_info.len() + 1];
        map_info
            .as_bytes()
            .to_vec()
            .iter()
            .enumerate()
            .for_each(|(i, e)| {
                command_string[i] = *e;
            });
        let forward_success_message = TaskMessage {
            channel_id,
            command: HdcCommand::ForwardSuccess,
            payload: command_string,
        };
        #[cfg(feature = "host")]
        {
            let _ = on_forward_success(forward_success_message, session_id).await;
        }
        #[cfg(not(feature = "host"))]
        {
            transfer::put(session_id, forward_success_message).await;
        }
    } else {
        echo_client(
            session_id,
            channel_id,
            "Forwardport result: Failed",
            MessageLevel::Fail,
        )
        .await;
        free_context(session_id, channel_id, 0, false).await;
        return false;
    }
    true
}

pub async fn detech_forward_type(session_id: u32, channel_id: u32) -> bool {
    let Some(task) = ForwardTaskMap::get(session_id, channel_id).await else {
        crate::error!("detech_forward_type get task is none session_id = {session_id}, channel_id = {channel_id}");
        return false;
    };
    let task = &mut task.clone();

    let type_str = &task.local_args[0];

    match type_str.as_str() {
        "tcp" => {
            task.forward_type = ForwardType::Tcp;
        }
        "dev" => {
            task.forward_type = ForwardType::Device;
        }
        "localabstract" => {
            task.forward_type = ForwardType::Abstract;
        }
        "localfilesystem" => {
            task.local_args[1] = HARMONY_RESERVED_SOCKET_PREFIX.to_owned() + &task.local_args[1];
            task.forward_type = ForwardType::FileSystem;
        }
        "jdwp" => {
            task.forward_type = ForwardType::Jdwp;
        }
        "ark" => {
            task.forward_type = ForwardType::Ark;
        }
        "localreserved" => {
            task.local_args[1] = FILE_SYSTEM_SOCKET_PREFIX.to_owned() + &task.local_args[1];
            task.forward_type = ForwardType::Reserved;
        }
        _ => {
            crate::error!("this forward type may is not expected");
            ForwardTaskMap::update(session_id, channel_id, task.clone()).await;
            return false;
        }
    }
    ForwardTaskMap::update(session_id, channel_id, task.clone()).await;
    true
}

pub async fn forward_tcp_accept(
    session_id: u32,
    channel_id: u32,
    port: u32,
    value: String,
    cid: u32,
) -> io::Result<()> {
    let saddr = format!("127.0.0.1:{}", port);
    crate::info!("forward_tcp_accept bind addr:{:#?}", saddr);
    let result = TcpListener::bind(saddr.clone()).await;
    match result {
        Ok(listener) => {
            crate::info!("forward_tcp_accept bind ok");
            let join_handle = utils::spawn(async move {
                loop {
                    let client = listener.accept().await;
                    if client.is_err() {
                        continue;
                    }
                    let (stream, _addr) = client.unwrap();
                    let (rd, wr) = stream.into_split();
                    TcpWriteStreamMap::put(channel_id, wr).await;
                    utils::spawn(on_accept(session_id, channel_id, value.clone(), cid));
                    recv_tcp_msg(session_id, channel_id, rd, cid).await;
                }
            });
            TcpListenerMap::put(channel_id, join_handle).await;
            Ok(())
        }
        Err(e) => {
            crate::error!("forward_tcp_accept fail:{:#?}", e);
            Err(e)
        }
    }
}

pub async fn recv_tcp_msg(session_id: u32, channel_id: u32, mut rd: SplitReadHalf, cid: u32) {
    let mut data = vec![0_u8; SOCKET_BUFFER_SIZE];
    loop {
        match rd.read(&mut data).await {
            Ok(recv_size) => {
                if recv_size == 0 {
                    free_context(session_id, channel_id, 0, true).await;
                    drop(rd);
                    crate::info!("recv_size is 0, tcp close shutdown");
                    return;
                }
                if send_to_task(
                    session_id,
                    channel_id,
                    HdcCommand::ForwardData,
                    &data[0..recv_size],
                    recv_size,
                    cid,
                )
                .await
                {
                    crate::info!("send task success");
                }
            }
            Err(_e) => {
                crate::error!(
                    "recv tcp msg read failed session_id={session_id},channel_id={channel_id}"
                );
            }
        }
    }
}

pub async fn on_accept(session_id: u32, channel_id: u32, value: String, cid: u32) {
    let buf_string: Vec<u8> = value.as_bytes().to_vec();
    let mut new_buf = vec![0_u8; buf_string.len() + 9];

    buf_string.iter().enumerate().for_each(|(i, e)| {
        new_buf[i + 8] = *e;
    });

    send_to_task(
        session_id,
        channel_id,
        HdcCommand::ForwardActiveSlave,
        &new_buf,
        buf_string.len() + 9,
        cid,
    )
    .await;
}

pub async fn daemon_connect_tcp(session_id: u32, channel_id: u32, port: u32, cid: u32) {
    let saddr = format!("127.0.0.1:{}", port);
    let stream = match TcpStream::connect(saddr).await {
        Err(err) => {
            crate::error!("TcpStream::stream failed {:?}", err);
            free_context(session_id, channel_id, 0, false).await;
            return;
        }
        Ok(addr) => addr,
    };
    send_active_master(session_id, channel_id).await;
    let (rd, wr) = stream.into_split();
    TcpWriteStreamMap::put(channel_id, wr).await;
    recv_tcp_msg(session_id, channel_id, rd, cid).await;
}

#[cfg(not(target_os = "windows"))]
pub async fn deamon_read_socket_msg(session_id: u32, channel_id: u32, fd: i32) {
    let Some(task) = ForwardTaskMap::get(session_id, channel_id).await else {
        crate::error!("deamon_read_socket_msg get task is none session_id={session_id},channel_id={channel_id}");
        return;
    };
    let task = &mut task.clone();
    loop {
        let mut buffer: [u8; SOCKET_BUFFER_SIZE] = [0; SOCKET_BUFFER_SIZE];
        let recv_size = UdsClient::wrap_recv(fd, &mut buffer);
        if recv_size <= 0 {
            free_context(session_id, channel_id, 0, true).await;
            crate::info!("local abstract close shutdown");
            return;
        }
        if send_to_task(
            session_id,
            channel_id,
            HdcCommand::ForwardData,
            &buffer[0..recv_size as usize],
            recv_size as usize,
            task.context_forward.id,
        )
        .await
        {
            crate::info!("send task success");
        }
    }
}

pub async fn free_context(session_id: u32, channel_id: u32, _id: u32, notify_remote: bool) {
    let Some(task) = ForwardTaskMap::get(session_id, channel_id).await else {
        return;
    };
    crate::info!("free_context session_id:{session_id}, channel_id:{channel_id}");
    let task = &mut task.clone();
    if notify_remote {
        let vec_none = Vec::<u8>::new();
        send_to_task(
            session_id,
            channel_id,
            HdcCommand::ForwardFreeContext,
            &vec_none,
            0,
            task.context_forward.id,
        )
        .await;
    }
    match task.forward_type {
        ForwardType::Tcp => {
            TcpWriteStreamMap::end(channel_id).await;
            TcpListenerMap::end(channel_id).await;
        }
        ForwardType::Jdwp | ForwardType::Ark => {
            TcpWriteStreamMap::end(channel_id).await;
            let ret = unsafe { libc::close(task.context_forward.fd) };
            crate::debug!(
                "close context_forward fd, ret={}, session_id={}, channel_id={}",
                ret,
                session_id,
                channel_id,
            );
            let target_fd_ret = unsafe { libc::close(task.context_forward.target_fd) };
            crate::debug!(
                "close context_forward target fd, ret={}, session_id={}, channel_id={}",
                target_fd_ret,
                session_id,
                channel_id,
            );
            TcpListenerMap::end(channel_id).await;
        }        
        ForwardType::Abstract | ForwardType::FileSystem | ForwardType::Reserved => {
            #[cfg(not(target_os = "windows"))]
            UdsServer::wrap_close(task.context_forward.fd);
        }
        ForwardType::Device => {
            return;
        }
    }
    ForwardTaskMap::remove(session_id, channel_id).await;
}

pub async fn setup_tcp_point(session_id: u32, channel_id: u32) -> bool {
    let Some(mut task) = ForwardTaskMap::get(session_id, channel_id).await else {
        crate::error!(
            "setup_tcp_point get task is none session_id={session_id},channel_id={channel_id}"
        );
        return false;
    };
    let task = &mut task;
    let Ok(port) = task.local_args[1].parse::<u32>() else {
        crate::error!("setup_tcp_point parse error");
        return false;
    };
    let cid = task.context_forward.id;
    if task.is_master {
        let parameters = task.remote_parameters.clone();
        let result = forward_tcp_accept(session_id, channel_id, port, parameters, cid).await;
        crate::info!("setup_tcp_point result:{:?}", result);
        task.context_forward.last_error = format!("TCP Port listen failed at {}", port);
        ForwardTaskMap::update(session_id, channel_id, task.clone()).await;
        return result.is_ok();
    } else {
        crate::info!("setup_tcp_point slaver");
        utils::spawn(
            async move { daemon_connect_tcp(session_id, channel_id, port, cid).await },
        );
    }
    true
}

#[cfg(not(target_os = "windows"))]
async fn server_socket_bind_listen(
    session_id: u32,
    channel_id: u32,
    path: String,
    cid: u32,
) -> bool {
    let Some(task) = ForwardTaskMap::get(session_id, channel_id).await else {
        crate::error!(
            "setup_tcp_point get task is none session_id={session_id},channel_id={channel_id}"
        );
        return false;
    };
    let task = &mut task.clone();
    let parameters = task.remote_parameters.clone();
    let fd: i32 = UdsClient::wrap_socket(AF_UNIX);
    task.context_forward.fd = fd;
    ForwardTaskMap::update(session_id, channel_id, task.clone()).await;

    let name: Vec<u8> = path.as_bytes().to_vec();
    let mut socket_name = vec![0_u8; name.len() + 1];
    socket_name[0] = b'\0';
    name.iter().enumerate().for_each(|(i, e)| {
        socket_name[i + 1] = *e;
    });
    let addr = UdsAddr::parse_abstract(&socket_name[1..]);
    if let Ok(addr_obj) = &addr {
        let ret = UdsServer::wrap_bind(fd, addr_obj);
        if ret.is_err() {
            echo_client(
                session_id,
                channel_id,
                "Unix pipe bind failed",
                MessageLevel::Fail,
            )
            .await;
            crate::error!("bind fail");
            return false;
        }
        let ret = UdsServer::wrap_listen(fd);
        if ret < 0 {
            echo_client(
                session_id,
                channel_id,
                "Unix pipe listen failed",
                MessageLevel::Fail,
            )
            .await;
            crate::error!("listen fail");
            return false;
        }
        utils::spawn(async move {
            loop {
                let client_fd = UdsServer::wrap_accept(fd);
                if client_fd == -1 {
                    break;
                }
                utils::spawn(on_accept(session_id, channel_id, parameters.clone(), cid));
            }
        });
    }
    true
}

pub async fn canonicalize(path: String) -> Result<String, Error> {
    match fs::canonicalize(path) {
        Ok(abs_path) => match abs_path.to_str() {
            Some(path) => Ok(path.to_string()),
            None => Err(Error::new(ErrorKind::Other, "forward canonicalize failed")),
        },
        Err(_) => Err(Error::new(ErrorKind::Other, "forward canonicalize failed")),
    }
}

#[cfg(target_os = "windows")]
pub async fn setup_device_point(_session_id: u32, _channel_id: u32) -> bool {
    false
}

#[cfg(not(target_os = "windows"))]
pub async fn setup_device_point(session_id: u32, channel_id: u32) -> bool {
    let Some(task) = ForwardTaskMap::get(session_id, channel_id).await else {
        crate::error!(
            "setup_device_point get task is none session_id={session_id},channel_id={channel_id}"
        );
        return false;
    };
    let task = &mut task.clone();
    let s_node_cfg = task.local_args[1].clone();
    let cid = task.context_forward.id;

    let Ok(resolv_path) = canonicalize(s_node_cfg).await else {
        crate::error!("Open unix-dev failed");
        return false;
    };
    let thread_path_ref = Arc::new(Mutex::new(resolv_path));
    if !send_active_master(session_id, channel_id).await {
        crate::error!(
            "send_active_master return failed channel_id={:?}",
            channel_id
        );
        return false;
    }

    utils::spawn(async move {
        loop {
            let path = thread_path_ref.lock().await;
            let Ok(mut file) = File::open(&*path) else {
                crate::error!("open {} failed.", *path);
                break;
            };
            let mut total = Vec::new();
            let mut buf: [u8; config::FILE_PACKAGE_PAYLOAD_SIZE] =
                [0; config::FILE_PACKAGE_PAYLOAD_SIZE];
            let Ok(read_len) = file.read(&mut buf[4..]) else {
                crate::error!("read {} failed.", *path);
                break;
            };
            if read_len == 0 {
                free_context(session_id, channel_id, 0, true).await;
                break;
            }
            total.append(&mut buf[0..read_len].to_vec());
            send_to_task(
                session_id,
                channel_id,
                HdcCommand::ForwardData,
                &total,
                read_len,
                cid,
            )
            .await;
        }
    });
    true
}

#[cfg(not(feature = "host"))]
fn get_pid(parameter: &str, forward_type: ForwardType) -> u32 {
    match forward_type == ForwardType::Jdwp {
        true => parameter.parse::<u32>().unwrap_or_else(|e| {
            crate::error!("Jdwp get pid err :{:?}", e);
            0_u32
        }),
        false => {
            let params: Vec<&str> = parameter.split('@').collect();
            params[0].parse::<u32>().unwrap_or_else(|e| {
                crate::error!("get pid err :{:?}", e);
                0_u32
            })
        }
    }
}
#[cfg(feature = "host")]
pub async fn setup_jdwp_point(_session_id: u32, _channel_id: u32) -> bool {
    crate::info!("not daemon setup_jdwp_point");
    false
}

#[cfg(not(feature = "host"))]
pub async fn setup_jdwp_point(session_id: u32, channel_id: u32) -> bool {
    crate::info!("setup_jdwp_point start.");
    let Some(task): Option<HdcForward> = ForwardTaskMap::get(session_id, channel_id).await else {
        crate::error!(
            "setup_jdwp_point get task is none session_id={session_id},channel_id={channel_id}"
        );
        return false;
    };
    let task = &mut task.clone();
    let local_args = task.local_args[1].clone();
    let parameter = local_args.as_str();
    let style = &task.forward_type;
    let pid = get_pid(parameter, style.clone());
    let cid = task.context_forward.id;
    if pid == 0 {
        crate::error!("setup_jdwp_point get pid is 0");
        return false;
    }

    let result = UdsServer::wrap_socketpair(SOCK_STREAM);
    if result.is_err() {
        crate::error!("wrap socketpair failed");
        return false;
    }
    let mut target_fd = 0;
    let mut local_fd = 0;
    if let Ok((fd0, fd1)) = result {
        crate::info!("pipe, fd0:{}, fd1:{}", fd0, fd1);
        local_fd = fd0;
        target_fd = fd1;
        task.context_forward.fd = local_fd;
        task.context_forward.target_fd = target_fd;
        ForwardTaskMap::update(session_id, channel_id, task.clone()).await;
        target_fd = fd1;
    }

    utils::spawn(async move {
        loop {
            let result = ylong_runtime::spawn_blocking(move || {
                let mut buffer = [0u8; 1024];
                let size = UdsServer::wrap_read(local_fd, &mut buffer);
                (size, buffer)
            }).await;
            let (size, buffer) = match result {
                Ok((size, _)) if size < 0 => {
                    crate::error!("disconnect fd:({local_fd}, {target_fd}), error:{:?}", size);
                    free_context(session_id, channel_id, 0, true).await;
                    break;
                },
                Ok((0, _)) => {
                    ylong_runtime::time::sleep(Duration::from_millis(200)).await;
                    continue;
                },
                Ok((size, buffer)) => (size, buffer),
                Err(err) => {
                    crate::error!("{err}");
                    break;
                }
            };
            send_to_task(
                session_id,
                channel_id,
                HdcCommand::ForwardData,
                &buffer[0..size as usize],
                size as usize,
                cid,
            )
            .await;
        }
    });

    let jdwp = Jdwp::get_instance();
    let mut param = task.local_args[0].clone();
    param.push(':');
    param.push_str(parameter);

    let ret = jdwp.send_fd_to_target(pid, target_fd, local_fd, param.as_str()).await;
    if !ret {
        crate::error!("not found pid:{:?}", pid);
        echo_client(
            session_id,
            channel_id,
            format!("fport fail:pid not found:{}", pid).as_str(),
            MessageLevel::Fail,
        )
        .await;
        task_finish(session_id, channel_id).await;
        return false;
    }

    let vec_none = Vec::<u8>::new();
    send_to_task(
        session_id,
        channel_id,
        HdcCommand::ForwardActiveMaster, // 04
        &vec_none,
        0,
        cid,
    )
    .await;
    crate::info!("setup_jdwp_point return true");
    true
}

async fn echo_client(_session_id: u32, channel_id: u32, message: &str, _level: MessageLevel) {
    #[cfg(feature = "host")]
    {
        let level = match _level {
            MessageLevel::Ok => transfer::EchoLevel::OK,
            MessageLevel::Fail => transfer::EchoLevel::FAIL,
            MessageLevel::Info => transfer::EchoLevel::INFO,
        };
        let _ =
            transfer::send_channel_msg(channel_id, level, message.to_string())
                .await;
        return;
    }
    #[allow(unreachable_code)]
    {
        hdctransfer::echo_client(_session_id, channel_id, message.as_bytes().to_vec(), _level)
            .await;
    }
}

async fn task_finish(session_id: u32, channel_id: u32) {
    transfer_task_finish(channel_id, session_id).await;
}

#[cfg(not(target_os = "windows"))]
pub async fn daemon_connect_pipe(session_id: u32, channel_id: u32, fd: i32, path: String) {
    let name: Vec<u8> = path.as_bytes().to_vec();
    let mut socket_name = vec![0_u8; name.len() + 1];
    socket_name[0] = b'\0';
    name.iter().enumerate().for_each(|(i, e)| {
        socket_name[i + 1] = *e;
    });
    let addr = UdsAddr::parse_abstract(&socket_name[1..]);
    if let Ok(addr_obj) = &addr {
        let ret: Result<(), Error> = UdsClient::wrap_connect(fd, addr_obj);
        if ret.is_err() {
            echo_client(
                session_id,
                channel_id,
                "localabstract connect fail",
                MessageLevel::Fail,
            )
            .await;
            free_context(session_id, channel_id, 0, true).await;
            return;
        }
        send_active_master(session_id, channel_id).await;
        read_data_to_forward(session_id, channel_id).await;
    }
}

#[cfg(target_os = "windows")]
pub async fn setup_file_point(_session_id: u32, _channel_id: u32) -> bool {
    false
}

#[cfg(not(target_os = "windows"))]
pub async fn setup_file_point(session_id: u32, channel_id: u32) -> bool {
    let Some(task) = ForwardTaskMap::get(session_id, channel_id).await else {
        crate::error!(
            "setup_file_point get task is none session_id={session_id},channel_id={channel_id}"
        );
        return false;
    };
    let task = &mut task.clone();
    let s_node_cfg = task.local_args[1].clone();
    if task.is_master {
        if task.forward_type == ForwardType::Reserved
            || task.forward_type == ForwardType::FileSystem
        {
            let _ = fs::remove_file(s_node_cfg.clone());
        }
        if !server_socket_bind_listen(session_id, channel_id, s_node_cfg, task.context_forward.id)
            .await
        {
            crate::error!(
                "server socket bind listen failed channel_id={:?}",
                channel_id
            );
            task_finish(session_id, channel_id).await;
            return false;
        }
    } else if task.forward_type == ForwardType::Abstract {
        let fd: i32 = UdsClient::wrap_socket(AF_LOCAL);
        unsafe {
            libc::fcntl(fd, F_SETFD, FD_CLOEXEC);
        }
        task.context_forward.fd = fd;
        ForwardTaskMap::update(session_id, channel_id, task.clone()).await;
        daemon_connect_pipe(session_id, channel_id, fd, s_node_cfg).await;
    } else {
        let fd: i32 = UdsClient::wrap_socket(AF_UNIX);
        task.context_forward.fd = fd;
        ForwardTaskMap::update(session_id, channel_id, task.clone()).await;
        daemon_connect_pipe(session_id, channel_id, fd, s_node_cfg).await;
    }
    ForwardTaskMap::update(session_id, channel_id, task.clone()).await;
    true
}

pub async fn setup_point(session_id: u32, channel_id: u32) -> bool {
    if !detech_forward_type(session_id, channel_id).await {
        crate::error!("forward type is not true");
        return false;
    }
    let Some(task) = ForwardTaskMap::get(session_id, channel_id).await else {
        crate::error!(
            "setup_point get task is none session_id={session_id},channel_id={channel_id}"
        );
        return false;
    };
    let task = &mut task.clone();
    if cfg!(target_os = "windows") && task.forward_type != ForwardType::Tcp {
        task.context_forward.last_error = String::from("Not support forward-type");
        ForwardTaskMap::update(session_id, channel_id, task.clone()).await;
        return false;
    }
    ForwardTaskMap::update(session_id, channel_id, task.clone()).await;
    let mut ret = false;
    crate::info!("setup_point forward type:{:#?}", task.forward_type);
    match task.forward_type {
        ForwardType::Tcp => {
            ret = setup_tcp_point(session_id, channel_id).await;
        }
        ForwardType::Device => {
            if !cfg!(target_os = "windows") {
                ret = setup_device_point(session_id, channel_id).await;
            }
        }
        ForwardType::Jdwp | ForwardType::Ark => {
            crate::info!("setup_point ark case");
            if !cfg!(feature = "host") {
                ret = setup_jdwp_point(session_id, channel_id).await;
            }
        }
        ForwardType::Abstract | ForwardType::FileSystem | ForwardType::Reserved => {
            if !cfg!(target_os = "windows") {
                ret = setup_file_point(session_id, channel_id).await;
            }
        }
    };
    crate::info!("setup_point, ret:{ret}");
    ret
}

pub async fn send_to_task(
    session_id: u32,
    channel_id: u32,
    command: HdcCommand,
    buf_ptr: &[u8],
    buf_size: usize,
    cid: u32,
) -> bool {
    if buf_size > (config::MAX_SIZE_IOBUF * 2) {
        crate::error!("send task buf_size oversize");
        return false;
    }

    let mut new_buf = [u32::to_be_bytes(cid).as_slice(), buf_ptr].concat();
    new_buf[4..].copy_from_slice(&buf_ptr[0..buf_size]);
    let file_check_message = TaskMessage {
        channel_id,
        command,
        payload: new_buf,
    };
    transfer::put(session_id, file_check_message).await;
    true
}

pub async fn filter_command(_payload: &[u8]) -> io::Result<(String, u32)> {
    let bytes = &_payload[4..];
    let ct: Result<String, std::string::FromUtf8Error> = String::from_utf8(bytes.to_vec());
    if let Ok(content) = ct {
        let mut id_bytes = [0u8; 4];
        id_bytes.copy_from_slice(&_payload[0..4]);
        let id: u32 = u32::from_be_bytes(id_bytes);
        return Ok((content, id));
    }
    Err(Error::new(ErrorKind::Other, "filter command failure"))
}

pub async fn send_active_master(session_id: u32, channel_id: u32) -> bool {
    let Some(task) = ForwardTaskMap::get(session_id, channel_id).await else {
        crate::error!(
            "send_active_master get task is none session_id={session_id},channel_id={channel_id}"
        );
        return false;
    };
    let task = &mut task.clone();
    if task.context_forward.check_order {
        let flag = [0u8; 1];
        send_to_task(
            session_id,
            channel_id,
            HdcCommand::ForwardCheckResult,
            &flag,
            1,
            task.context_forward.id,
        )
        .await;
        free_context(session_id, channel_id, 0, false).await;
        ForwardTaskMap::update(session_id, channel_id, task.clone()).await;
        return true;
    }
    if !send_to_task(
        session_id,
        channel_id,
        HdcCommand::ForwardActiveMaster,
        &Vec::<u8>::new(),
        0,
        task.context_forward.id,
    )
    .await
    {
        free_context(session_id, channel_id, 0, true).await;
        ForwardTaskMap::update(session_id, channel_id, task.clone()).await;
        return false;
    }
    true
}

pub async fn begin_forward(session_id: u32, channel_id: u32, _payload: &[u8]) -> bool {
    let Ok(command) = String::from_utf8(_payload.to_vec()) else {
        crate::error!("cmd argv  is not int utf8");
        return false;
    };
    crate::info!("begin forward, command: {:?}", command);
    let Some(task) = ForwardTaskMap::get(session_id, channel_id).await else {
        crate::error!("begin forward get task is none");
        return false;
    };
    let task = &mut task.clone();
    task.task_command = command.clone();
    let result = Base::split_command_to_args(&command);
    let argv = result.0;
    let argc = result.1;
    task.context_forward.id = get_id(_payload);
    task.is_master = true;

    if argc < ARG_COUNT2 {
        crate::error!("argc < 2 parse is failed.");
        task.context_forward.last_error = "Too few arguments.".to_string();
        ForwardTaskMap::update(session_id, channel_id, task.clone()).await;
        return false;
    }
    if argv[0].len() > BUF_SIZE_SMALL || argv[1].len() > BUF_SIZE_SMALL {
        crate::error!("parse's length is flase.");
        task.context_forward.last_error = "Some argument too long.".to_string();
        ForwardTaskMap::update(session_id, channel_id, task.clone()).await;
        return false;
    }
    if !check_node_info(&argv[0], &mut task.local_args).await {
        crate::error!("check argv[0] node info is flase.");
        task.context_forward.last_error = "Arguments parsing failed.".to_string();
        ForwardTaskMap::update(session_id, channel_id, task.clone()).await;
        return false;
    }
    if !check_node_info(&argv[1], &mut task.remote_args).await {
        crate::error!("check argv[1] node info is flase.");
        task.context_forward.last_error = "Arguments parsing failed.".to_string();
        ForwardTaskMap::update(session_id, channel_id, task.clone()).await;
        return false;
    }
    task.remote_parameters = argv[1].clone();
    ForwardTaskMap::update(session_id, channel_id, task.clone()).await;
    if !setup_point(session_id, channel_id).await {
        crate::error!("setup point return false");
        return false;
    }

    let Some(task) = ForwardTaskMap::get(session_id, channel_id).await else {
        crate::error!("begin forward get task is none");
        return false;
    };
    let task = &mut task.clone();
    task.map_ctx_point
        .insert(task.context_forward.id, task.context_forward.clone());

    let wake_up_message = TaskMessage {
        channel_id,
        command: HdcCommand::KernelWakeupSlavetask,
        payload: Vec::<u8>::new(),
    };
    transfer::put(session_id, wake_up_message).await;

    let buf_string: Vec<u8> = argv[1].as_bytes().to_vec();
    let mut new_buf = vec![0_u8; buf_string.len() + 9];
    buf_string.iter().enumerate().for_each(|(i, e)| {
        new_buf[i + 8] = *e;
    });
    send_to_task(
        session_id,
        channel_id,
        HdcCommand::ForwardCheck,
        &new_buf,
        buf_string.len() + 9,
        task.context_forward.id,
    )
    .await;
    ForwardTaskMap::update(session_id, channel_id, task.clone()).await;
    true
}

pub async fn slave_connect(
    session_id: u32,
    channel_id: u32,
    _payload: &[u8],
    check_order: bool,
) -> bool {
    let Some(task) = ForwardTaskMap::get(session_id, channel_id).await else {
        crate::error!(
            "slave_connect get task is none session_id={session_id},channel_id={channel_id}"
        );
        return false;
    };
    let task = &mut task.clone();
    task.is_master = false;
    task.context_forward.check_order = check_order;
    if let Ok((content, id)) = filter_command(_payload).await {
        let content = &content[8..].trim_end_matches('\0').to_string();
        task.task_command = content.clone();
        if !check_node_info(content, &mut task.local_args).await {
            crate::error!("check local args is false");
            return false;
        }
        task.context_forward.id = id;
    }
    task.map_ctx_point
        .insert(task.context_forward.id, task.context_forward.clone());
    ForwardTaskMap::update(session_id, channel_id, task.clone()).await;
    if !check_order {
        if !setup_point(session_id, channel_id).await {
            crate::error!("setup point return false, free context");
            free_context(session_id, channel_id, 0, true).await;
            return false;
        }
    } else {
        send_active_master(session_id, channel_id).await;
    }
    true
}

pub async fn read_data_to_forward(session_id: u32, channel_id: u32) -> bool {
    let Some(mut task) = ForwardTaskMap::get(session_id, channel_id).await else {
        crate::error!(
            "read_data_to_forward get task is none session_id={session_id},channel_id={channel_id}"
        );
        return false;
    };
    let task = &mut task;
    let cid = task.context_forward.id;
    match task.forward_type {
        ForwardType::Tcp | ForwardType::Jdwp | ForwardType::Ark => {
            utils::spawn(async move {
                TcpReadStreamMap::read(session_id, channel_id, cid).await
            });
        }
        ForwardType::Abstract | ForwardType::FileSystem | ForwardType::Reserved => {
            let _fd = task.context_forward.fd;
            #[cfg(not(target_os = "windows"))]
            utils::spawn(async move {
                deamon_read_socket_msg(session_id, channel_id, _fd).await
            });
        }
        ForwardType::Device =>
        {
            #[cfg(not(target_os = "windows"))]
            if !setup_device_point(session_id, channel_id).await {
                return false;
            }
        }
    }
    true
}

pub async fn write_forward_bufer(
    session_id: u32,
    channel_id: u32,
    _id: u32,
    content: Vec<u8>,
) -> bool {
    let Some(mut task) = ForwardTaskMap::get(session_id, channel_id).await else {
        crate::error!(
            "write_forward_bufer get task is none session_id={session_id},channel_id={channel_id}"
        );
        return false;
    };
    let task = &mut task;
    if task.forward_type == ForwardType::Tcp {
        TcpWriteStreamMap::write(channel_id, content).await;
    } else {
        #[cfg(not(target_os = "windows"))]
        {
            let fd = task.context_forward.fd;
            UdsClient::wrap_send(fd, &content);
        }
    }
    true
}

pub async fn forward_command_dispatch(
    session_id: u32,
    channel_id: u32,
    command: HdcCommand,
    _payload: &[u8],
) -> bool {
    let Some(task) = ForwardTaskMap::get(session_id, channel_id).await else {
        crate::error!("forward_command_dispatch get task is none session_id={session_id},channel_id={channel_id}"
        );
        return false;
    };
    let task: &mut HdcForward = &mut task.clone();
    let mut ret: bool = true;
    if let Ok((_content, id)) = filter_command(_payload).await {
        task.context_forward.id = id;
    }
    let send_msg = _payload[4..].to_vec();
    ForwardTaskMap::update(session_id, channel_id, task.clone()).await;
    match command {
        HdcCommand::ForwardCheckResult => {
            ret = check_command(session_id, channel_id, _payload).await;
        }
        HdcCommand::ForwardData => {
            ret = write_forward_bufer(session_id, channel_id, task.context_forward.id, send_msg)
                .await;
        }
        HdcCommand::ForwardFreeContext => {
            free_context(session_id, channel_id, 0, false).await;
        }
        HdcCommand::ForwardActiveMaster => {
            ret = true;
        }
        _ => {
            ret = false;
        }
    }
    ForwardTaskMap::update(session_id, channel_id, task.clone()).await;
    ret
}

async fn get_last_error(session_id: u32, channel_id: u32) -> io::Result<String> {
    let Some(task) = ForwardTaskMap::get(session_id, channel_id).await else {
        return Err(Error::new(ErrorKind::Other, "task not found."));
    };
    Ok(task.context_forward.last_error)
}

async fn print_error_info(session_id: u32, channel_id: u32) {
    if let Ok(error) = get_last_error(session_id, channel_id).await {
        echo_client(
            session_id,
            channel_id,
            error.as_str(),
            MessageLevel::Fail,
        )
        .await;
    }
}

pub async fn command_dispatch(
    session_id: u32,
    channel_id: u32,
    _command: HdcCommand,
    _payload: &[u8],
    _payload_size: u16,
) -> bool {
    crate::info!("command_dispatch command recv: {:?}", _command);
    let ret = match _command {
        HdcCommand::ForwardInit => begin_forward(session_id, channel_id, _payload).await,
        HdcCommand::ForwardCheck => {
            slave_connect(session_id, channel_id, _payload, true).await
        }
        HdcCommand::ForwardActiveSlave => {
            slave_connect(session_id, channel_id, _payload, false).await
        }
        _ => forward_command_dispatch(session_id, channel_id, _command, _payload).await,
    };
    crate::info!("command dispatch ret: {:?}", ret);
    if !ret {
        print_error_info(session_id, channel_id).await;
        task_finish(session_id, channel_id).await;
        return false;
    }
    ret
}
