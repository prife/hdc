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
//! buffer
#![allow(missing_docs)]

use super::base::{self, Writer};
use super::uart::UartWriter;
use super::usb::{self, UsbReader, UsbWriter};
use super::{tcp, uart_wrapper};

use crate::config::TaskMessage;
use crate::config::{self, ConnectType};
use crate::serializer;
#[allow(unused)]
use crate::utils::hdc_log::*;

use std::collections::HashMap;
use std::io::{self, Error, ErrorKind};
use std::sync::Arc;

use ylong_runtime::io::AsyncWriteExt;
use ylong_runtime::net::{SplitReadHalf, SplitWriteHalf};
use ylong_runtime::sync::{mpsc, Mutex, RwLock};

type ConnectTypeMap_ = Arc<RwLock<HashMap<u32, ConnectType>>>;

struct ConnectTypeMap {}
impl ConnectTypeMap {
    fn get_instance() -> ConnectTypeMap_ {
        static mut CONNECT_TYPE_MAP: Option<ConnectTypeMap_> = None;
        unsafe {
            CONNECT_TYPE_MAP
                .get_or_insert_with(|| Arc::new(RwLock::new(HashMap::new())))
                .clone()
        }
    }

    async fn put(session_id: u32, conn_type: ConnectType) {
        let arc_map = Self::get_instance();
        let mut map = arc_map.write().await;
        map.insert(session_id, conn_type);
    }

    async fn get(session_id: u32) -> ConnectType {
        let arc_map = Self::get_instance();
        let map = arc_map.read().await;
        map.get(&session_id).unwrap().clone()
    }
}

type TcpWriter_ = Arc<Mutex<SplitWriteHalf>>;
type TcpMap_ = Arc<RwLock<HashMap<u32, TcpWriter_>>>;

pub struct TcpMap {}
impl TcpMap {
    fn get_instance() -> TcpMap_ {
        static mut TCP_MAP: Option<TcpMap_> = None;
        unsafe {
            TCP_MAP
                .get_or_insert_with(|| Arc::new(RwLock::new(HashMap::new())))
                .clone()
        }
    }

    async fn put(session_id: u32, data: TaskMessage) {
        let send = serializer::concat_pack(data);
        let instance = Self::get_instance();
        let map = instance.read().await;
        let arc_wr = map.get(&session_id).unwrap();
        let mut wr = arc_wr.lock().await;
        let _ = wr.write_all(send.as_slice()).await;
    }

    pub async fn send_channel_message(channel_id: u32, buf: Vec<u8>) -> io::Result<()> {
        crate::trace!("send channel msg: {:#?}", buf.clone());
        let send = [
            u32::to_be_bytes(buf.len() as u32).as_slice(),
            buf.as_slice(),
        ]
        .concat();
        let instance = Self::get_instance();
        let map = instance.read().await;
        if let Some(guard) = map.get(&channel_id) {
            let mut wr = guard.lock().await;
            let _ = wr.write_all(send.as_slice()).await;
            return Ok(());
        }
        Err(Error::new(ErrorKind::NotFound, "channel not found"))
    }

    pub async fn start(id: u32, wr: SplitWriteHalf) {
        let instance = Self::get_instance();
        let mut map = instance.write().await;
        let arc_wr = Arc::new(Mutex::new(wr));
        map.insert(id, arc_wr);
        ConnectTypeMap::put(id, ConnectType::Tcp).await;
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

type UsbWriter_ = Arc<Mutex<UsbWriter>>;
type UsbMap_ = Arc<RwLock<HashMap<u32, UsbWriter_>>>;

pub struct UsbMap {}
impl UsbMap {
    fn get_instance() -> UsbMap_ {
        static mut USB_MAP: Option<UsbMap_> = None;
        unsafe {
            USB_MAP
                .get_or_insert_with(|| Arc::new(RwLock::new(HashMap::new())))
                .clone()
        }
    }

    #[allow(unused)]
    async fn put(session_id: u32, data: TaskMessage) -> io::Result<()> {
        let body = serializer::concat_pack(data);
        let head = usb::build_header(session_id, 1, body.len());
        let tail = usb::build_header(session_id, 0, 0);

        let instance = Self::get_instance();
        let map = instance.read().await;
        let arc_wr = map.get(&session_id).unwrap();
        let mut wr = arc_wr.lock().await;
        wr.write_all(head)?;
        wr.write_all(body)?;
        wr.write_all(tail)?;
        Ok(())
    }

    pub async fn start(session_id: u32, wr: UsbWriter) {
        let buffer_map = Self::get_instance();
        let mut map = buffer_map.write().await;
        let arc_wr = Arc::new(Mutex::new(wr));
        map.insert(session_id, arc_wr);
        ConnectTypeMap::put(session_id, ConnectType::Usb("some_mount_point".to_string())).await;
    }
}

type UartWriter_ = Arc<Mutex<UartWriter>>;
type UartMap_ = Arc<RwLock<HashMap<u32, UartWriter_>>>;

pub struct UartMap {}
impl UartMap {
    fn get_instance() -> UartMap_ {
        static mut UART_MAP: Option<UartMap_> = None;
        unsafe {
            UART_MAP
                .get_or_insert_with(|| Arc::new(RwLock::new(HashMap::new())))
                .clone()
        }
    }

    #[allow(unused)]
    pub async fn put(session_id: u32, data: Vec<u8>) -> io::Result<()> {
        let instance = Self::get_instance();
        let map = instance.read().await;
        let arc_wr = map.get(&session_id).unwrap();
        let wr = arc_wr.lock().await;
        wr.write_all(data)?;
        Ok(())
    }

    pub async fn start(session_id: u32, wr: UartWriter) {
        let instance = Self::get_instance();
        let mut map = instance.write().await;
        let arc_wr = Arc::new(Mutex::new(wr));
        if map.contains_key(&session_id) {
            println!("uart start, contain session:{}", session_id);
            return;
        }
        map.insert(session_id, arc_wr);
        ConnectTypeMap::put(session_id, ConnectType::Uart).await;
    }
}

pub async fn put(session_id: u32, data: TaskMessage) {
    match ConnectTypeMap::get(session_id).await {
        ConnectType::Tcp => {
            TcpMap::put(session_id, data).await;
        }
        ConnectType::Usb(_mount_point) => {
            if let Err(e) = UsbMap::put(session_id, data).await {
                crate::error!("{e:?}");
            }
        }
        ConnectType::Uart => {
            uart_wrapper::wrap_put(session_id, data, 0, 0).await;
        }
        ConnectType::Bt => {}
    }
}

pub async fn send_channel_data(channel_id: u32, data: Vec<u8>) {
    let _ = TcpMap::send_channel_message(channel_id, data).await;
}

pub enum EchoLevel {
    INFO,
    FAIL,
    RAW,
}

pub async fn send_channel_msg(channel_id: u32, level: EchoLevel, msg: String) -> io::Result<()> {
    let data = match level {
        EchoLevel::INFO => format!("[Info]{msg}"),
        EchoLevel::FAIL => format!("[Fail]{msg}"),
        EchoLevel::RAW => msg.to_string(),
    } + "\r\n";
    TcpMap::send_channel_message(channel_id, data.as_bytes().to_vec()).await
}

// client recv and print msg
type TcpRecver_ = Arc<Mutex<SplitReadHalf>>;
type ChannelMap_ = Arc<RwLock<HashMap<u32, TcpRecver_>>>;

pub struct ChannelMap {}
impl ChannelMap {
    fn get_instance() -> ChannelMap_ {
        static mut TCP_RECVER: Option<ChannelMap_> = None;
        unsafe {
            TCP_RECVER
                .get_or_insert_with(|| Arc::new(RwLock::new(HashMap::new())))
                .clone()
        }
    }

    pub async fn start(rd: SplitReadHalf) {
        let instance = Self::get_instance();
        let mut map = instance.write().await;
        let arc_rd = Arc::new(Mutex::new(rd));
        map.insert(0, arc_rd);
    }

    pub async fn recv() -> io::Result<Vec<u8>> {
        let instance = Self::get_instance();
        let map = instance.read().await;
        let arc_rd = map.get(&0).unwrap();
        let mut rd = arc_rd.lock().await;
        tcp::recv_channel_message(&mut rd).await
    }
}

pub fn usb_start_recv(fd: i32, _session_id: u32) -> mpsc::BoundedReceiver<(TaskMessage, u32)> {
    let (tx, rx) = mpsc::bounded_channel::<(TaskMessage, u32)>(config::USB_QUEUE_LEN);
    ylong_runtime::spawn(async move {
        let mut rd = UsbReader { fd };
        loop {
            if let Err(e) = base::unpack_task_message(&mut rd, tx.clone()) {
                crate::warn!("unpack task failed: {}, reopen fd...", e.to_string());
                break;
            }
        }
    });
    rx
}
