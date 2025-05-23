use bitcoin::{Transaction, Witness};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use anyhow::{Result, anyhow};
use warp::{Filter, fs::dir, ws::{Message, Ws}};
use std::convert::Infallible;
use webbrowser;
use tokio::{time::{sleep, Duration}, sync::broadcast};
use base64;

#[derive(Debug, Serialize, Deserialize)]
struct ApiResponse { result: String }

#[derive(Debug)]
pub struct InscriptionDecoder { api_base_url: String }

#[derive(Debug, Clone)]
pub struct InscriptionData { pub content_type: String, pub content: Vec<u8>, pub content_length: Option<usize> }

impl InscriptionDecoder {
    pub fn new() -> Self {
        Self { api_base_url: "https://mempool.space/api".to_string() }
    }

    pub async fn fetch_transaction_hex(&self, txid: &str) -> Result<String> {
        let url = format!("{}/tx/{}/hex", self.api_base_url, txid);
        let response = reqwest::get(&url).await?.text().await?;
        if response.starts_with("Transaction not found") {
            return Err(anyhow!("Transaction not found: {}", txid));
        }
        Ok(response)
    }

    pub fn parse_transaction(&self, hex_str: &str) -> Result<Transaction> {
        let tx_bytes = hex::decode(hex_str.trim())?;
        let tx: Transaction = bitcoin::consensus::deserialize(&tx_bytes)?;
        Ok(tx)
    }

    pub fn extract_witness_data(&self, tx: &Transaction) -> Vec<Witness> {
        tx.input.iter().map(|i| i.witness.clone()).collect()
    }

    pub async fn decode_inscription(&self, txid: &str) -> Result<Option<InscriptionData>> {
        let hex = self.fetch_transaction_hex(txid).await?;
        let tx = self.parse_transaction(&hex)?;
        for w in self.extract_witness_data(&tx) {
            if let Some(ins) = self.parse_witness_for_inscription(&w)? {
                return Ok(Some(ins));
            }
        }
        Ok(None)
    }

    fn parse_witness_for_inscription(&self, w: &Witness) -> Result<Option<InscriptionData>> {
        for item in w.iter() {
            if item.len() > 10 {
                if let Some(ins) = self.parse_script_for_inscription(item)? {
                    return Ok(Some(ins));
                }
            }
        }
        Ok(None)
    }

    fn parse_script_for_inscription(&self, s: &[u8]) -> Result<Option<InscriptionData>> {
        let mut i = 0;
        while i + 6 < s.len() {
            if &s[i..i+6] == [0x00,0x63,0x03,0x6f,0x72,0x64] {
                i += 6;
                for _ in 0..2 { if i < s.len() && s[i]==0x01 { i+=1; } }
                let mut ct = String::new();
                if let Some(data) = self.parse_push_data(s, &mut i)? { ct = String::from_utf8_lossy(&data).into(); }
                while i<s.len() && s[i]!=0x00 { i+=1; }
                if i<s.len() && s[i]==0x00 { i+=1; }
                let mut content = Vec::new();
                while i<s.len() {
                    if s[i]==0x68 { break; }
                    if let Some(d) = self.parse_push_data(s, &mut i)? { content.extend(d); } else { i+=1; }
                }
                if !ct.is_empty() && !content.is_empty() {
                    let length = content.len();
                    return Ok(Some(InscriptionData { content_type: ct, content, content_length: Some(length) }));
                }
            }
            i += 1;
        }
        Ok(None)
    }

    fn parse_push_data(&self, s: &[u8], idx: &mut usize) -> Result<Option<Vec<u8>>> {
        if *idx>=s.len() { return Ok(None); }
        let op = s[*idx]; *idx+=1;
        let len = match op {
            1..=75 => op as usize,
            0x4c if *idx<s.len()=>{ let l=s[*idx] as usize; *idx+=1; l }
            0x4d if *idx+1<s.len()=>{ let l=u16::from_le_bytes([s[*idx],s[*idx+1]]) as usize; *idx+=2; l }
            0x4e if *idx+3<s.len()=>{ let l=u32::from_le_bytes([s[*idx],s[*idx+1],s[*idx+2],s[*idx+3]]) as usize; *idx+=4; l }
            _=>return Ok(None)
        };
        if *idx + len > s.len() { return Ok(None); }
        let data = s[*idx..*idx+len].to_vec(); *idx+=len;
        Ok(Some(data))
    }
}

async fn get_inscription_api(txid: String) -> Result<impl warp::Reply, Infallible> {
    let dec = InscriptionDecoder::new();
    match dec.decode_inscription(&txid).await {
        Ok(Some(ins)) => {
            let b = base64::encode(&ins.content);
            let url = format!("data:{};base64,{}", ins.content_type, b);
            Ok(warp::reply::json(&serde_json::json!({"success":true,"content_type":ins.content_type,"content_length":ins.content_length,"data_url":url})))
        }
        Ok(None) => Ok(warp::reply::json(&serde_json::json!({"success":false,"error":"No inscription"}))),
        Err(e) => Ok(warp::reply::json(&serde_json::json!({"success":false,"error":format!("{}",e)})))
    }
}

#[derive(Deserialize)]
struct BlockInfo { id: String }

fn with_broadcast(tx: broadcast::Sender<String>) -> impl Filter<Extract=(broadcast::Sender<String>,),Error=Infallible>+Clone {
    warp::any().map(move||tx.clone())
}

async fn client_connection(ws: warp::ws::WebSocket, tx: broadcast::Sender<String>) {
    let mut rx = tx.subscribe();
    let (mut tx_ws, _) = ws.split();
    while let Ok(msg) = rx.recv().await {
        if tx_ws.send(Message::text(msg)).await.is_err() { break; }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let (tx, _) = broadcast::channel(100);
    let api = warp::path("api").and(warp::path("inscription")).and(warp::path::param()).and_then(get_inscription_api);
    let ws_rt = warp::path("ws").and(warp::ws()).and(with_broadcast(tx.clone()))
        .map(|ws: Ws, tx| ws.on_upgrade(move |sock| client_connection(sock, tx)));
    let index = warp::path::end().map(|| warp::reply::with_header(include_str!("../static/homepage.html"),"content-type","text/html; charset=utf-8"));
    let static_files = dir("static");
    let routes = api.or(ws_rt).or(index).or(static_files);
    println!("Server on http://localhost:3030");
    tokio::spawn(async move {
        sleep(Duration::from_millis(500)).await;
        let _ = webbrowser::open("http://localhost:3030");
    });
    tokio::spawn(async move {
        let dec = InscriptionDecoder::new();
        loop {
            // fetch last 3 blocks
            if let Ok(r) = reqwest::get("https://mempool.space/api/blocks").await {
                if let Ok(blocks) = r.json::<Vec<BlockInfo>>().await {
                    for blk in blocks.iter().take(3) {
                        // send block separator
                        let _ = tx.send("----".to_string());
                        // fetch txids for block
                        if let Ok(r2) = reqwest::get(&format!("https://mempool.space/api/block/{}/txids", blk.id)).await {
                            if let Ok(ids) = r2.json::<Vec<String>>().await {
                                for txid in ids.iter() {
                                    if let Ok(Some(_)) = dec.decode_inscription(txid).await {
                                        let _ = tx.send(txid.clone());
                                    }
                                }
                            }
                        }
                    }
                }
            }
            sleep(Duration::from_secs(60)).await;
        }
    });
    warp::serve(routes).run(([127, 0, 0, 1], 3030)).await;
    Ok(())
}