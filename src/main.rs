use bitcoin::{Transaction, Witness};
use serde::{Deserialize, Serialize};
use anyhow::{Result, anyhow};
use warp::Filter;
use warp::fs::dir;
use std::convert::Infallible;
use webbrowser;
use tokio::time::{sleep, Duration};
use base64;

#[derive(Debug, Serialize, Deserialize)]
struct ApiResponse {
    result: String,
}

#[derive(Debug)]
pub struct InscriptionDecoder {
    api_base_url: String,
}

#[derive(Debug, Clone)]
pub struct InscriptionData {
    pub content_type: String,
    pub content: Vec<u8>,
    pub content_length: Option<usize>,
}

impl InscriptionDecoder {
    pub fn new() -> Self {
        Self {
            api_base_url: "https://mempool.space/api".to_string(),
        }
    }

    pub async fn fetch_transaction_hex(&self, txid: &str) -> Result<String> {
        let url = format!("{}/tx/{}/hex", self.api_base_url, txid);
        let response = reqwest::get(&url)
            .await?
            .text()
            .await?;
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
        tx.input.iter().map(|input| input.witness.clone()).collect()
    }

    pub async fn decode_inscription(&self, txid: &str) -> Result<Option<InscriptionData>> {
        println!("Fetching transaction: {}", txid);
        let hex_data = self.fetch_transaction_hex(txid).await?;
        println!("Retrieved {} bytes of transaction data", hex_data.len() / 2);

        let tx = self.parse_transaction(&hex_data)?;
        println!("Parsed transaction with {} inputs, {} outputs", tx.input.len(), tx.output.len());

        let witnesses = self.extract_witness_data(&tx);
        println!("Found {} witness stacks", witnesses.len());

        for (i, witness) in witnesses.iter().enumerate() {
            println!("Witness {}: {} items", i, witness.len());
            if let Some(inscription) = self.parse_witness_for_inscription(witness)? {
                println!("Found inscription in witness {}", i);
                return Ok(Some(inscription));
            }
        }

        println!("No inscription found in transaction");
        Ok(None)
    }

    fn parse_witness_for_inscription(&self, witness: &Witness) -> Result<Option<InscriptionData>> {
        for (i, item) in witness.iter().enumerate() {
            println!("  Witness item {}: {} bytes", i, item.len());
            if item.len() > 10 {
                let hex_preview = hex::encode(&item[..std::cmp::min(40, item.len())]);
                println!("    Preview: {}...", hex_preview);
                if let Some(inscription) = self.parse_script_for_inscription(item)? {
                    return Ok(Some(inscription));
                }
            }
        }
        Ok(None)
    }

    fn parse_script_for_inscription(&self, script_bytes: &[u8]) -> Result<Option<InscriptionData>> {
        let mut i = 0;
        let script_len = script_bytes.len();
        while i < script_len {
            if i + 6 < script_len &&
               script_bytes[i] == 0x00 &&
               script_bytes[i + 1] == 0x63 &&
               script_bytes[i + 2] == 0x03 &&
               script_bytes[i + 3..i + 6] == [0x6f, 0x72, 0x64] {
                println!("    Found inscription envelope at offset {}", i);
                i += 6;

                let mut content_type = String::new();
                let mut content = Vec::new();

                // Skip OP_1 OP_1
                if script_bytes[i] == 0x01 { i += 1; }
                if script_bytes[i] == 0x01 { i += 1; }

                if let Some(ct_data) = self.parse_push_data(&script_bytes, &mut i)? {
                    content_type = String::from_utf8_lossy(&ct_data).to_string();
                    println!("    Parsed content type: '{}'", content_type);
                }

                // Find OP_0
                while i < script_len && script_bytes[i] != 0x00 { i += 1; }
                if i < script_len && script_bytes[i] == 0x00 {
                    println!("    Found OP_0 at offset {}", i);
                    i += 1;
                    while i < script_len {
                        let opcode = script_bytes[i];
                        if opcode == 0x68 {
                            println!("    Found OP_ENDIF at offset {}", i);
                            break;
                        }
                        if let Some(data) = self.parse_push_data(&script_bytes, &mut i)? {
                            content.extend_from_slice(&data);
                        } else {
                            i += 1;
                        }
                    }
                }

                if !content_type.is_empty() && !content.is_empty() {
                    println!("    Successfully extracted inscription:");
                    println!("      Content type: {}", content_type);
                    println!("      Content size: {} bytes", content.len());
                    return Ok(Some(InscriptionData {
                        content_type,
                        content: content.clone(),
                        content_length: Some(content.len()),
                    }));
                }
            }
            i += 1;
        }
        Ok(None)
    }
    /// Parse push data operation from script

    fn parse_push_data(&self, script: &[u8], index: &mut usize) -> Result<Option<Vec<u8>>> {
        if *index >= script.len() {
            return Ok(None);
        }
        let opcode = script[*index];
        *index += 1;
        let data_len = match opcode {
            // Direct push of 1-75 bytes
            1..=75 => opcode as usize,
            // OP_PUSHDATA1: next byte is length

            0x4c if *index < script.len() => {
                let len = script[*index] as usize; *index += 1; len
            }
            0x4d if *index + 1 < script.len() => {
                let len = u16::from_le_bytes([script[*index], script[*index + 1]]) as usize;
                *index += 2; len
            }
            0x4e if *index + 3 < script.len() => {
                let len = u32::from_le_bytes([
                    script[*index], script[*index + 1],
                    script[*index + 2], script[*index + 3]
                ]) as usize;
                *index += 4; len
            }
            _ => return Ok(None),
        };
        // Extract the data

        if *index + data_len > script.len() {
            return Ok(None);
        }
        let data = script[*index..*index + data_len].to_vec();
        *index += data_len;
        Ok(Some(data))
    }

        /// Check if witness item contains inscription envelope markers
    fn contains_inscription_markers(&self, data: &[u8]) -> bool {
        let hex_str = hex::encode(data);
        hex_str.contains("6f7264") // "ord" in hex
    }
}

async fn get_inscription_api(txid: String) -> Result<impl warp::Reply, Infallible> {
    let decoder = InscriptionDecoder::new();
    match decoder.decode_inscription(&txid).await {
        Ok(Some(inscription)) => {
            let base64_content = base64::encode(&inscription.content);
            let data_url = format!("data:{};base64,{}", inscription.content_type, base64_content);
            let response = serde_json::json!({
                "success": true,
                "content_type": inscription.content_type,
                "content_length": inscription.content_length,
                "data_url": data_url
            });
            Ok(warp::reply::json(&response))
        }
        Ok(None) => {
            let response = serde_json::json!({
                "success": false,
                "error": "No inscription found in this transaction"
            });
            Ok(warp::reply::json(&response))
        }
        Err(e) => {
            let response = serde_json::json!({
                "success": false,
                "error": format!("Error processing transaction: {}", e)
            });
            Ok(warp::reply::json(&response))
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // API route
    let api = warp::path("api")
        .and(warp::path("inscription"))
        .and(warp::path::param())
        .and_then(get_inscription_api);

    // Serve the homepage at `/`
    let index = warp::path::end()
        .map(|| {
            let html = include_str!("../static/homepage.html");
            warp::reply::with_header(
                html,
                "content-type",
                "text/html; charset=utf-8"
            )
        });

    // Serve other static assets if you add them
    let static_files = dir("static");

    let routes = api.or(index).or(static_files);

    println!("Server starting on http://localhost:3030");

    // Open in default browser shortly after launch
    tokio::spawn(async {
        sleep(Duration::from_millis(500)).await;
        if let Err(e) = webbrowser::open("http://localhost:3030") {
            eprintln!("❌ could not open browser: {}", e);
        }
    });

    warp::serve(routes)
        .run(([127, 0, 0, 1], 3030))
        .await;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_fetch_transaction() {
        let decoder = InscriptionDecoder::new();
        let txid = "4b19c8b5c02051fa526a55c1a9ed0cf2bd9f172aa814ae45188f8638e2298423";
        let result = decoder.fetch_transaction_hex(txid).await;
        assert!(result.is_ok());
        let hex_data = result.unwrap();
        assert!(!hex_data.is_empty());
        assert!(hex_data.len() % 2 == 0);
    }

    #[test]
    fn test_inscription_marker_detection() {
        let decoder = InscriptionDecoder::new();
        let test_data = hex::decode("006a6f726451").unwrap();
        assert!(decoder.contains_inscription_markers(&test_data));
        let test_data = hex::decode("deadbeef").unwrap();
        assert!(!decoder.contains_inscription_markers(&test_data));
    }
}
