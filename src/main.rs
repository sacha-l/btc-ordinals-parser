use bitcoin::{Transaction, Witness};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use anyhow::{Result, anyhow};

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
            // Using mempool.space API as default
            api_base_url: "https://mempool.space/api".to_string(),
        }
    }

    /// Fetch raw transaction hex from blockchain API
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

    /// Parse hex string into Bitcoin transaction
    pub fn parse_transaction(&self, hex_str: &str) -> Result<Transaction> {
        let tx_bytes = hex::decode(hex_str.trim())?;
        let tx: Transaction = bitcoin::consensus::deserialize(&tx_bytes)?;
        Ok(tx)
    }

    /// Extract witness data from transaction inputs
    pub fn extract_witness_data(&self, tx: &Transaction) -> Vec<Witness> {
        tx.input
            .iter()
            .map(|input| input.witness.clone())
            .collect()
    }

    /// Main function to decode inscription from transaction ID
    pub async fn decode_inscription(&self, txid: &str) -> Result<Option<InscriptionData>> {
        println!("Fetching transaction: {}", txid);
        
        // Step 1: Fetch raw transaction
        let hex_data = self.fetch_transaction_hex(txid).await?;
        println!("Retrieved {} bytes of transaction data", hex_data.len() / 2);

        // Step 2: Parse transaction
        let tx = self.parse_transaction(&hex_data)?;
        println!("Parsed transaction with {} inputs, {} outputs", 
                tx.input.len(), tx.output.len());

        // Step 3: Extract witness data
        let witnesses = self.extract_witness_data(&tx);
        println!("Found {} witness stacks", witnesses.len());

        // Step 4: Look for inscription in witness data
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

    /// Parse witness data looking for inscription envelope
    fn parse_witness_for_inscription(&self, witness: &Witness) -> Result<Option<InscriptionData>> {
        for (i, item) in witness.iter().enumerate() {
            println!("  Witness item {}: {} bytes", i, item.len());
            
            if item.len() > 10 {
                let hex_preview = hex::encode(&item[..std::cmp::min(40, item.len())]);
                println!("    Preview: {}...", hex_preview);
                
                // Try to parse this witness item as a script containing an inscription
                if let Some(inscription) = self.parse_script_for_inscription(item)? {
                    return Ok(Some(inscription));
                }
            }
        }
        
        Ok(None)
    }

    /// Parse a script looking for inscription envelope pattern
    fn parse_script_for_inscription(&self, script_bytes: &[u8]) -> Result<Option<InscriptionData>> {
        let mut i = 0;
        let script_len = script_bytes.len();
        
        while i < script_len {
            // Look for inscription envelope: OP_FALSE OP_IF "ord"
            if i + 6 < script_len &&
               script_bytes[i] == 0x00 &&      // OP_FALSE
               script_bytes[i + 1] == 0x63 &&  // OP_IF
               script_bytes[i + 2] == 0x03 &&  // Push 3 bytes
               script_bytes[i + 3..i + 6] == [0x6f, 0x72, 0x64] { // "ord"
                
                println!("    Found inscription envelope at offset {}", i);
                
                // Move past the envelope start (OP_FALSE OP_IF "ord")
                i += 6;
                
                // Debug: show a larger chunk of data after "ord"
                if i + 50 < script_len {
                    let next_bytes = hex::encode(&script_bytes[i..i+50]);
                    println!("    Next 50 bytes after 'ord': {}", next_bytes);
                }
                
                // The inscription format is actually:
                // OP_FALSE OP_IF "ord" OP_1 <content-type> OP_0 <content> OP_ENDIF
                // But we need to handle the fact that content might be HUGE
                
                let mut content_type = String::new();
                let mut content = Vec::new();
                
                // The inscription format from the hex data shows:
                // After "ord": 01 01 09 696d6167652f706e67 00 4d08 02 89504e47...
                // This means: OP_1 OP_1 PUSH(9 bytes="image/png") OP_0 PUSH(content)...
                
                // Skip the first OP_1 and look for the actual content type
                if script_bytes[i] == 0x01 { // OP_1
                    i += 1;
                }
                if script_bytes[i] == 0x01 { // Another OP_1  
                    i += 1;
                }
                
                // Now parse the content type (should be next push data)
                if let Some(ct_data) = self.parse_push_data(&script_bytes, &mut i)? {
                    content_type = String::from_utf8_lossy(&ct_data).to_string();
                    println!("    Parsed content type: '{}'", content_type);
                } else {
                    println!("    Failed to parse content type");
                }
                
                // Look for OP_0 (content data marker)
                while i < script_len && script_bytes[i] != 0x00 {
                    i += 1;
                }
                
                if i < script_len && script_bytes[i] == 0x00 {
                    println!("    Found OP_0 at offset {}", i);
                    i += 1; // Skip OP_0
                    
                    // Parse ALL remaining data until we have enough or hit OP_ENDIF
                    while i < script_len {
                        let opcode = script_bytes[i];
                        
                        if opcode == 0x68 { // OP_ENDIF
                            println!("    Found OP_ENDIF at offset {}", i);
                            break;
                        }
                        
                        // Try to parse as push data
                        if let Some(data) = self.parse_push_data(&script_bytes, &mut i)? {
                            content.extend_from_slice(&data);
                            if content.len() % 10000 == 0 {
                                println!("    Content size now: {} bytes", content.len());
                            }
                        } else {
                            // If not push data, skip this byte
                            i += 1;
                        }
                    }
                }
                
                if !content_type.is_empty() && !content.is_empty() {
                    println!("    Successfully extracted inscription:");
                    println!("      Content type: {}", content_type);
                    println!("      Content size: {} bytes", content.len());
                    
                    // Verify it looks like valid image data
                    if content.len() > 100 {
                        let header_hex = hex::encode(&content[..16]);
                        println!("      Content header: {}", header_hex);
                    }
                    
                    return Ok(Some(InscriptionData {
                        content_type,
                        content: content.clone(),
                        content_length: Some(content.len()),
                    }));
                } else {
                    println!("    Failed to extract inscription:");
                    println!("      Content type: '{}'", content_type);
                    println!("      Content size: {} bytes", content.len());
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
            0x4c => {
                if *index >= script.len() {
                    return Ok(None);
                }
                let len = script[*index] as usize;
                *index += 1;
                len
            },
            // OP_PUSHDATA2: next 2 bytes are length (little endian)
            0x4d => {
                if *index + 1 >= script.len() {
                    return Ok(None);
                }
                let len = u16::from_le_bytes([script[*index], script[*index + 1]]) as usize;
                *index += 2;
                len
            },
            // OP_PUSHDATA4: next 4 bytes are length (little endian)
            0x4e => {
                if *index + 3 >= script.len() {
                    return Ok(None);
                }
                let len = u32::from_le_bytes([
                    script[*index], script[*index + 1], 
                    script[*index + 2], script[*index + 3]
                ]) as usize;
                *index += 4;
                len
            },
            _ => return Ok(None), // Not a push data operation
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
        // Look for the inscription envelope pattern:
        // OP_FALSE OP_IF "ord" OP_1 <content-type> OP_0 <content>
        
        // Convert to hex string for pattern matching
        let hex_str = hex::encode(data);
        
        // Look for common inscription patterns
        // "ord" in hex is 6f7264
        // OP_FALSE = 00, OP_IF = 63, OP_1 = 51, OP_0 = 00
        hex_str.contains("6f7264") // Contains "ord"
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let decoder = InscriptionDecoder::new();
    
    // Test with the provided transaction
    let txid = "4b19c8b5c02051fa526a55c1a9ed0cf2bd9f172aa814ae45188f8638e2298423";
    
        match decoder.decode_inscription(txid).await? {
            Some(inscription) => {
                println!("\n=== INSCRIPTION FOUND ===");
                println!("Content Type: {}", inscription.content_type);
                println!("Content Length: {:?}", inscription.content_length);
                println!("Data Size: {} bytes", inscription.content.len());
                
                // Save the content to a file based on content type
                if inscription.content_type.starts_with("image/") {
                    let extension = match inscription.content_type.as_str() {
                        "image/png" => "png",
                        "image/jpeg" => "jpg", 
                        "image/gif" => "gif",
                        "image/webp" => "webp",
                        "image/svg+xml" => "svg",
                        _ => "bin",
                    };
                    
                    let filename = format!("inscription_{}.{}", txid, extension);
                    std::fs::write(&filename, &inscription.content)?;
                    println!("Saved image to: {}", filename);
                } else {
                    // Save as binary file if not an image
                    let filename = format!("inscription_{}.bin", txid);
                    std::fs::write(&filename, &inscription.content)?;
                    println!("Saved content to: {}", filename);
                }
            }
            None => {
                println!("\n=== NO INSCRIPTION FOUND ===");
            }
        }

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
        assert!(hex_data.len() % 2 == 0); // Should be valid hex
    }

    #[test]
    fn test_inscription_marker_detection() {
        let decoder = InscriptionDecoder::new();
        
        // Test data containing "ord"
        let test_data = hex::decode("006a6f726451").unwrap(); // Contains "ord"
        assert!(decoder.contains_inscription_markers(&test_data));
        
        // Test data without inscription markers
        let test_data = hex::decode("deadbeef").unwrap();
        assert!(!decoder.contains_inscription_markers(&test_data));
    }
}