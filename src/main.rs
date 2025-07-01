use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, error, warn};
use tracing_subscriber;
use anyhow::Result;
use key_utils::Secp256k1PublicKey;
use roles_logic_sv2::common_messages_sv2::{Protocol, SetupConnection, SetupConnectionSuccess};
// Template distribution types - we'll parse manually for now
use binary_sv2::{to_bytes, from_bytes};
use noise_sv2::{Initiator, NoiseCodec};
use std::convert::TryInto;

const SV2_ADDR: &str = "127.0.0.1:8442";
const SERVER_PUBKEY: &str = "9beQjjVTzvXKTUsy9GfqReVZY54uFAvqFSLqso9mHZoSVKLU3fP";

const SETUP_CONNECTION_MSG_TYPE: u8 = 0x00;
const SETUP_CONNECTION_SUCCESS_MSG_TYPE: u8 = 0x01;
const COINBASE_OUTPUT_CONSTRAINTS_MSG_TYPE: u8 = 0x70;
const NEW_TEMPLATE_MSG_TYPE: u8 = 0x71;
const SET_NEW_PREV_HASH_MSG_TYPE: u8 = 0x72;
const REQUEST_TRANSACTION_DATA_MSG_TYPE: u8 = 0x73;

// Simple coinbase constraints structure
#[derive(Debug)]
struct CoinbaseOutputConstraints {
    max_additional_size: u32,
    max_additional_sigops: u16,
}

async fn send_sv2_message(
    stream: &mut TcpStream,
    noise_codec: &mut NoiseCodec,
    msg_type: u8,
    payload: Vec<u8>
) -> Result<()> {
    // Construct 6-byte header
    let mut header = Vec::new();
    header.extend_from_slice(&0u16.to_le_bytes());  // extension_type
    header.push(msg_type);                          // msg_type
    let length_bytes = (payload.len() as u32).to_le_bytes();
    header.extend_from_slice(&length_bytes[..3]);   // length (3 bytes)

    // Encrypt header and payload separately
    let mut encrypted_header = header.clone();
    noise_codec.encrypt(&mut encrypted_header)
        .map_err(|e| anyhow::anyhow!("Header encryption failed: {:?}", e))?;
    
    let mut encrypted_payload = payload.clone();
    noise_codec.encrypt(&mut encrypted_payload)
        .map_err(|e| anyhow::anyhow!("Payload encryption failed: {:?}", e))?;

    // Send complete frame
    let mut sv2_frame = Vec::new();
    sv2_frame.extend_from_slice(&encrypted_header);
    sv2_frame.extend_from_slice(&encrypted_payload);
    
    stream.write_all(&sv2_frame).await?;
    info!("📤 Sent message type 0x{:02x} ({} bytes)", msg_type, sv2_frame.len());
    
    Ok(())
}

async fn establish_encrypted_connection_and_setup() -> Result<()> {
    info!("🔌 Connecting to SV2 Template Provider at {}", SV2_ADDR);
    let mut stream = TcpStream::connect(SV2_ADDR).await?;
    info!("✅ Connected to template provider.");

    let server_pubkey: Secp256k1PublicKey = SERVER_PUBKEY.parse()?;
    info!("🔑 Using server public key: {}", SERVER_PUBKEY);

    let mut initiator = Initiator::new(Some(server_pubkey.0));
    info!("🤝 Created Noise handshake initiator");

    // Noise handshake
    let first_message = initiator.step_0()
        .map_err(|e| anyhow::anyhow!("Handshake step 0 failed: {:?}", e))?;
    stream.write_all(&first_message).await?;
    info!("✅ Sent handshake step 1 ({} bytes)", first_message.len());

    let mut response_buf = [0u8; 234];
    stream.read_exact(&mut response_buf).await?;
    info!("✅ Received handshake step 2 (234 bytes)");

    let mut noise_codec = initiator.step_2(response_buf)
        .map_err(|e| anyhow::anyhow!("Handshake step 2 failed: {:?}", e))?;
    info!("🎉 Noise handshake completed successfully!");

    // Send SetupConnection
    let setup_connection = SetupConnection {
        protocol: Protocol::TemplateDistributionProtocol,
        min_version: 2,
        max_version: 2,
        flags: 0,
        endpoint_host: "127.0.0.1".to_string().into_bytes().try_into()
            .map_err(|e| anyhow::anyhow!("Failed to convert host: {:?}", e))?,
        endpoint_port: 8442,
        vendor: "SV2-Viewer".to_string().into_bytes().try_into()
            .map_err(|e| anyhow::anyhow!("Failed to convert vendor: {:?}", e))?,
        hardware_version: "1.0".to_string().into_bytes().try_into()
            .map_err(|e| anyhow::anyhow!("Failed to convert hw_version: {:?}", e))?,
        firmware: "0.1.0".to_string().into_bytes().try_into()
            .map_err(|e| anyhow::anyhow!("Failed to convert firmware: {:?}", e))?,
        device_id: "viewer-001".to_string().into_bytes().try_into()
            .map_err(|e| anyhow::anyhow!("Failed to convert device_id: {:?}", e))?,
    };

    let setup_payload = to_bytes(setup_connection)
        .map_err(|e| anyhow::anyhow!("Failed to serialize SetupConnection: {:?}", e))?;
    send_sv2_message(&mut stream, &mut noise_codec, SETUP_CONNECTION_MSG_TYPE, setup_payload).await?;

    // Wait for SetupConnectionSuccess
    let mut response_buffer = [0u8; 4096];
    let bytes_read = stream.read(&mut response_buffer).await?;
    info!("📥 Received {} bytes response", bytes_read);

    let encrypted_response = response_buffer[..bytes_read].to_vec();
    
    // Decrypt header
    let mut header_data = encrypted_response[..22].to_vec();
    noise_codec.decrypt(&mut header_data)
        .map_err(|e| anyhow::anyhow!("Header decryption failed: {:?}", e))?;
    
    let msg_type = header_data[2];
    let _msg_length = u32::from_le_bytes([header_data[3], header_data[4], header_data[5], 0]);

    // Decrypt payload
    let ciphertext_payload_len = encrypted_response.len() - 22;
    let mut payload_data = encrypted_response[22..22 + ciphertext_payload_len].to_vec();
    noise_codec.decrypt(&mut payload_data)
        .map_err(|e| anyhow::anyhow!("Payload decryption failed: {:?}", e))?;

    if msg_type == SETUP_CONNECTION_SUCCESS_MSG_TYPE {
        match from_bytes::<SetupConnectionSuccess>(&mut payload_data) {
            Ok(success) => {
                info!("🎉🎉 SetupConnectionSuccess received!");
                info!("📋 Used version: {}, flags: {:b}", success.used_version, success.flags);
                info!("✅ Successfully connected to SV2 Template Provider!");
                
                // Send CoinbaseOutputConstraints to signal we're ready for templates
                send_coinbase_constraints(&mut stream, &mut noise_codec).await?;
                
                return listen_for_templates(stream, noise_codec).await;
            }
            Err(e) => return Err(anyhow::anyhow!("Failed to parse SetupConnectionSuccess: {:?}", e)),
        }
    }
    
    Err(anyhow::anyhow!("Unexpected response"))
}

async fn send_coinbase_constraints(
    stream: &mut TcpStream,
    noise_codec: &mut NoiseCodec
) -> Result<()> {
    info!("📤 Sending CoinbaseOutputConstraints to signal readiness for templates...");
    
    // Create coinbase constraints payload manually since we don't have the exact struct
    let mut payload = Vec::new();
    payload.extend_from_slice(&100u32.to_le_bytes());  // max_additional_size: 100 bytes
    payload.extend_from_slice(&0u16.to_le_bytes());    // max_additional_sigops: 0
    
    send_sv2_message(stream, noise_codec, COINBASE_OUTPUT_CONSTRAINTS_MSG_TYPE, payload).await?;
    info!("✅ CoinbaseOutputConstraints sent - ready to receive templates!");
    
    Ok(())
}

async fn process_single_message(
    msg_type: u8,
    payload_data: &[u8]
) {
    match msg_type {
        NEW_TEMPLATE_MSG_TYPE => {
            info!("🎯 NewTemplate message received!");
            parse_new_template(payload_data).await;
        }
        SET_NEW_PREV_HASH_MSG_TYPE => {
            info!("🎯 SetNewPrevHash message received!");
            parse_set_new_prev_hash(payload_data).await;
        }
        REQUEST_TRANSACTION_DATA_MSG_TYPE => {
            info!("🎯 RequestTransactionData message received!");
            // Could respond with transaction data if we had it
        }
        _ => {
            info!("📋 Unknown message type: 0x{:02x}", msg_type);
            info!("📋 Payload hex: {}", hex::encode(payload_data));
        }
    }
}

async fn listen_for_templates(mut stream: TcpStream, mut noise_codec: NoiseCodec) -> Result<()> {
    info!("👂 Listening for template messages...");
    
    let mut buffer = Vec::new();
    
    loop {
        let mut response_buffer = [0u8; 8192]; // Larger buffer for template messages
        
        match tokio::time::timeout(std::time::Duration::from_secs(60), stream.read(&mut response_buffer)).await {
            Ok(Ok(bytes_read)) if bytes_read > 0 => {
                info!("📥 Received {} bytes", bytes_read);
                
                // Append new data to our buffer
                buffer.extend_from_slice(&response_buffer[..bytes_read]);
                
                // Process all complete messages in the buffer
                let mut offset = 0;
                while offset + 22 <= buffer.len() {
                    // Try to decrypt header at current offset
                    let mut header_data = buffer[offset..offset + 22].to_vec();
                    match noise_codec.decrypt(&mut header_data) {
                        Ok(()) => {
                            if header_data.len() != 6 {
                                warn!("❌ Invalid header length: {}, skipping", header_data.len());
                                offset += 1; // Try next byte
                                continue;
                            }
                            
                            let extension_type = u16::from_le_bytes([header_data[0], header_data[1]]);
                            let msg_type = header_data[2];
                            let msg_length = u32::from_le_bytes([header_data[3], header_data[4], header_data[5], 0]);
                            
                            info!("📋 Message: [ext:{}][type:0x{:02x}][len:{}]", extension_type, msg_type, msg_length);
                            
                            // Calculate expected ciphertext length for payload
                            let expected_payload_ciphertext_len = if msg_length == 0 {
                                0
                            } else {
                                msg_length as usize + 16 // Add MAC
                            };
                            
                            // Check if we have enough data for the complete message
                            let total_message_len = 22 + expected_payload_ciphertext_len;
                            if offset + total_message_len > buffer.len() {
                                // Not enough data for complete message, wait for more
                                break;
                            }
                            
                            // Decrypt payload if present
                            if expected_payload_ciphertext_len > 0 {
                                let payload_start = offset + 22;
                                let payload_end = payload_start + expected_payload_ciphertext_len;
                                let mut payload_data = buffer[payload_start..payload_end].to_vec();
                                
                                match noise_codec.decrypt(&mut payload_data) {
                                    Ok(()) => {
                                        info!("🎉 Decrypted payload ({} bytes)", payload_data.len());
                                        
                                        // Verify payload length matches header
                                        if payload_data.len() != msg_length as usize {
                                            warn!("❌ Payload length mismatch: got {} bytes, expected {}", payload_data.len(), msg_length);
                                        } else {
                                            // Process the message
                                            process_single_message(msg_type, &payload_data).await;
                                        }
                                    }
                                    Err(e) => {
                                        error!("❌ Failed to decrypt payload for message 0x{:02x}: {:?}", msg_type, e);
                                    }
                                }
                            } else {
                                // No payload, just process the message type
                                process_single_message(msg_type, &[]).await;
                            }
                            
                            // Move to next message
                            offset += total_message_len;
                        }
                        Err(_) => {
                            // Decryption failed, try next byte position
                            offset += 1;
                        }
                    }
                }
                
                // Remove processed data from buffer
                if offset > 0 {
                    buffer.drain(..offset);
                }
            }
            Ok(Ok(_)) => {
                info!("📥 Server closed connection");
                break;
            }
            Ok(Err(e)) => {
                error!("❌ Read error: {:?}", e);
                break;
            }
            Err(_) => {
                info!("⏰ No messages received in 60s, continuing to listen...");
            }
        }
    }
    
    Ok(())
}

async fn parse_new_template(payload_data: &[u8]) {
    info!("🔍 Parsing NewTemplate message...");
    
    // Try to parse as NewTemplate - this might fail due to complex structure
    // For now, let's extract key fields manually
    if payload_data.len() >= 8 {
        let template_id = u64::from_le_bytes([
            payload_data[0], payload_data[1], payload_data[2], payload_data[3],
            payload_data[4], payload_data[5], payload_data[6], payload_data[7]
        ]);
        info!("📋 Template ID: {}", template_id);
        
        if payload_data.len() > 8 {
            let future_template = payload_data[8] != 0;
            info!("📋 Future template: {}", future_template);
        }
        
        if payload_data.len() >= 16 {
            let version = u32::from_le_bytes([
                payload_data[9], payload_data[10], payload_data[11], payload_data[12]
            ]);
            info!("📋 Block version: 0x{:08x}", version);
        }
        
        if payload_data.len() >= 20 {
            let coinbase_tx_version = u32::from_le_bytes([
                payload_data[13], payload_data[14], payload_data[15], payload_data[16]
            ]);
            info!("📋 Coinbase TX version: {}", coinbase_tx_version);
        }
        
        // Try to find coinbase value remaining (it's later in the structure)
        if payload_data.len() >= 50 {
            // This is a rough estimate of where coinbase_tx_value_remaining might be
            // The exact offset depends on the variable-length coinbase_prefix field
            for i in 20..50 {
                if i + 8 <= payload_data.len() {
                    let potential_value = u64::from_le_bytes([
                        payload_data[i], payload_data[i+1], payload_data[i+2], payload_data[i+3],
                        payload_data[i+4], payload_data[i+5], payload_data[i+6], payload_data[i+7]
                    ]);
                    // Look for reasonable coinbase values (between 1 BTC and 100 BTC in satoshis)
                    if potential_value >= 100_000_000 && potential_value <= 10_000_000_000 {
                        info!("📋 Potential coinbase value: {} satoshis ({} BTC)", potential_value, potential_value as f64 / 100_000_000.0);
                        break;
                    }
                }
            }
        }
    }
    
    info!("📋 Template data ({} bytes): {}", payload_data.len(), hex::encode(&payload_data[..std::cmp::min(100, payload_data.len())]));
    if payload_data.len() > 100 {
        info!("📋 ... (truncated, showing first 100 bytes)");
    }
}

async fn parse_set_new_prev_hash(payload_data: &[u8]) {
    info!("🔍 Parsing SetNewPrevHash message...");
    
    if payload_data.len() >= 8 {
        let template_id = u64::from_le_bytes([
            payload_data[0], payload_data[1], payload_data[2], payload_data[3],
            payload_data[4], payload_data[5], payload_data[6], payload_data[7]
        ]);
        info!("📋 Template ID: {}", template_id);
        
        if payload_data.len() >= 40 {
            let prev_hash = &payload_data[8..40];
            info!("📋 Previous hash: {}", hex::encode(prev_hash));
        }
        
        if payload_data.len() >= 44 {
            let header_timestamp = u32::from_le_bytes([
                payload_data[40], payload_data[41], payload_data[42], payload_data[43]
            ]);
            info!("📋 Header timestamp: {} (Unix timestamp)", header_timestamp);
        }
        
        if payload_data.len() >= 48 {
            let nbits = u32::from_le_bytes([
                payload_data[44], payload_data[45], payload_data[46], payload_data[47]
            ]);
            info!("📋 nBits (difficulty): 0x{:08x}", nbits);
        }
        
        if payload_data.len() >= 80 {
            let target = &payload_data[48..80];
            info!("📋 Target: {}", hex::encode(target));
        }
    }
    
    info!("📋 SetNewPrevHash data ({} bytes): {}", payload_data.len(), hex::encode(payload_data));
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();
    
    info!("🚀 Starting Enhanced SV2 Template Provider client...");
    
    establish_encrypted_connection_and_setup().await?;
    
    Ok(())
}