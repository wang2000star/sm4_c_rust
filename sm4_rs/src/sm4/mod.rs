// #![allow(dead_code)]
// #![allow(unused)]
mod sm4_utils;
use sm4_utils::{sm4key_expansion, sm4_enc_dec};


pub fn  demo_sm4(){
    let plaintext: [u8;16] = [
        0x00, 0x11, 0x22, 0x33,
        0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb,
        0xcc, 0xdd, 0xee, 0xff,
    ];
    let key : [u8;16] = [
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f,
    ];
    let enc_key = sm4key_expansion(true,&key);
    let ciphertext = sm4_enc_dec(&enc_key, &plaintext);
    println!("plaintext:");
    for i in 0..16{
        print!("{:02x} ", plaintext[i]);
    }
    println!("\nciphertext:");
    for i in 0..16{
        print!("{:02x} ", ciphertext[i]);
    }
    let dec_key = sm4key_expansion(false, &key);
    let plaintext2 = sm4_enc_dec(&dec_key, &ciphertext);
    println!("\nplaintext2:");
    for i in 0..16{
        print!("{:02x} ", plaintext2[i]);
    }
    if plaintext == plaintext2{
        println!("\nsm4 decryption passed");
    }else{
        println!("\nsm4 decryption failed");
    }
}
pub fn sm4_speed(){
    let plaintext: [u8;16] = [
        0x00, 0x11, 0x22, 0x33,
        0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb,
        0xcc, 0xdd, 0xee, 0xff,
    ];
    let key : [u8;16] = [
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f,
    ];
    // 生成加密拓展密钥
    let enc_key = sm4key_expansion(true,&key);
    let mut _ciphertext: [u8; 16] = [0; 16];    
    // 加密次数
    let max_num = 1024*1024;
    // 计时开始
    let start = std::time::Instant::now();
    for _ in 0..max_num{
        _ciphertext = sm4_enc_dec(&enc_key, &plaintext);
    }
    // 计时结束
    let duration = start.elapsed();
    let seconds = duration.as_secs_f64();
    let throughput = (16.0 * (max_num/(1024*1024)) as f64) / seconds;
    println!("sm4 throughput: {:.2} MiB/s", throughput);
}
    
