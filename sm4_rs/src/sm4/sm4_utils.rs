#![allow(dead_code)]
// SboxTable is the S-box used in SM4
static SM4_SBOX: [[u8;16];16] = [ [0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05],
                                  [0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99],
                                  [0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62],
                                  [0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6],
                                  [0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8],
                                  [0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35],
                                  [0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87],
                                  [0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e],
                                  [0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1],
                                  [0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3],
                                  [0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f],
                                  [0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51],
                                  [0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8],
                                  [0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0],
                                  [0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84],
                                  [0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48] ];

fn vec_bool_to_u64(v : &Vec<bool>) -> u64{
    assert_eq!(v.len(), 32);
    v.iter().enumerate().map(|(i, b)| if *b {1 << (31 - i)} else {0}).sum()
}


fn u64_to_vec_bool(x : u64) -> Vec<bool>{
    (0..32).map(|i| (x >> (31 - i)) % 2 == 1).collect()
}

pub fn vec_bool_to_u8(v : &Vec<u64>) -> u8{
    assert_eq!(v.len(), 8);
    v.iter().enumerate().map(|(i, b)| if *b == 1 {1 << (7 - i)} else {0}).sum()
}


pub fn u8_to_vec_bool(x : u8) -> Vec<bool>{
    (0..8).map(|i| (x >> (7 - i)) % 2 == 1).collect()
}


pub fn u8_to_vec_bool_integer(x : u8) -> Vec<u64>{
    (0..8).map(|i| (x as u64 >> (7 - i)) % 2).collect::<Vec<u64>>()
}



//单个S盒
fn substitute(o : u8) -> u8{
    let upper_nibble = o >> 4;
    let lower_nibble = o % 16;
    SM4_SBOX[upper_nibble as usize][lower_nibble as usize]
}
//字节替换层，调用substitute
fn sub_word(x : u32) -> u32{
    let bytes : Vec<u8> = (0..4).map(|i| (x >> (8 * (3 - i)) % 256) as u8).collect();
    let bytes_subs : Vec<u8> = bytes.iter().map(|o| substitute(*o)).collect();
    bytes_subs.iter().enumerate().map(|(i, o)| (*o as u32)  << (8 * (3 - i))).sum()
}


/*sm4的轮密钥拓展函数
输入原始密钥为长度为16的向量，向量元素长度为8比特
输出轮密钥为长度为32的向量，向量元素长度为32比特
轮数为32轮
FK[4] = {0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc};
Ck[32] = {
            0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
            0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
            0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
            0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
            0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
            0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
            0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
            0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
        };
mod = true表示加密，false表示解密
*/
pub fn sm4key_expansion(mode : bool,sm4_key : &mut Vec<u8>) -> Vec<u32>{
    let fk: [u32; 4] = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc];
    let ck: [u32; 32] = [
        0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
        0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
        0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
        0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
        0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
        0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
        0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
        0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
    ];
    let mut rk: Vec<u32> = vec![0; 32];
    // 把sm4_key转换为4个32比特的整数存在buffer前4个元素中
    let mut buffer: [u32; 36] = [0; 36];
    for i in 0..4{
        buffer[i] = ((sm4_key[i * 4] as u32) << 24) | ((sm4_key[i * 4 + 1] as u32) << 16) | ((sm4_key[i * 4 + 2] as u32) << 8) | (sm4_key[i * 4 + 3] as u32);
    }
    // 常数异或
    for i in 0..4{
        buffer[i] = buffer[i] ^ fk[i];
    }
    // 32轮函数
    for r in 0..32{
        // 轮密钥异或，buffer[4+r]=buffer[r+1] ^ buffer[r+2] ^ buffer[r+3] ^ CK[r]
        buffer[4 + r] = buffer[r + 1] ^ buffer[r + 2] ^ buffer[r + 3] ^ ck[r];
        // s盒，分为4个字节，分别调用substitute
        buffer[4 + r] = sub_word(buffer[4 + r]);
        // 线性变换，循环左移位0,13,23再异或
        buffer[4 + r] = buffer[4 + r] ^ buffer[4 + r].rotate_left(13) ^ buffer[4 + r].rotate_left(23);
        // 异或，buffer[4+r] = buffer[4+r] ^ buffer[r];
        buffer[4 + r] = buffer[4 + r] ^ buffer[r];
        // 轮密钥
        rk[r] = buffer[4 + r];
    }
    // 如果是解密模式，则反转轮密钥
    if !mode{
        rk.reverse();
    }
    // 返回轮密钥
    rk
}
/*  sm4拓展秘钥是长度为32的向量，向量元素长度为32比特，相当于128字节
    明文是长度为16的向量，向量元素长度为8比特
    密文是长度为16的向量，向量元素长度为8比特
    轮数是32轮
*/
pub fn sm4_enc_dec(enc_key : Vec<u32>, plaintext : [u8; 16]) -> [u8;16]{
    // 令palintext转换为4个32比特的整数存在buffer前4个元素中
    let mut buffer: [u32; 36] = [0; 36];
    for i in 0..4{
        buffer[i] = ((plaintext[i * 4] as u32) << 24)  |((plaintext[i * 4 + 1] as u32) << 16) | ((plaintext[i * 4 + 2] as u32) << 8) | (plaintext[i * 4 + 3] as u32);
    }
    // 32轮函数
    for r in 0..32{
        // 轮密钥异或，buffer[4+r]=buffer[r+1] ^ buffer[r+2] ^ buffer[r+3] ^ enc_key[r]
        buffer[4 + r] = buffer[r + 1] ^ buffer[r + 2] ^ buffer[r + 3] ^ enc_key[r];
        // s盒，分为4个字节，分别调用substitute
        buffer[4 + r] = sub_word(buffer[4 + r]);
        // 线性变换，循环左移位0,2,10,18,24再异或
        buffer[4 + r] = buffer[4 + r] ^ buffer[4 + r].rotate_left(2) ^ buffer[4 + r].rotate_left(10) ^ buffer[4 + r].rotate_left(18) ^ buffer[4 + r].rotate_left(24);
        // 异或，buffer[4+r] = buffer[4+r] ^ buffer[r];
        buffer[4 + r] = buffer[4 + r] ^ buffer[r];
    }
    // 分别把buffer[35-i]转换为4个字节整数放在ciphertext[4*i+0],ciphertext[4*i+1],ciphertext[4*i+2],ciphertext[4*i+3]
    let mut ciphertext: [u8; 16] = [0; 16];
    for i in 0..4{
        ciphertext[i * 4] = (buffer[35 - i] >> 24) as u8;
        ciphertext[i * 4 + 1] = (buffer[35 - i] >> 16) as u8;
        ciphertext[i * 4 + 2] = (buffer[35 - i] >> 8) as u8;
        ciphertext[i * 4 + 3] = buffer[35 - i] as u8;
    }
    ciphertext
}
#[test]
fn test_sm4_enc(){
    let plaintext: [u8;16] = [
        0x00, 0x11, 0x22, 0x33,
        0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb,
        0xcc, 0xdd, 0xee, 0xff,
    ];
    let mut key : Vec<u8> = vec![
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f,
    ];
    let enc_key = sm4key_expansion(true,&mut key);
    let ciphertext = sm4_enc_dec(enc_key, plaintext);
    let dec_key = sm4key_expansion(false,&mut key);
    let plaintext2 = sm4_enc_dec(dec_key, ciphertext);
    assert_eq!(plaintext, plaintext2);
}