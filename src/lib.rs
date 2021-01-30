#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![allow(incomplete_features)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::inline_always)]
#![feature(const_int_pow)]
#![feature(array_value_iter)]
#![feature(associated_type_bounds)]
#![feature(const_generics)]
#![feature(const_generic_impls_guard)]

#[macro_use]
extern crate derivative;
use crate::Tomtel::Machine;
use itertools::{izip, unfold, Itertools};
use openssl::aes::unwrap_key;
use openssl::symm::decrypt;
use std::array::LengthAtMost32;
use std::convert::TryInto;
use std::error::Error;
use std::fmt::{self, Display};
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::Ipv4Addr;
use std::str::from_utf8;
use std::{array, path::Path};
// use std::str::from_utf8;
use io::{stdout, Stdout};
use openssl::aes::AesKey;
use openssl::symm::Cipher;

pub type Res<T> = Result<T, Box<dyn Error>>;

pub fn read_input<P: AsRef<Path>>(p: P) -> io::Result<Vec<u8>> {
    let mut buffer = Vec::<u8>::with_capacity(100_000);
    let mut f = File::open(p)?;
    f.read_to_end(&mut buffer)?;
    Ok(buffer)
}

fn write_output(p: impl AsRef<Path>, b: impl IntoIterator<Item = u8>) -> io::Result<()> {
    // return Ok(());

    let mut f = File::create(p)?;
    // let mut f = BufWriter::new(f); // matters?
    f.write_all(&b.into_iter().collect::<Vec<u8>>())
}

fn get_next_input<'a>(b: &'a [u8]) -> impl Iterator<Item = u8> + 'a {
    b.windows(2)
        // .filter(|&c| c != b'\r' && c != b'\n')
        .skip_while(|&arr| arr != b"<~")
        .skip(2)
        .take_while(|&arr| arr != b"~>")
        .map(|arr| arr[0])
}

fn get_next_input2(b: impl Iterator<Item = u8>) -> impl Iterator<Item = u8> {
    const PRE: (u8, u8) = (b'<', b'~');
    const POS: (u8, u8) = (b'~', b'>');
    b.tuple_windows::<(u8, u8)>()
        // .filter(|&c| c != b'\r' && c != b'\n')
        .skip_while(|&w| w != PRE)
        .skip(2)
        .take_while(|&w| w != POS)
        .map(|arr| arr.0)
}

fn write_next_input<P: AsRef<Path>>(p: P, b: &[u8]) -> io::Result<()> {
    // return Ok(());

    let mut f = File::create(p)?;
    // let mut f = BufWriter::new(f); // matters?
    f.write_all(&get_next_input(b).collect::<Vec<u8>>())
}

fn strip_input<'a>(buf: &'a [u8]) -> impl Iterator<Item = u8> + 'a {
    buf.iter().cloned().filter(|&c| c != b'\r' && c != b'\n')
}

fn u8x7(x: u64) -> [u8; 7] {
    x.to_be_bytes()[1..8].try_into().unwrap()
}
// fn u8x7(x: u64) -> [u8; 7] {
// let b1: u8 = ((x >> 48) & 0xff) as u8;
// let b2: u8 = ((x >> 40) & 0xff) as u8;
// let b3: u8 = ((x >> 32) & 0xff) as u8;
// let b4: u8 = ((x >> 24) & 0xff) as u8;
// let b5: u8 = ((x >> 16) & 0xff) as u8;
// let b6: u8 = ((x >> 8) & 0xff) as u8;
// let b7: u8 = (x & 0xff) as u8;
// return [b1, b2, b3, b4, b5, b6, b7];
// }

// #[no_mangle]
fn base85_parse(block: [u8; 5]) -> [u8; 4] {
    const MULS: [u32; 5] = [85_u32.pow(4), 85_u32.pow(3), 85_u32.pow(2), 85, 1];
    block
        .iter()
        .map(|&a| a - b'!')
        .map(u32::from)
        .zip(&MULS)
        .map(|(a, &b)| a * b)
        .sum::<u32>()
        .to_be_bytes()
}

// #[no_mangle]
fn base85_parse2(block: [u8; 5]) -> [u8; 4] {
    block
        .iter()
        // .inspect(|&&v| print!("({:?} {:?}) ",  v as char, v))
        .map(|&a| a - b'!')
        .map(u32::from)
        // .inspect(|&v| println!("{:?}", v))
        .fold(0_u32, |total, n| total * 85 + n)
        .to_be_bytes()
}

fn layer1_decode(buffer: &[u8]) -> Vec<u8> {
    buffer
        .iter()
        .map(|&b| b ^ 0b0101_0101)
        .map(|b| b.rotate_right(1))
        .collect()
}

pub fn ascii85_decode(buffer: &[u8]) -> Vec<u8> {
    let padding = match buffer.len() % 5 {
        0 => 0,
        i => 5 - i,
    };

    let decoded_iter = strip_input(buffer)
        .batching(|it| {
            const Z: u8 = b'z';
            match it.next() {
                Some(Z) => Some([b'!'; 5]),
                Some(v) => Some([
                    v,
                    it.next().unwrap_or(b'u'),
                    it.next().unwrap_or(b'u'),
                    it.next().unwrap_or(b'u'),
                    it.next().unwrap_or(b'u'),
                ]),
                None => None,
            }
        })
        .map(base85_parse);

    // let mut decoded = Vec::with_capacity(buffer.len());
    // decoded.extend(decoded_iter);
    // let mut decoded = decoded_iter.fold(Vec::with_capacity(100_000), |mut v, d| {
    //     v.extend_from_slice(&d);
    //     v
    // });
    let mut decoded = decoded_iter
        .flat_map(array::IntoIter::new)
        .collect::<Vec<_>>();

    for _i in 0..padding {
        decoded.pop();
    }

    decoded
}

fn even_parity_check(b: u8) -> Option<u8> {
    if b.count_ones() % 2 == 0 {
        Some(b >> 1)
    } else {
        None
    }
}

fn chunk_exact<T: Default + Copy, I: Iterator<Item = T>, const N: usize>(
    mut it: I,
) -> Option<[T; N]>
where
    [T; N]: LengthAtMost32,
{
    let mut tmp = [T::default(); N];
    for b in &mut tmp {
        *b = it.next()?;
    }
    Some(tmp)
}

#[allow(clippy::redundant_closure)]
fn layer2_decode(buffer: &[u8]) -> Vec<u8> {
    // let buffer: Vec<u8> = buffer.iter().filter_map(|&x| even_parity_check(x)).collect();
    buffer
        .iter()
        .cloned()
        .filter_map(even_parity_check)
        .batching(|x| chunk_exact::<_, _, 8>(x))
        .map(|x| x.iter().fold(0_u64, |x, &n| x << 7 | u64::from(n)))
        .map(u8x7)
        .flat_map(array::IntoIter::new)
        .collect()
    // .fold(Vec::with_capacity(100_000), |mut v, bs| {
    // v.extend_from_slice(&bs.to_be_bytes()[1..8]);
    // v
    // })
}

fn layer3_decode(buffer: &[u8]) -> Vec<u8> {
    // TODO: Auto hacking
    // const KNOWN2: &[u8] = b"==[ Layer 4/5: XOR Encryption ]=============================\n\n";
    // fn slice_known<'a>(text: &'a [u8]) -> impl Iterator<Item = &u8> + 'a {
    //     let pre = &text[..15];
    //     let pos = &text[32..64][15..];
    //     debug_assert_eq!(pre.len() + pos.len(), 32);
    //     pre.iter().chain(pos)
    // }
    // let key: Vec<_> = slice_known(&buffer)
    //     .zip(slice_known(KNOWN2))
    //     .map(|(&a, &b)| a ^ b)
    //     .collect();
    let key = {
        const KNOWN: &[u8] = b"==[ Layer 4/6: Network Traffic ]============>===============\n\n";
        let enced = &buffer[0..32];
        let mut key = [0_u8; 32];
        izip!(&mut key, KNOWN, enced).for_each(|(k, a, b)| *k = a ^ b);
        key
        // let key: Vec<_> = KNOWN.iter().zip(enced).map(|(&a, &b)| a ^ b).collect();
    };

    // println!("{:?}", key.collect::<Vec<u8>>());
    let deced = key
        .iter()
        .cycle()
        .zip(buffer)
        .map(|(a, &b)| a ^ b)
        .collect();

    deced
}

const IP_HEADER_SIZE: usize = 20;
const UDP_HEADER_SIZE: usize = 8;
#[derive(Debug, Clone)]
struct IPHeader {
    length: u16,
    // checksum: u16,
    src: u32,
    dst: u32,
}

impl Display for IPHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "IPHeader{{ length: {}, src: {}, dst: {}}}",
            self.length,
            // self.checksum,
            Ipv4Addr::from(self.src),
            Ipv4Addr::from(self.dst)
        )
    }
}

impl IPHeader {
    fn new(raw: &[u8]) -> IPHeader {
        IPHeader {
            length: u16::from_be_bytes(raw[2..4].try_into().unwrap()),
            // checksum: u16::from_be_bytes(raw[10..12].try_into().unwrap()),
            src: u32::from_be_bytes(raw[12..16].try_into().unwrap()),
            dst: u32::from_be_bytes(raw[16..20].try_into().unwrap()),
        }
    }
}

#[inline(always)]
#[allow(clippy::cast_possible_truncation)]
fn ones_compl_add_u16(x: u16, y: u16) -> u16 {
    let s = u32::from(x) + u32::from(y);
    ((s + ((s >> 16) & 1)) & 0xFFFF) as u16
    // (if s > 0xFFFF { s - 0xFFFF } else { s }) as u16
}

#[inline(always)]
fn calc_checksum_serial(buf: &[u8]) -> u16 {
    // TODO: vectorize this?
    buf.chunks_exact(2)
        .map(TryInto::try_into)
        .map(Result::unwrap)
        .map(u16::from_be_bytes)
        // .tree_fold1(ones_compl_add_u16).unwrap()
        .fold1(ones_compl_add_u16)
        .unwrap()
    // .fold(0u16, ones_compl_add_u16)
}

fn calc_checksum(buf: &[u8]) -> u16 {
    let chk = calc_checksum_serial(buf);
    if buf.len() % 2 == 1 {
        ones_compl_add_u16(chk, u16::from_be_bytes([*buf.last().unwrap(), 0]))
    } else {
        chk
    }
}

#[derive(Debug, Clone)]
struct StrError(&'static str);
impl Display for StrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl StrError {
    fn err<T>(s: &'static str) -> Result<T, Box<dyn Error>> {
        Err(Box::new(StrError(s)))
    }
}

impl Error for StrError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

#[derive(Debug, Clone)]
struct UDPHeader {
    // buf: &'a [u8],
    length: u16,
    // checksum: u16,
    src: u16,
    dst: u16,
}

impl UDPHeader {
    fn new(raw: &[u8]) -> UDPHeader {
        UDPHeader {
            // buf: raw,
            length: u16::from_be_bytes(raw[4..6].try_into().unwrap()),
            // checksum: u16::from_be_bytes(raw[6..8].try_into().unwrap()),
            src: u16::from_be_bytes(raw[0..2].try_into().unwrap()),
            dst: u16::from_be_bytes(raw[2..4].try_into().unwrap()),
        }
    }
}

fn udp_checksum(buf: &[u8]) -> u16 {
    let mut chk: u16 = calc_checksum(&buf[12..20]); //src,dst
    chk = ones_compl_add_u16(chk, calc_checksum(&[0, 0x11])); //zeroes, protocol
    chk = ones_compl_add_u16(chk, calc_checksum(&buf[24..26])); // UDP length
    chk = ones_compl_add_u16(chk, calc_checksum(&buf[IP_HEADER_SIZE..])); // UDP header + DATA
                                                                          // chk = !chk;
    chk
}

// fn layer4_decode_one(buf: &[u8]) -> (Result<&[u8], StrError>, &[u8]) {
fn layer4_decode_one(buf: &[u8]) -> (Res<&[u8]>, &[u8]) {
    const EXPECT_SRC_IP: u32 = u32::from_be_bytes([10, 1, 1, 10]);
    const EXPECT_DST_IP: u32 = u32::from_be_bytes([10, 1, 1, 200]);
    const EXPECT_DST_PORT: u16 = 42069;

    let mut len = IP_HEADER_SIZE + UDP_HEADER_SIZE;
    // let res = || -> Result<&[u8], StrError> {
    let res = || -> Res<_> {
        let iph = IPHeader::new(buf);
        len = iph.length as usize;
        // println!("{}", iph);

        let data = &buf[(IP_HEADER_SIZE + UDP_HEADER_SIZE)..iph.length as usize];

        if iph.src != EXPECT_SRC_IP || iph.dst != EXPECT_DST_IP {
            // println!("{:?}", from_utf8(data)?);
            return StrError::err("IP Src/Dst Address Incorrect");
        }
        if !calc_checksum(&buf[0..IP_HEADER_SIZE]) != 0 {
            // println!("{:?}", from_utf8(data)?);
            return StrError::err("IP Checksum Fail");
        }

        let buf = &buf[..iph.length as usize];
        // let (buf, rest) = buf.split_at(iph.length as usize);

        let udph = UDPHeader::new(&buf[IP_HEADER_SIZE..]);
        // println!("{:?}", udph);

        if udph.dst != EXPECT_DST_PORT {
            // println!("{:?}", from_utf8(data)?);
            return StrError::err("IP Dst Port Incorrect");
        }

        if !udp_checksum(buf) != 0 {
            // println!("{:?}", from_utf8(data)?);
            return StrError::err("UDP Checksum Fail");
        }

        // println!("{:?}", from_utf8(data)?);

        Ok(data)
    }();
    let rest = &buf[(len as usize)..];

    (res, rest)
}

fn layer4_decode(b: &[u8]) -> Vec<u8> {
    unfold(&*b, |left| {
        left.get(IP_HEADER_SIZE + UDP_HEADER_SIZE).map(|_| {
            let (pack, rest) = layer4_decode_one(&left);
            *left = rest;
            pack.unwrap_or(&[])
            // match pack {
            // Ok(pack) => pack,
            // Err(e) => {
            // dbg!(e); &[]
            // }
            // }
        })
    })
    .fold(Vec::with_capacity(100_000), |mut vec, data| {
        vec.extend_from_slice(data);
        vec
    })
    // .flatten()
    // .cloned()
    // .collect()
}

fn layer5_decode(layer1: &[u8]) -> Vec<u8> {
    let (kek, rest) = layer1.split_at(32);
    let (kekiv, rest) = rest.split_at(8);
    let (wrapped_key, rest) = rest.split_at(40);
    let (iv, data) = rest.split_at(16);

    let unwrapped_key = {
        let kekiv = kekiv.try_into().unwrap();
        let kek = AesKey::new_decrypt(kek).unwrap();

        let mut keybuf = [0_u8; 32];
        unwrap_key(&kek, Some(kekiv), &mut keybuf, wrapped_key).unwrap();
        keybuf
    };

    decrypt(Cipher::aes_256_ctr(), &unwrapped_key, Some(iv), data).unwrap()
}

mod Tomtel {
    use std::fmt::Debug;
    use std::fmt::Display;
    use std::io::stdout;
    use std::time::Duration;
    use std::{
        convert::TryInto,
        io::{Stdout, Write},
        ops::BitXor,
        thread::sleep,
    };
    #[derive(Debug, Clone, Default)]
    struct Regs {
        a: u8,    //Accumulation register -- Used to store the result
        b: u8,    //Operand register -- This is 'right hand side' of
        c: u8,    //Count/offset register -- Holds an offset or index
        d: u8,    //General purpose register
        e: u8,    //General purpose register
        f: u8,    //Flags register -- Holds the result of the
        la: u32,  //General purpose register
        lb: u32,  //General purpose register
        lc: u32,  //General purpose register
        ld: u32,  //General purpose register
        ptr: u32, //Pointer to memory -- holds a memory address which
        pc: u32,  //Program counter -- holds a memory address that
    }

    #[derive(Derivative)]
    #[derivative(Debug)]
    pub(crate) struct Machine<OStream: Write> {
        regs: Regs,
        #[derivative(Debug = "ignore")]
        memory: Vec<u8>,
        #[derivative(Debug = "ignore")]
        output: OStream,

        pub(crate) halted: bool,
    }

    impl Machine<Stdout> {
        pub fn std(code: Vec<u8>) -> Self {
            Machine {
                regs: Regs::default(),
                memory: code,
                output: stdout(),
                halted: false,
            }
        }
    }

    impl<O: Write> Machine<O> {
        pub fn new(code: Vec<u8>, o: O) -> Self {
            Machine {
                regs: Regs::default(),
                memory: code,
                output: o,
                halted: false,
            }
        }
    }

    const OPC_ADD: u8 = 0xC2;
    const OPC_APTR: u8 = 0xE1;
    const OPC_CMP: u8 = 0xC1;
    const OPC_HALT: u8 = 0x01;
    const OPC_JEZ: u8 = 0x21;
    const OPC_JNZ: u8 = 0x22;
    const OPC_OUT: u8 = 0x02;
    const OPC_SUB: u8 = 0xC3;
    const OPC_XOR: u8 = 0xC4;
    // const OPC_MV: u8 = 0b01DDDSSS;
    // const OPC_MV32: u8 = 0b10DDDSSS;
    // const OPC_MVI: u8 = 0b01DDD000;
    // const OPC_MVI32: u8 = 0b10DDD000;

    impl<O: Write> Machine<O> {
        fn pc(&self) -> u8 {
            let r = self.memory[self.regs.pc as usize];
            print!("(INS @ {} = {r:x}  {r:b}) ", self.regs.pc, r = r); // Tomtel Assembly Debugging
            r
        }
        fn par(&self, i: usize) -> u8 {
            let r = self.memory[self.regs.pc as usize + i];
            print!("(IMM8={}) ", r); // Tomtel Assembly Debugging
            r
        }
        fn par32(&self, i: usize) -> u32 {
            let r = u32::from_le_bytes(
                self.memory[self.regs.pc as usize + i..][..4]
                    .try_into()
                    .unwrap(),
            );
            print!("(IMM32={}) ", r); // Tomtel Assembly Debugging
            r
        }
        fn reg_print<T: Display>(r: T) -> T {
            print!("(REG={}) ", r); // Tomtel Assembly Debugging
            r
        }
        fn reg(&mut self, i: u8) -> &mut u8 {
            match i {
                1 => Self::reg_print(&mut self.regs.a),
                2 => Self::reg_print(&mut self.regs.b),
                3 => Self::reg_print(&mut self.regs.c),
                4 => Self::reg_print(&mut self.regs.d),
                5 => Self::reg_print(&mut self.regs.e),
                6 => Self::reg_print(&mut self.regs.f),
                7 => {
                    let r = &mut self.memory[self.regs.ptr as usize + self.regs.c as usize];
                    print!("(MEM @ {}+{} = {}) ", self.regs.ptr, self.regs.c, r); // Tomtel Assembly Debugging
                    r
                }
                _ => unreachable!("Invalid Register, I dont even care rn"),
            }
        }
        fn reg32(&mut self, i: u8) -> &mut u32 {
            match i {
                1 => Self::reg_print(&mut self.regs.la),
                2 => Self::reg_print(&mut self.regs.lb),
                3 => Self::reg_print(&mut self.regs.lc),
                4 => Self::reg_print(&mut self.regs.ld),
                5 => Self::reg_print(&mut self.regs.ptr),
                6 => Self::reg_print(&mut self.regs.pc),
                _ => unreachable!("Invalid Register32, I dont even care rn"),
            }
        }
        fn op(&mut self, f: impl Fn(u8, u8) -> u8) {
            print!("(({}, {})) ", self.regs.a, self.regs.b); // Tomtel Assembly Debugging
            self.regs.a = f(self.regs.a, self.regs.b);
            print!("(-> {}) ", self.regs.a); // Tomtel Assembly Debugging
        }
        fn mv_dst(&self, opc: u8) -> u8 {
            (opc & 0b0011_1000) >> 3
        }
        fn mv_src(&self, opc: u8) -> u8 {
            opc & 0b0000_0111
        }
        fn dst(&mut self, opc: u8) -> &mut u8 {
            let dst = self.mv_dst(opc);
            print!("(DST:{}) ", dst); // Tomtel Assembly Debugging
            self.reg(dst)
        }
        fn dst32(&mut self, opc: u8) -> &mut u32 {
            let dst = self.mv_dst(opc);
            print!("(DST:{}) ", dst); // Tomtel Assembly Debugging
            self.reg32(dst)
        }
        fn src(&mut self, opc: u8) -> (u8, u32) {
            let src = self.mv_src(opc);
            print!("(SRC:{}) ", src); // Tomtel Assembly Debugging
            if src == 0 {
                (self.par(1), 1)
            } else {
                (*self.reg(src), 0)
            }
        }
        fn src32(&mut self, opc: u8) -> (u32, u32) {
            let src = self.mv_src(opc);
            print!("(SRC:{}) ", src); // Tomtel Assembly Debugging
            if src == 0 {
                (self.par32(1), 4)
            } else {
                (*self.reg32(src), 0)
            }
        }
        pub fn step(&mut self) {
            let pc = match self.pc() {
                OPC_HALT => {
                    print!("(OP:HALT) "); // Tomtel Assembly Debugging
                    self.halted = true;
                    self.regs.pc
                }
                OPC_ADD => {
                    print!("(OP:ADD) "); // Tomtel Assembly Debugging
                    self.op(u8::wrapping_add);
                    self.regs.pc + 1
                }
                OPC_SUB => {
                    print!("(OP:SUB) "); // Tomtel Assembly Debugging
                    self.op(|a, b| {
                        let res = i32::from(a) - i32::from(b);
                        (if res < 0 { res + 255 } else { res }) as u8
                    });
                    self.regs.pc + 1
                }
                OPC_XOR => {
                    print!("(OP:XOR) "); // Tomtel Assembly Debugging
                    self.op(BitXor::bitxor);
                    self.regs.pc + 1
                }
                OPC_APTR => {
                    print!("(OP:APTR) "); // Tomtel Assembly Debugging
                    self.regs.ptr += self.par(1) as u32;
                    self.regs.pc + 2
                }
                OPC_CMP => {
                    if self.regs.a == self.regs.b {
                        self.regs.f = 0;
                    } else {
                        self.regs.f = 1;
                    }
                    print!(// Tomtel Assembly Debugging
                        "((OP:CMP) {} ?= {} -> {}) ",
                        self.regs.a, self.regs.b, self.regs.f
                    );
                    self.regs.pc + 1
                }
                OPC_JEZ => {
                    print!("((OP:JEZ) {}) ", self.regs.f); // Tomtel Assembly Debugging
                    if self.regs.f == 0 {
                        print!("(JUMPED) "); // Tomtel Assembly Debugging
                        self.par32(1)
                    } else {
                        self.regs.pc + 5
                    }
                }
                OPC_JNZ => {
                    print!("((OP:JNZ) {}) ", self.regs.f); // Tomtel Assembly Debugging
                    if self.regs.f == 0 {
                        self.regs.pc + 5
                    } else {
                        print!("(JUMPED) "); // Tomtel Assembly Debugging
                        self.par32(1)
                    }
                }
                OPC_OUT => {
                    print!("((OP:OUT) {} {}) ", self.regs.a, self.regs.a as char); // Tomtel Assembly Debugging
                    self.output
                        .write_all(&[self.regs.a])
                        .expect("Tomtel Output Stream Failed");
                    self.regs.pc + 1
                }
                opc => {
                    if opc & 0b1111_1000 == 0b1000_0000 | (6 << 3) {
                        // JMP IMM32 JMP REG
                        print!("(OP:JMP) "); // Tomtel Assembly Debugging
                        print!("(JUMPED) "); // Tomtel Assembly Debugging
                        let (src32, inc) = self.src32(opc);
                        *self.dst32(opc) = src32;
                        self.regs.pc
                    } else if opc & 0b1100_0000 == 0b0100_0000 {
                        print!("(OP:MV) "); // Tomtel Assembly Debugging
                                            //MV MVI
                        let (src, inc) = self.src(opc);
                        *self.dst(opc) = src;
                        self.regs.pc + inc + 1
                    } else if opc & 0b1100_0000 == 0b1000_0000 {
                        //MV32 MVI32
                        print!("(OP:MV32) "); // Tomtel Assembly Debugging
                        let (src32, inc) = self.src32(opc);
                        *self.dst32(opc) = src32;
                        self.regs.pc + inc + 1
                    } else {
                        println!("Invalid Machine Code @ {} : {:x}", self.regs.pc, self.pc());
                        self.halted=true;
                        self.regs.pc
                    }
                }
            };
            println!(); // Tomtel Assembly Debugging
                        // sleep(Duration::from_millis(200));

            self.regs.pc = pc;

            println!("{:?}\n", self); // Tomtel Assembly Debugging
        }
    }
}

fn layer6_decode(input: &[u8]) -> Vec<u8> {
    // let input = { // Hello World
    //     let mut buf = String::with_capacity(1000);
    //     File::open("exprg.txt")
    //         .unwrap()
    //         .read_to_string(&mut buf)
    //         .unwrap();
    //     buf.split_ascii_whitespace()
    //         .map(|c| u8::from_str_radix(c, 16).unwrap())
    //         .collect_vec()
    // };
    let mut output = Vec::<u8>::with_capacity(100_000);
    // let mut mach = Machine::new(input, &mut output);
    let mut mach = Machine::new(input.to_vec(), &mut output);

    while !mach.halted {
        mach.step();
    }

    output
}

pub fn peel_all_layers() -> Res<()> {
    peel_layer0()?;

    peel_layer1()?;

    peel_layer2()?;

    peel_layer3()?;

    peel_layer4()?;

    peel_layer5()?;

    peel_layer6()?;

    Ok(())
}

#[allow(clippy::let_and_return)]
#[must_use]
pub fn peel_all_layers2(input: &[u8]) -> Vec<u8> {
    let output0 = ascii85_decode(input);
    let input1 = get_next_input(&output0).collect::<Vec<u8>>();
    let output1 = only_peel_layer1(&input1);
    let input2 = get_next_input(&output1).collect::<Vec<u8>>();
    let output2 = only_peel_layer2(&input2);
    let input3 = get_next_input(&output2).collect::<Vec<u8>>();
    let output3 = only_peel_layer3(&input3);
    let input4 = get_next_input(&output3).collect::<Vec<u8>>();
    let output4 = only_peel_layer4(&input4);
    let input5 = get_next_input(&output4).collect::<Vec<u8>>();
    let output5 = only_peel_layer5(&input5);
    output5
}

#[must_use]
pub fn only_peel_layer6(buffer: &[u8]) -> Vec<u8> {
    let layer1 = {
        let mut layer1 = ascii85_decode(buffer);
        layer1.extend_from_slice(&[0; 4]);
        layer1
    };
    {
        use std::fmt::Write as FmtWrite;
        write_output(
            "code6.txt",
            layer1
                .iter()
                .fold(String::new(), |mut s, &b| {
                    writeln!(&mut s, "0x{b:x} 0b{b:08b}", b = b).unwrap();
                    s
                })
                .bytes(),
        )
        .unwrap_or(());
    }
    layer6_decode(&layer1)
}

pub fn peel_layer6() -> Res<()> {
    // println!("Starting Layer 5");
    let buffer = read_input("input6.txt")?;
    let layer6 = only_peel_layer6(&buffer);

    // write_next_input
    write_output("layer7.txt", layer6)?;

    Ok(())
}

#[must_use]
pub fn only_peel_layer5(buffer: &[u8]) -> Vec<u8> {
    let layer1 = ascii85_decode(buffer);
    layer5_decode(&layer1)
}

pub fn peel_layer5() -> Res<()> {
    // println!("Starting Layer 5");
    let buffer = read_input("input5.txt")?;
    let layer6 = only_peel_layer5(&buffer);

    write_next_input("input6.txt", &layer6)?;
    write_output("layer6.txt", layer6)?;

    Ok(())
}

#[must_use]
pub fn only_peel_layer4(buffer: &[u8]) -> Vec<u8> {
    let layer1 = ascii85_decode(buffer);
    layer4_decode(&layer1)
}

pub fn peel_layer4() -> Res<()> {
    // println!("Starting Layer 4");
    let buffer = read_input("input4.txt")?;
    let layer5 = only_peel_layer4(&buffer);

    write_next_input("input5.txt", &layer5)?;
    write_output("layer5.txt", layer5)?;

    Ok(())
}

#[must_use]
pub fn only_peel_layer3(buffer: &[u8]) -> Vec<u8> {
    let layer1 = ascii85_decode(buffer);
    layer3_decode(&layer1)
}

pub fn peel_layer3() -> Res<()> {
    // println!("Starting Layer 3");
    let buffer = read_input("input3.txt")?;
    let layer4 = only_peel_layer3(&buffer);

    write_next_input("input4.txt", &layer4)?;
    write_output("layer4.txt", layer4)?;

    Ok(())
}

#[must_use]
pub fn only_peel_layer2(buffer: &[u8]) -> Vec<u8> {
    let layer1 = ascii85_decode(buffer);
    layer2_decode(&layer1)
}

pub fn peel_layer2() -> Res<()> {
    // println!("Starting Layer 2");
    let buffer = read_input("input2.txt")?;
    let layer3 = only_peel_layer2(&buffer);

    write_next_input("input3.txt", &layer3)?;
    write_output("layer3.txt", layer3)?;

    Ok(())
}

#[must_use]
pub fn only_peel_layer1(buffer: &[u8]) -> Vec<u8> {
    let layer1 = ascii85_decode(buffer);
    layer1_decode(&layer1)
}

pub fn peel_layer1() -> Res<()> {
    // println!("Starting Layer 1");
    let buffer = read_input("input1.txt")?;
    let layer2 = only_peel_layer1(&buffer);

    write_next_input("input2.txt", &layer2)?;
    write_output("layer2.txt", layer2)?;

    Ok(())
}

pub fn peel_layer0() -> Res<()> {
    // println!("Starting Layer 0");
    let buffer = read_input("input.txt")?;
    let layer1 = ascii85_decode(&buffer);
    // let layer1 = ascii85_decode(buffer);

    write_next_input("input1.txt", &layer1)?;
    write_output("layer1.txt", layer1)?;

    Ok(())
}
