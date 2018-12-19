extern crate flate2;
extern crate byteorder;
#[macro_use] extern crate enum_primitive;
extern crate num;
extern crate crypto;
use num::FromPrimitive;
use crypto::digest::Digest;

struct HashingWrite<D, W> where D: Digest, W: Write {
    hasher: D,
    actual: W
}

impl <D, W> Write for HashingWrite<D, W> where D: Digest, W: Write {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.hasher.input(buf);
        self.actual.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.actual.flush()
    }
}

enum_from_primitive! {
#[derive(Debug, PartialEq)]
enum object_type {
	OBJ_BAD = -1,
	OBJ_NONE = 0,
	OBJ_COMMIT = 1,
	OBJ_TREE = 2,
	OBJ_BLOB = 3,
	OBJ_TAG = 4,
	/* 5 for future expansion */
	OBJ_OFS_DELTA = 6,
	OBJ_REF_DELTA = 7,
	OBJ_ANY,
	OBJ_MAX
}
}

macro_rules! println_stderr(
    ($($arg:tt)*) => { {
        let r = writeln!(&mut ::std::io::stderr(), $($arg)*);
        r.expect("failed printing to stderr");
    } }
);

use std::io::prelude::*;
use flate2::Compression;
use flate2::read::{ZlibDecoder, ZlibEncoder};
use byteorder::{ReadBytesExt, WriteBytesExt, BigEndian, LittleEndian};
use std::fs::File;

fn transform(do_enflate: bool) -> std::result::Result<(), std::io::Error> {
    let mut inp = std::io::stdin();
    let mut oup = HashingWrite { actual: std::io::stdout(), hasher: crypto::sha1::Sha1::new() };
    let mut buf = [0; 4];
    inp.read_exact(&mut buf)?;
    assert!(std::str::from_utf8(&buf) == Ok("PACK"), "invalid header");
    oup.write("PACK".as_bytes())?;

    assert!(inp.read_u32::<BigEndian>()? == 2, "unknown version");
    oup.write_u32::<BigEndian>(2)?;

    let count = inp.read_u32::<BigEndian>()?;
    oup.write_u32::<BigEndian>(count)?;

    println_stderr!("Object count: {}", count);
    for i in 0..count {
        let mut b = inp.read_u8()?;
        oup.write(&[b])?;
        let mut cont = b >> 7;
        let typ = (b >> 4) & ((1<<3)-1);
        let mut size: u64 = (b & ((1<<4) - 1)) as u64;
        let mut offset = 4;
        while cont == 1 {
            b = inp.read_u8()?;
            oup.write_u8(b)?;
            size += ((b as u64) & ((1<<7) -1))<<offset;
            offset += 7;
            cont = b >> 7;
        }
        let obj_type = object_type::from_u8(typ).expect("unknown type");
        println_stderr!("Object {}: type: {:?}, size={}", i, obj_type, size);
        if obj_type == object_type::OBJ_REF_DELTA {
            let mut base_sha = [0; 20];
            inp.read_exact(&mut base_sha)?;
            oup.write(&base_sha)?;
        } else if obj_type == object_type::OBJ_OFS_DELTA {
            let mut b = inp.read_u8()?;
            oup.write_u8(b)?;
            while b&(1<<7) != 0 {
                b = inp.read_u8()?;
                oup.write_u8(b)?;
            }
        }
        if do_enflate {
            let limited = &mut inp;
            //let mut oup2 = File::create(format!("{}.txt", i))?;
            // TODO: use larger buffer and seek back after read
            let mut dec = ZlibDecoder::new_with_buf(limited, vec![0; 1]);
            std::io::copy(&mut dec, &mut oup)?;
            assert!(dec.total_out() == size, "size mismatch: {} != {}");
            // println!("i={}, o={}", dec.total_in(), dec.total_out());
        }
        else {
            let limited = (&mut inp).take(size);
            let mut enc = ZlibEncoder::new(limited, Compression::Default);
            std::io::copy(&mut enc, &mut oup)?;
            assert!(enc.total_in() == size, "enc size mismatch");
        }
        /*let mut x = Vec::new();
        inp.read_to_end(&mut x)?;
        println!("count rem: {}", x.len());*/

    }
    let mut sha1sum = [0; 20];
    inp.read_exact(&mut sha1sum)?;
    //oup.write(&sha1sum)?;
    let mut newsum = vec![0; oup.hasher.output_bytes()];
    oup.hasher.result(&mut newsum);
    oup.actual.write(&newsum[..])?;
    let remaining = inp.bytes().count();
    if remaining == 0 {
        return std::result::Result::Ok(());
    } else {
        return std::result::Result::Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, format!("Expected EOF, got {} remaining bytes", remaining)));
    }
}
fn main() {
    let do_deflate = std::env::args().len() > 1;
    transform(!do_deflate).expect("IO Error");
    //std::io::copy(&mut inp, &mut decoder).expect("could not copy");
}
