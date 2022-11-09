extern crate rand;
extern crate bigi;

use rand::Rng;
use bigi::Bigi;
use bigi::prime;


const BITS: usize = 1024;

const BYTES: usize = BITS / 8;
const ORDER: usize = BITS / 64;
type Block = [u8; BYTES];


#[no_mangle]
pub extern "C" fn genkeys(modulo: &mut Block,
                          privatekey: &mut Block,
                          publickey: &mut Block) {
    // Random generator
    let mut rng = rand::thread_rng();

    // Generate two prime numbers
    let (p1, p2) = _gen_two_primes(&mut rng);

    // Calculate module and Euler function
    let mod_ = p1 * &p2;
    let phi = (p1 - &Bigi::from(1)) * &(p2 - &Bigi::from(1));

    // Generate keys
    let (pvk, pbk) = _gen_key_pair(&mut rng, &phi);

    // Fill the buffers
    modulo.clone_from_slice(&mod_.to_bytes());
    privatekey.clone_from_slice(&pvk.to_bytes());
    publickey.clone_from_slice(&pbk.to_bytes());
}

#[no_mangle]
pub extern "C" fn encrypt(modulo: &Block,
                          publickey: &Block,
                          message: &Block,
                          result: &mut Block) {
    _rsa_power(modulo, publickey, message, result);
}

#[no_mangle]
pub extern "C" fn decrypt(modulo: &Block,
                          privatekey: &Block,
                          message: &Block,
                          result: &mut Block) {
    _rsa_power(modulo, privatekey, message, result);
}


fn _gen_two_primes<R: Rng + ?Sized>(rng: &mut R) -> (Bigi<ORDER>, Bigi<ORDER>) {
    let p1: Bigi<ORDER> = prime::gen_prime(rng,BITS / 2);
    loop {
        let p2: Bigi<ORDER> = prime::gen_prime(rng, BITS / 2);
        if p1 != p2 {
            return (p1, p2);
        }
    }
}


fn _gen_key_pair<R: Rng + ?Sized>(rng: &mut R, phi: &Bigi<ORDER>) -> (Bigi<ORDER>, Bigi<ORDER>) {
    loop {
        let pvk = Bigi::gen_random(rng, BITS, true) % phi;
        if pvk > Bigi::from(1) {
            let (gcd, pbk, _) = prime::euclidean_extended(&pvk, phi);
            if gcd == Bigi::from(1) {
                return (pvk, pbk);
            }
        }
    }
}


fn _rsa_power(modulo: &Block,
              key: &Block,
              message: &Block,
              result: &mut Block) {
    // Create integers
    let mod_ = Bigi::<ORDER>::from_bytes(modulo);
    let k = Bigi::<ORDER>::from_bytes(key);
    let msg = Bigi::<ORDER>::from_bytes(message);

    // Decrypting
    let res = msg.powmod(&k, &mod_);

    // Fill the result
    result.clone_from_slice(&res.to_bytes());
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() {
        let mut modulo: [u8; BYTES] = [0; BYTES];
        let mut privatekey: [u8; BYTES] = [0; BYTES];
        let mut publickey: [u8; BYTES] = [0; BYTES];

        genkeys(&mut modulo, &mut privatekey, &mut publickey);

        let message: [u8; BYTES] = [25; BYTES];
        let mut encrypted: [u8; BYTES] = [0; BYTES];

        encrypt(&modulo, &publickey, &message, &mut encrypted);

        let mut decrypted: [u8; BYTES] = [0; BYTES];

        decrypt(&modulo, &privatekey, &encrypted, &mut decrypted);

        assert_eq!(decrypted, message);
    }
}
