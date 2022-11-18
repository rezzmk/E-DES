# E-DES (Enhanced Data Encryption Standard)

## Summary
E-DES is a variant of DES that attempts to fix the main DES shortfalls, which are the key size and openness to potential attacks using knowledge about its S-Boxes.
in E-DES, keys are always 256 bits long and the S-Boxes are generated dynamically (16 boxes, instead of 8), from the keys.

Having Key-Dependent S-Boxes means we can significantly reduce the amount of processing needed to encrypt and decrypt messages, compared to DES. Essentially, provided we already have the S-Boxes generated and a set of 16 keys (derived from a main one), all we need is to use a Feistel Network approach, as explained [here](https://en.wikipedia.org/wiki/Feistel_cipher).

![image](https://user-images.githubusercontent.com/16304428/202696534-1c821202-3754-430b-ac95-f73d9b702d9e.png)

The process looks like the above image, stolen from the wikipedia page.

## Benchmarks
Using the provided `speed.c` code, we can compare the execution time of classic DES (in ECB mode), against E-DES, by running encryption and decryption on a 4KiB random buffer (from `/dev/urandom`), 100k times. An average of the best 10k results is then taken.

Below's a more thorough benchmark, using Rust's Criterion library. You can find the code for that in the Rust repo (for E-DES), [https://github.com/rezzmk/RustyEDES](https://github.com/rezzmk/RustyEDES), more specifically, [here](https://github.com/rezzmk/RustyEDES/blob/main/benches/edes.rs).

![image](https://user-images.githubusercontent.com/16304428/202697064-28cc4c08-c3a0-4cd1-aa72-e62c977b68af.png)

We can clearly see that E-DES is essentially twice as fast as DES. There is still some optimization work to do, my goal is to reach a 3x improvement over DES.

> Note: This is mostly academic work, I'm by no means remotely close to an expert in cryptography. It's just a stepping stone in my learning proggress.
