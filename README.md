# TP1 Crypto Engineering
Implementing  a simple, yet effective key-recovery attack on a reduced
version of the AES. This attack (taking the many names of “square”, “‘saturation” or
“integral” attack) is structural, in the sense that it does not depend on many details
of the AES, but rather on its overall SPN structure.

You can also find test of the function when running the q1,q2,q3 files.

The attack is implemented and tested in the file "aes128_attack.c" Also after performing the attacks different test will run automatically in order to test the attack on different Sbox and different xtime function.

## Compilation:

 ```sh
   make
   ```

## Running files:
```sh
./q1
./q2
./q3
./aes128_attack (after running the program please provide a number for how many times you need to perform the attack)
```

## cleaning the project:
```sh
make clean
```