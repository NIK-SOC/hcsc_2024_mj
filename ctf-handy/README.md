# Handy

Very easy crypto introductory challenge.

> I heard you are like an IT guy. So setting up a printer should be a piece of cake for you. How about crypto? I came up with an encryption algorithm, but lost the plaintext. Can you help me recover it? All I have is this: `440222077770222024{20_4033077706020660_906660777030_333066607770_60666022044405550330_704406660660330}`

## How to run

The image was tested with podman, but should work fine with docker as well.

0. Clone the repo and cd to the root folder of the particular challenge
1. Build the image: `podman build -t ctf-handy:latest .`
2. Run the image: `podman rm -f ctf-handy:latest; podman run --name ctf-handy -it --rm -p 1337:1337 -e BACKEND_PORT=1337 ctf-handy:latest`

Connect on port 1337.

<details>
<summary>Writeup (Spoiler)</summary>

So the flag was presumably given to us straight away. The `{`, `}` and `_` in plain sight suggest that. This probably also means that we are dealing with some simple substitution where the letters are replaced with certain numbers. We also get a backend we can play around with:

```
[steve@todo ctf-handy]$ nc localhost 1337
      ,-'""`-,               
,'        `.             
/    _,,,_   \            
/   ,'  |  `\/\\           
/   /,--' `--.  `           
|   /      ___\_            
|  | /  ______|             
|  | |  |_' \'|             
\ ,' (   _) -`|             
'--- \ '-.-- /             
______/`--'--<              
|    |`-.  ,;/``--._        
|    |-. _///     ,'`\      
|    |`-Y;'/     /  ,-'\    
|    | // <_    / ,'  ,-'\  
'----'// -- `-./,' ,-'  \/  
|   //[==]     \,' \_.,-\  
|  //      `  -- | \__.,-' 
// -[==]_      |   ____\ 
//          `-- |--' |   \
    [==__,,,,--'    |-'" 
---""''             |    
hjm          ___...____/     
    --------------------.
           ,.        --.|
          /||\        /||
           ||        /  |
           ||       /   |
            |      /    |

Beep, boop! Give me a message to encrypt: Hello world!123@
Here ya go: 440330555055506660 9066607770555030!123@
```

Cool, it let's us encrypt messages. First thing we may notice is that it really only encrypts the letters. The numbers and special characters are left untouched. We can also try to encrypt the same message again to see if the encryption is deterministic:

```
Beep, boop! Give me a message to encrypt: Hello world!123@
Here ya go: 440330555055506660 9066607770555030!123@
```

And it is. This means if we request all letters individually, we will know what each letter will translate to. Thankfully there is no need to do that individually, since we know that special characters and numbers are left untouched. We can just request the whole alphabet and numbers joined together using some special character:

```
Beep, boop! Give me a message to encrypt: a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/t/u/v/w/x/y/z
Here ya go: 20/220/2220/30/330/3330/40/440/4440/50/550/5550/60/660/6660/70/770/7770/77770/80/880/8880/90/990/9990/99990
```

That's good, we now have a lookup table. Since we know the flag format is `HCSC24{}`, we can indeed confirm that the beginning (`440222077770222024`) translates to `HCSC24{`.

- `440` -> `H`
- `2220` -> `C`
- `77770` -> `S`
- `2220` -> `C`
- `2` -> `2`
- `4` -> `4`
- `{` -> `{`

So letters are handled. But the number sequences are not using a fixed length, so we cannot just split the string into X-character long chunks and translate them. However we can notice that each number ends in a `0`. This means we can read a number until we encounter a `0` and then translate it. If we don't encounter a `0` at the end, we can write it down as-is. And if we encounter a non number, we can write it down as-is too. I prepared a solver script that does just that, you can find it in [poc.py](poc.py).

```
[steve@todo ctf-handy]$ python3 ./poc.py 
[+] Opening connection to localhost on port 1337: Done
Decrypted flag: hcsc24{a_german_word_for_mobile_phone}
[*] Closed connection to localhost port 1337
```

And we got the flag: `hcsc24{a_german_word_for_mobile_phone}`. This one is case insensitive.

### Another way, without the backend

One can just realize that the numbers used represent old phone keypad presses ([T9 SMS style](https://www.dcode.fr/t9-cipher)), where one keeps pressing the same key to get to the desired letter. The only difference is that the `0` key is used for spaces. So it's possible to use a T9 cipher to decrypt the message without the need for any lookup tables and whatnot. But of course the challenge becomes guessier that way.

**Note**: For the sake of clarity, one wouldn't call this encryption. It's a simple substitution cipher. I just used the term encryption to make the challenge a little less obvious at the beginning.

</details>