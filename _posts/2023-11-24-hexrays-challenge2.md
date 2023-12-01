---
title: "Madame De Maintenon’s Cryptographic Pursuit – Unmasking the Traitors"
excerpt: "Hex-rays has published a second CTF where we have to uncover the location of the traitors in the story of Madame de Maintenon (the IDA Lady)"
categories:
    - Reverse Engineering
    - CTF
tags:
    - Python
    - ELF
    - Linux
    - Binary Analysis
    - Binary Ninja
last_modified_at: 2023-11-24-17:40:00
toc: true
---

<figure>
<a href="/assets/images/hex-ray-challenge2/jiu-detective.jpg"><img src="/assets/images/hex-ray-challenge2/jiu-detective.jpg"></a>
<figcaption>Detective Jiu has found a few clues, will be able to solve the riddle...?</figcaption>
</figure>

Following my previous post on a Hex-Rays challenge ([hexrays-challenge-triton](https://farena.in/symbolic%20execution/triton/hexrays-challenge-triton/)), my friend Robert Yates informed me about a new challenge from Hex-Rays, which was shared in this [Tweet](https://twitter.com/HexRaysSA/status/1724794320925098477). Intrigued, I decided to take on the challenge as a way to spend a boring weekend. In this write-up, I will illustrate how I successfully tackled the challenge step by step, utilizing various tools such as [Ghidra](https://ghidra-sre.org/), [Binary Ninja](https://binary.ninja/), [GDB-Gef](https://github.com/hugsy/gef), and a touch of [Triton](https://triton-library.github.io/).


## Authors

* Eduardo Blázquez

## The Challenge

For this challenge, we are once again confronted with a 64-bit architecture ELF binary. It is dynamically linked and has a size of 31 kilobytes. To obtain this information, we can use the `file` command:

```console
$ file madame
madame: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=ab32392967c6b82b041dc3389df9e226916506ed, for GNU/Linux 3.2.0, stripped
```

For this challenge, I began the analysis using the *Ghidra* disassembler. However, I also applied the same analysis using *Binary Ninja*, so most of the screenshots will be from the latter tool.

Let's run the program to examine what we are dealing with. In case it prompts for input, you can simply enter anything as a basic test:

<figure>
<a href="/assets/images/hex-ray-challenge2/1.png"><img src="/assets/images/hex-ray-challenge2/1.png"></a>
<figcaption>Running the binary with an incorrect input.</figcaption>
</figure>

From the previous image, it's evident that the challenge sets the stage with some context and a brief narrative. Following the tradition of old video games, our task is to craft our own adventure and discover the right actions to navigate through the challenge and solve the riddle.

As a small spoiler, I'll mention that four correct inputs are required to complete the challenge. Consequently, I'll structure this post into sections, each dedicated to one of the inputs. But before delving into that, let's commence the analysis of the challenge using Binary Ninja.

### Analyzing the Challenge with Binary Ninja

This marks my inaugural experience with Binary Ninja, and I must say, it has proven to be remarkably user-friendly and intuitive. To initiate the analysis, one simply needs to launch the `binaryninja` executable, navigate to `File`, and select `Open`. Subsequently, we choose the `madame` binary for analysis. Binary Ninja adeptly identifies the `main` function, serving as our starting point for the analysis.

In my case, I've taken the liberty of renaming most variables and functions. Consequently, throughout this post, I'll be referencing functions by their addresses, facilitating seamless navigation with any analysis tool. For this exploration in Binary Ninja, I'll be utilizing the `High Level IL` representation.

<figure>
<a href="/assets/images/hex-ray-challenge2/2.png"><img src="/assets/images/hex-ray-challenge2/2.png"></a>
<figcaption>Main function from madame binary.</figcaption>
</figure>

As mentioned earlier, the binary isn't particularly large, and to successfully navigate the challenge, we must supply four inputs. In the preceding image, four calls to check functions are evident (located at addresses `0x004011e6`, `0x004011ed`, `0x004011f4`, and `0x004011fb`). The `main` function concludes with a jump to a final function at address `0x00401204`.

#### First steps at the local library

The challenge begins with the following prompt: *You have heard that a rival historian recently discovered a copy of a chapter of the diary of Madame de Maintenon at the local library.* Our initial task unfolds at the local library, where we must discern the next course of action. By double-clicking on the first called function, we'll delve into the analysis of the function located at address `0x00401894`.

##### First part of the function

Let's examine the initial segment of the function. This function is obfuscated, and both in disassembly view and decompiler view, discerning its purpose proves challenging:

<figure>
<a href="/assets/images/hex-ray-challenge2/3.png"><img src="/assets/images/hex-ray-challenge2/3.png"></a>
<figcaption>First part of the function 0x00401894.</figcaption>
</figure>

Following the analysis and utilizing GDB, it becomes apparent that the value to be stored in the variable `rdx_2` is derived from the length of a buffer read with a call at address `0x004018fc`. Towards the end of the code, there's a check to ascertain whether this length is less than 18 or equal to 18.

This code ultimately verifies that the length is neither less than 18 nor equal to 18, indicating that we are in search of a string longer than 18 characters.

##### Small stop at `read` function

Now, let's take a preliminary look at the `read` function located at address `0x00402370`. While we won't delve into the details at this point, our focus is to gain an initial understanding of what transpires with the `buffer` supplied as a parameter.

<figure>
<a href="/assets/images/hex-ray-challenge2/4.png"><img src="/assets/images/hex-ray-challenge2/4.png"></a>
<figcaption>Read function at address 0x00402370.</figcaption>
</figure>

The function starts with two checks that internally involve `__builtin_memcpy`. These two `memcpy` instances have been generated by Binary Ninja after recognizing the following pattern as a `memcpy`:

```assembly
00402382  488d35174b0000     lea     rsi, [rel second_public_key]  {"678dcc64ccf7c29ffe64838a80196bd9…"}
00402389  488d3d10540000     lea     rdi, [rel first_public_key]  {"8e449627141446d50a3bfab5d9fc0d58…"}
00402390  b940000000         mov     ecx, 0x40
00402395  f348a5             rep movsq qword [rdi], [rsi]  {0x0}
```

However, we will skip over that portion of the code and direct our attention to the subsequent loop. This loop is designed to read a maximum of 200 bytes into the input-provided buffer. It restricts acceptance to characters whose representation is lower than `0x7e`, essentially allowing only printable characters.

In essence, we have a secure reading function for a buffer supplied as a parameter to the function.

##### Second part of the function

Now, let's proceed with the initial check function. The first segment of the function involved an obfuscated `strlen`. The subsequent image illustrates the second part:

<figure>
<a href="/assets/images/hex-ray-challenge2/5.png"><img src="/assets/images/hex-ray-challenge2/5.png"></a>
<figcaption>Second part of the function 0x00401894.</figcaption>
</figure>

It's noteworthy that initially, the variable `rsi_1` points to the string *"Head to the library"*, while the variable `rdi_1` points to the buffer. Subsequently, a while loop systematically compares them character by character using the following lines:

```
equal_18 = temp2_1 == temp3_1
```

The loop terminates when the variable `equal_18` becomes equal to `0`, indicating that the characters being compared are different. This function sets the variable `i.b` and checks if the value is equal to zero. This behavior aligns with that of `strcmp`, a function that compares two strings and returns `0` when the strings are identical.

In essence, we have two functions in an obfuscated representation: `strlen` and `strcmp`. The comparison is performed against the string *"Head to the library"*.

##### Third part of the function

As we conclude this function, we begin encountering calls to `AES` functions. `AES` is a symmetric block cipher that employs the same key for both encryption and decryption.

<figure>
<a href="/assets/images/hex-ray-challenge2/6.png"><img src="/assets/images/hex-ray-challenge2/6.png"></a>
<figcaption>Third part of the function 0x00401894.</figcaption>
</figure>

In this segment of the function, the 19 bytes from the input (the length from the previous string) serve as the key. This key is then used to decrypt a buffer of 0x600 bytes.

<figure>
<a href="/assets/images/hex-ray-challenge2/7.png"><img src="/assets/images/hex-ray-challenge2/7.png"></a>
<figcaption>First decrypted buffer.</figcaption>
</figure>

It appears that the correct flag is utilized to decrypt another string, likely the next part of the riddle!

#### Finishing the First Check

We will attempt to provide the string *"Head to the library"* as input and see if we can glean more information from the challenge.

<figure>
<a href="/assets/images/hex-ray-challenge2/8.png"><img src="/assets/images/hex-ray-challenge2/8.png"></a>
<figcaption>Using the first flag.</figcaption>
</figure>

As observed, providing the string yields the next part of the story and reveals the string *01000010* as the first clue for the riddle. Let's retain this data as it may prove useful for the rest of the challenge.

- **First Flag:** *"Head to the library"*
- **First Clue:** 01000010

#### The Book that Fell from the Shelf

We concluded the previous section with the text: *"The page was lying on the shelf in the open, maybe it fell from somewhere. You see a few more loose pages sticking out of some other books around you. What happened here?"*

As the story progresses, so shall we. Let's directly transition to the second check function, located at address `0x00401a50`. Once again, we will break down the analysis step by step.

##### First Part of the Function

The pivotal segment of this function is its initial part, where we once again encounter the reading of a buffer and a subsequent call to a comparison function.

<figure>
<a href="/assets/images/hex-ray-challenge2/9.png"><img src="/assets/images/hex-ray-challenge2/9.png"></a>
<figcaption>First part of the function 0x00401a50.</figcaption>
</figure>

Here, the program prompts us with *"What do you do?"*, and immediately after the `read`, there is a call to a function I've named `cmpSecondFlag`, found at the address `0x00402560`. Let's proceed to analyze that function.

##### Analysis of Comparison Function

Let's delve into the function and understand how the second flag is examined.

<figure>
<a href="/assets/images/hex-ray-challenge2/10.png"><img src="/assets/images/hex-ray-challenge2/10.png"></a>
<figcaption>Comparison function at address 0x00402560.</figcaption>
</figure>

To begin, the function copies two byte arrays into local buffers, one labeled `xor_buffer` and the other `cmp_buffer`. The representation of `cmp_buffer` in this display is not complete, as the disassembler reveals an instruction that copies a final byte:


```
004025b6  c644241c9f         mov     byte [rsp+0x1c {var_12c}], 0x9f
```


Applying a final fix, here are the buffers:

```
xor_buffer = "\x44\x36\x63\xc8\x1c\x28\x84\xa0\x8d\x3a\x2f\x39\xf7\xee\x92\x4f\xa7\xd5\xd3\x6c\x81\x8c\x4f\xcd\x37\x17\x89\xfc\xf9\x1c\xc2\x1b"
cmp_buffer = "\x07\x5e\x06\xab\x77\x08\xe6\xcf\xe2\x51\x5c\x19\x98\x80\xb2\x3b\xcf\xb0\xf3\x02\xe4\xf4\x3b\xed\x44\x7f\xec\x90\x9f"
```

Then, using `strncpy`, the buffer given as a parameter is copied into a local buffer. Subsequently, we encounter two loops: the first of them performs an XOR operation on the provided buffer with the first buffer (`xor_buffer`), and the second loop is employed to compare the resulting buffer with the second copied buffer (`cmp_buffer`). This reveals a straightforward encryption mechanism based on XOR operations with a hardcoded buffer.

To retrieve the final flag, we can utilize the following Python script:

```python
a = b"\x44\x36\x63\xc8\x1c\x28\x84\xa0\x8d\x3a\x2f\x39\xf7\xee\x92\x4f\xa7\xd5\xd3\x6c\x81\x8c\x4f\xcd\x37\x17\x89\xfc\xf9\x1c\xc2\x1b"
b = b"\x07\x5e\x06\xab\x77\x08\xe6\xcf\xe2\x51\x5c\x19\x98\x80\xb2\x3b\xcf\xb0\xf3\x02\xe4\xf4\x3b\xed\x44\x7f\xec\x90\x9f"

flag = ""
for i in range(len(b)):
    c = chr(a[i] ^ b[i])
    flag += c

print("The final flag is: %s" % (flag))
```

Running the script gives us the next output:

```
The final flag is: Check books on the next shelf
```

So we obtained the second flag! 

#### Second Part of the Function

Before delving into the second flag, let's conclude the analysis of the second comparison function.

<figure>
<a href="/assets/images/hex-ray-challenge2/11.png"><img src="/assets/images/hex-ray-challenge2/11.png"></a>
<figcaption>Second part of the function 0x00401a50.</figcaption>
</figure>

For now, we'll skip over the copy from `second_buffer` to `encrypted_buffer` and the calls to `keyMethod` since we'll explore them at the end of this post. Once again, we observe that the user's buffer is employed as an AES key to decrypt another buffer, likely the subsequent buffer to be presented to the user.

#### Finishing the Second Check

We will utilize the message as a flag for the second part of the challenge and observe the outcome.

<figure>
<a href="/assets/images/hex-ray-challenge2/12.png"><img src="/assets/images/hex-ray-challenge2/12.png"></a>
<figcaption>Entering the second flag and obtaining the third message.</figcaption>
</figure>

It appears that the sentence *"Check books on the next shelf"* serves as the correct flag, leading us to acquire a third message. Once again, let's retain the flag and the new clue:

- **Second Flag:** *"Check books on the next shelf"*
- **Second Clue:** 00110111


#### Where are the rest of the clues?

<figure>
<a href="/assets/images/hex-ray-challenge2/jiu-detective2.png"><img src="/assets/images/hex-ray-challenge2/jiu-detective2.png"></a>
<figcaption>Detective Jiu has found already two clues, will be able to find the rest?</figcaption>
</figure>

We have reached the halfway point of this trip, and we will continue with the third check. Let's dive straight into the function and discover what kind of check we have to solve this time.

<figure>
<a href="/assets/images/hex-ray-challenge2/13.png"><img src="/assets/images/hex-ray-challenge2/13.png"></a>
<figcaption>Beginning of the third comparison function at the address 0x00401cd0.</figcaption>
</figure>

This function is nearly identical to the second comparison. It begins by reading a buffer of 200 characters and then immediately jumps to the comparison function. If the comparison returns 0, the control flow will redirect to a `puts` function followed by an `exit`, resulting in the printing of the following text: *"Where could the third page possibly be? How could your fellow historian have been so careless with such a priceless artifact?"* Therefore, we should make every effort to prevent the comparison from returning 0.

##### Analysis of the comparison function

The third check is located at the address *0x00401300*. In this function, a character-by-character comparison takes place, accompanied by a straightforward mathematical operation for each character. The complete function is illustrated in the following images:

<figure>
<a href="/assets/images/hex-ray-challenge2/14.png"><img src="/assets/images/hex-ray-challenge2/14.png"></a>
<a href="/assets/images/hex-ray-challenge2/15.png"><img src="/assets/images/hex-ray-challenge2/15.png"></a>
<a href="/assets/images/hex-ray-challenge2/16.png"><img src="/assets/images/hex-ray-challenge2/16.png"></a>
<figcaption>Third comparison function from the challenge.</figcaption>
</figure>

To solve this, all we need to do is apply the inverse operation for each line. You can use the following Python script to simplify the process:

```python
flag = ""
flag += chr(0x62 - 0xf & 0xFF)
flag += chr(0x5e ^ 0x3b & 0xFF)
flag += chr(0x9a - 0x39 & 0xFF)
flag += chr(0x4a ^ 0x38 & 0xFF)
flag += chr(0x17 ^ 0x74 & 0xFF)
flag += chr(0x53 ^ 0x3b & 0xFF)
flag += chr(0x23 - 3 & 0xFF)
flag += chr(0x31 + 0x43 & 0xFF)
flag += chr(0x71 - 9 & 0xFF)
flag += chr(0x71 - 0xc & 0xFF)
flag += chr(0x7a - 0x5a & 0xFF)
flag += chr(0x52 + 0x10 & 0xFF)
flag += chr(0xea - 0x7b & 0xFF)
flag += chr(0x46 ^ 0x29 & 0xFF)
flag += chr(0xec + 0x7f & 0xFF)
flag += chr(0x22 ^ 2 & 0xFF)
flag += chr(0xba - 0x54 & 0xFF)
flag += chr(0xdf ^ 0xb0 & 0xFF)
flag += chr(0xd8 - 0x66 & 0xFF)
flag += chr(0xb3 + 0x6d & 0xFF)
flag += chr(0x43 ^ 0x20 & 0xFF)
flag += chr(0xdb + 0x91 & 0xFF)
flag += chr(0x8d + 0xe8 & 0xFF)
flag += chr(0x6e + 0xf7 & 0xFF)
flag += chr(0xa3 - 0x30 & 0xFF)
flag += chr(0xed + 0x13 & 0xFF)
flag += chr(0xc3 + 0x3d & 0xFF)
flag += chr(0x93 + 0x6d & 0xFF)
flag += chr(0x8a + 0x76 & 0xFF)
flag += chr(0x7e + 0x82 & 0xFF)
flag += chr(0x2a - 0x2a & 0xFF)
flag += chr(0x5c ^ 0x5c & 0xFF) 
print(flag)
```

But if we are using Ghidra, we will be able to see the solution directly in the decompiler:

<figure>
<a href="/assets/images/hex-ray-challenge2/17.png"><img src="/assets/images/hex-ray-challenge2/17.png"></a>
<figcaption>Decompiler from Ghidra showing the solution byte by byte.</figcaption>
</figure>

Running the python script:

```console
$ python third_flag.py
Search the book for clues
```

So, it looks like we have to continue looking for clues in the book, and probably our third flag will be *Search the book for clues*.

##### End of third check function

This function ends in the same way than the second, it uses the flag for decrypting a big buffer:

<figure>
<a href="/assets/images/hex-ray-challenge2/18.png"><img src="/assets/images/hex-ray-challenge2/18.png"></a>
<figcaption>Final part of function at the address 0x00401cd0.</figcaption>
</figure>


##### Finishing the third check function

Now, let's attempt to solve the third check function using the flag we obtained earlier, *Search the book for clues*, and observe the results:

<figure>
<a href="/assets/images/hex-ray-challenge2/19.png"><img src="/assets/images/hex-ray-challenge2/19.png"></a>
<figcaption>Entering the third flag, and obtaining the fourth message.</figcaption>
</figure>

It looks like we obtained a correct flag, and with that the fourth message and the third clue.

Third flag: *"Search the book for clues"*

Third clue: 10110010.

#### End of the world! (as we know it)

We are nearing the end of this journey, with just one more flag to obtain. The function at address 0x00401f50 resembles the previous ones – it prompts us for our flag and stores it in a buffer with a size of 200 characters. Once again, we encounter a `puts` message asking, *"What do you do?"*, followed by a call to the `read` function from the binary. After this, the final check function at address 0x004016f0 is invoked. This sequence is illustrated in the following image:

<figure>
<a href="/assets/images/hex-ray-challenge2/20.png"><img src="/assets/images/hex-ray-challenge2/20.png"></a>
<figcaption>Beginning of the function 0x00401f50, last check.</figcaption>
</figure>

Now we will jump to the comparison function, in order to retrieve the last flag!

##### Retrieving the last flag

The last function at the address 0x004016f0 will make a very simple comparison using `strncmp` from our buffer, and another buffer decrypted using `AES`, we can see it in the next picture:

<figure>
<a href="/assets/images/hex-ray-challenge2/21.png"><img src="/assets/images/hex-ray-challenge2/21.png"></a>
<figcaption>Function 0x004016f0, last comparison from the program.</figcaption>
</figure>

While we can retrieve the AES key, and write a program to decrypt the last flag, we will go with the easy way, and we will use `gdb` debugger in order to retrieve the parameters from the `strncmp` function. We can set a breakpoint in the address 0x0040179e, and enter the previous flags to reach to the last one.

<figure>
<a href="/assets/images/hex-ray-challenge2/22.png"><img src="/assets/images/hex-ray-challenge2/22.png"></a>
<figcaption>Running gdb-gef for obtaining the last flag.</figcaption>
</figure>

If we introduce the correct flags, and we reach the breakpoint, we will see one of the parameters with the correct flag. Since I do not have the fourth flag I will just enter the next string *"This is a test!"*, and as we can see in the next image, we obtain the final flag!

<figure>
<a href="/assets/images/hex-ray-challenge2/23.png"><img src="/assets/images/hex-ray-challenge2/23.png"></a>
<figcaption>Obtaining the last flag!</figcaption>
</figure>

And we obtain the last flag which is the string *"Turn over the page"*, and with this we will have the four flags, and the challenge is over, we can finally *Praise the Sun*.


<figure>
<a href="/assets/images/hex-ray-challenge2/praise_the_sun.jpg"><img src="/assets/images/hex-ray-challenge2/praise_the_sun.jpg"></a>
</figure>

Now we will enter the last flag into our program, and then retrieve the solution as expected in all this kind of challenges. So let's go with it!

<figure>
<a href="/assets/images/hex-ray-challenge2/24.png"><img src="/assets/images/hex-ray-challenge2/24.png"></a>
</figure>

<figure>
<a href="/assets/images/hex-ray-challenge2/wtf.jpeg"><img src="/assets/images/hex-ray-challenge2/wtf.jpeg"></a>
</figure>


WTF happened? We obtained the four flags, but it's telling us the next:

*What does this mean? You've worked so hard but yet still don't have the information you seek? What now?*
*You have all four pages your rival claimed to have found, and yet are no closer to the truth.*
*After several hours of fruitlessly searching for meaning in the messages, you give up and turn to leave in defeat.*

So it looks like we were not right, or at least completely right with the flags. In any case, let's keep this fourth flag and the last clue.

Fourth flag: *"Turn over the page"*

Fourth clue: 00000101.

#### The Real End

In this point is where we realize that we didn't finish the challenge, and it was too easy for being a reverse engineering challenge. We will now start our analysis with the last function, and from this last function we will dig into other functions that will provide us with the final answer. The analysis now will start with the function at the address 0x00402640.

<figure>
<a href="/assets/images/hex-ray-challenge2/25.png"><img src="/assets/images/hex-ray-challenge2/25.png"></a>
</figure>

We have here three variables that are checked to be different to 0, `CHECK1`, `CHECK2` and `CHECK3`. We will have to look where these variables are set to a value different to 0. We find the write cross-reference in the function at the address 0x004021e0.

<figure>
<a href="/assets/images/hex-ray-challenge2/26.png"><img src="/assets/images/hex-ray-challenge2/26.png"></a>
</figure>

In the previous image we have the function that will modify those global variables, but how these global variables are set to 1?. First of all a `memcmp` must return the value 0 (two buffers are the same). Let's analyze a little bit more. The function starts retrieving two big numbers, one is: 

```
8e449627141446d50a3bfab5d9fc0d58c6b9f64630d011cb5c831c5989402de1f553ae70c9f8ddefb42f001e553fe7d852bb08cec6efebe490eb40c91955b020159c66836a5d7d5364da7cab32deff4ea6ec1e41bdda7b7c298da68d4be77e4750bf86d5d24ed67511bb37a105bc4da0e3ec0cd4960a1ae2986fd402101061d290f292030bcf21a38d77dbde760d01a3faaa210e34a4e471fa0eac5518d2f01faa70659f582a9e211ff6b438b0bb1abb49f4bb458acefd7bbcc8f68ed7cd121bf16ad1d5e0cd5384b4e3441de7d5ec3c10c52ed9263ffe3c6af5ba508f0b774e932dece2f84c053f972ca31a68c1cd13668db6adb3e2320c93a0b06ae1737ad9
```

And the other is the value `3`. These are used as the *module* and the *exponent* for generating a RSA public key. Then a variable called *global_user_buffer* is encrypted with that RSA public key, and compared with a buffer, the beginning of the buffer is presented in the next picture:

<figure>
<a href="/assets/images/hex-ray-challenge2/27.png"><img src="/assets/images/hex-ray-challenge2/27.png"></a>
</figure>

For those who do not understand why it is almost impossible to decrypt the buffer, in the next link you can find the theory of [public key cryptography](https://en.wikipedia.org/wiki/Public-key_cryptography).

But two questions, where does the buffer *global_user_buffer* comes, and where this *keyMethod* is called from?

If we follow the cross references from *global_user_buffer*, we can see that this value is written in the first function for the flag check (we called it *firstFlagCheck* at the address 0x00401870). This value is exactly the first buffer the user introduced, we can see it in the next image:

<figure>
<a href="/assets/images/hex-ray-challenge2/28.png"><img src="/assets/images/hex-ray-challenge2/28.png"></a>
</figure>

Also, we can see from the previous image that the *global_user_buffer* is written once the check from the first flag is correct, so the flag *Head to the library* is correct, but it looks like the comparison after the RSA encryption is not working.

And now where is called this `keyMethod` function? We check the references with Binary Ninja, and we can see that this function is called always at the end of each function used to check each flag:

<figure>
<a href="/assets/images/hex-ray-challenge2/29.png"><img src="/assets/images/hex-ray-challenge2/29.png"></a>
</figure>

##### Understanding the comparisons flow

So we have a comparison that works more or less like the next pseudo-code:

```
module = 0x8e449627141446d50a3bfab5d9fc0d58c6b9f64630d011cb...
exponent = 3
public_key = RSA_PUBLIC_KEY(module, exponent, 0)

final_buffer = 0x7d9e6b093218080a5a34349c0db3c3c986b102d9...
encrypted_buffer = RSA_ENCRYPT(user_buffer, public_key)

is_buffer_correct = final_buffer == encrypted_buffer
```

If we analyze the program, we can go to three different points. The first one is the `read` function, where we were able to see the next code:

<figure>
<a href="/assets/images/hex-ray-challenge2/30.png"><img src="/assets/images/hex-ray-challenge2/30.png"></a>
</figure>

We had two comparisons and two conditional codes, that in case the global variables `CHECK2` and `CHECK3` are different to 0, they would replace the `module` from the previous pseudo-code, with two other different values (two different modules), next we have those two different numbers:

```
678dcc64ccf7c29ffe64838a80196bd90b2d6247e4d712cb60c6a4a3a09ac088b9d1b19518451ce1a295ca6134a65cb5176083849e11cea23cf5d6c303ee95d02f1af26f741131d03c4e86866e26b09069c0be5c718298ed1cfc01493d78520957e25c2d921f6b6518ef5ef608e209d4d9ad613fdb6a2eb4156c906c89583949ca076312c6a258f14794ee852a61f27fe2a6b17b1ea85de3e40a2636fc4430e920ed8dc688aebdb6f5e63140f7844f3597c82704545c308a36e20eb94e00b35eaee860835c2f213956bfb79bb17d9b914524a5b133be5af4667ca0710420ca6bd90c28761ba1d52ed7d83d927245f53d45b35f2f1729ff602271abb0ebf7ce5b
```

And the next one:

```
b1b751bdef5727862c0f6bddcaa9802722b2499c760e02d7bb4c38629339194431dbeb41a6222e01dca0fa8e792562ccc9bcf9c57549037a44eb4945daf4440ac4f4aab3bdf1566a3961c88e8cdb925870e68e9064354568335eefc62344fdac06593bdd8c4dc63c0af932f5dab986919f4acb4b602896ba1896c3d0bc00a9bd6408a85e3e8766bfd44af0ab151d3537c2b2955eebe9cbcd6871146524253e14e374cdda166e8b298932695c774ab8f8ac332a92fa49c91f65ce1a01b12e3d056990c954a3c6fa9346a67819bbc76d9cfbebff9810841810ccfdd3a3773cc24ead32665b8e667b1b0b817f0bb3d8d7ca17342e6b2d024762e2ecbf897af9cb15
```

So it looks like in total, the program contains 3 modules that can be used to generate 3 RSA public keys.

Now we can move to the functions at the addresses 0x00401a50 (`secondFlagCheck`) and to the function at the address 0x00401cd0 (`thirdFlagCheck`). In `secondFlagCheck` we had the next code:

<figure>
<a href="/assets/images/hex-ray-challenge2/31.png"><img src="/assets/images/hex-ray-challenge2/31.png"></a>
</figure>

The encrypted buffer that was used for the comparison is replaced by another buffer. And if we move to the `thirdFlagCheck`, we can see the next:

<figure>
<a href="/assets/images/hex-ray-challenge2/32.png"><img src="/assets/images/hex-ray-challenge2/32.png"></a>
</figure>

We have the same code as before, the encrypted buffer is replaced by a third buffer. We have the next:

* Three modules for RSA keys.
* Three encrypted buffers used for comparison
* An exponent with value 3

We can see the flow of these checks in the next scheme:

<figure>
<a href="/assets/images/hex-ray-challenge2/flow.png"><img src="/assets/images/hex-ray-challenge2/flow.png"></a>
</figure>


So although we only have one function for checking, we use different modules each time, and the user buffer is compared against three different encrypted buffers.

##### Chinese Remainder Theorem

We now have to solve a big problem which is finding what is the correct input we need for the first flag, having different RSA modules for public keys, and three different encrypted messages. 

Here we will use an attack for RSA known as **Low Exponent Attack**. While I am not a crypto expert, we will see in what this attack is based. So if we have three encrypted messages with the next shape:

```
c1 = c (mod p1)
c2 = c (mod p2)
c3 = c (mod p3)
```

We can recover this `c` value, using the Chinese Remainder Theorem. Given the fact that both encrypted messages (`cX`) and the modulus from the equations (`pX`) are coprimes to each other.

In our case `c` is the value m^3, where `m` is our message we want to recover, and recover `m` will be easy since it will be finding the cube root from `c`.

You can find more information about this attack in the next [post](https://yurichev.org/RSA_low/) by Dennis Yurichev, highly recommended.

So we will have to solve the equations system to retrieve m^3, and then apply the cube root in order to retrieve the message decrypted, for the solution I have adapted the code from the next [post](https://asecuritysite.com/ctf/rsa_ctf02). I just added the modules from our binary, and the encrypted buffers. You can find next the python code:

```python
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto import Random
import Crypto
import sys
import libnum

e=3
n1=0x8e449627141446d50a3bfab5d9fc0d58c6b9f64630d011cb5c831c5989402de1f553ae70c9f8ddefb42f001e553fe7d852bb08cec6efebe490eb40c91955b020159c66836a5d7d5364da7cab32deff4ea6ec1e41bdda7b7c298da68d4be77e4750bf86d5d24ed67511bb37a105bc4da0e3ec0cd4960a1ae2986fd402101061d290f292030bcf21a38d77dbde760d01a3faaa210e34a4e471fa0eac5518d2f01faa70659f582a9e211ff6b438b0bb1abb49f4bb458acefd7bbcc8f68ed7cd121bf16ad1d5e0cd5384b4e3441de7d5ec3c10c52ed9263ffe3c6af5ba508f0b774e932dece2f84c053f972ca31a68c1cd13668db6adb3e2320c93a0b06ae1737ad9
c1=0x7d9e6b093218080a5a34349c0db3c3c986b102d98c14cda70bb241b5a838394cabb132d9789deade34ca28a3967b77e1da56c428f40c7d601be4ae2cb98fee1b8c8dcb22eeedfc4bb6462a9c24d4fd45854d5dc04f58e5bc701b6cac9ed6d02ba05b8935c7fe26f84086cd49d0d66bcb6575aaa791f81be84768b5961f3ff105ee5ec56fcdaf46a1c7369dd4d58ecd2ce28c7abb0f35e0dc0752a11b8916969af491f6baafbffe0877fae05ba18d6daf385bccd88951d72e6b8a4ccca00fa3bf451f512eaebf8a20baad68e04caae68b8fa1dbcbd1ae377b5cf26a7c90b6348569036d76d838b5bcd0e6c423581265edccf32279a0b629fab0fcd485a38b4205
n2=0x678dcc64ccf7c29ffe64838a80196bd90b2d6247e4d712cb60c6a4a3a09ac088b9d1b19518451ce1a295ca6134a65cb5176083849e11cea23cf5d6c303ee95d02f1af26f741131d03c4e86866e26b09069c0be5c718298ed1cfc01493d78520957e25c2d921f6b6518ef5ef608e209d4d9ad613fdb6a2eb4156c906c89583949ca076312c6a258f14794ee852a61f27fe2a6b17b1ea85de3e40a2636fc4430e920ed8dc688aebdb6f5e63140f7844f3597c82704545c308a36e20eb94e00b35eaee860835c2f213956bfb79bb17d9b914524a5b133be5af4667ca0710420ca6bd90c28761ba1d52ed7d83d927245f53d45b35f2f1729ff602271abb0ebf7ce5b
c2=0x67512e54ff9cd853ab645a69ec8f64009fad60eee84ce5d9a5db8754813d5f9c9c038da9476caf9f1b543a289613d02a4addc2948b94a965b2dce0cb93b771236a7f1cf879c86c4f9c07f26bbbd773a7d9edf6b3981e4f96f355ecdd7407506672e5025ec2c915ca1d5f35d1ccc35679aff91b833a07fc6bfad06c9acf053870e5f52d3dc8f1757355ea4c8da81d88c37d4b68ebe50274566cb683c19cf5fa6d8851f92d9f9abd5fd0cbb67551c3fa2018555b9a2995da96443d9746399fbb86aca121fe4ebe97d8468db22a0bd087a1e3fc289c5633157bdc0bcd677faa26b1fa4be84285a408edd28e48ab47535465dce281111b0b70855cae188aa6fdaa85
n3=0xb1b751bdef5727862c0f6bddcaa9802722b2499c760e02d7bb4c38629339194431dbeb41a6222e01dca0fa8e792562ccc9bcf9c57549037a44eb4945daf4440ac4f4aab3bdf1566a3961c88e8cdb925870e68e9064354568335eefc62344fdac06593bdd8c4dc63c0af932f5dab986919f4acb4b602896ba1896c3d0bc00a9bd6408a85e3e8766bfd44af0ab151d3537c2b2955eebe9cbcd6871146524253e14e374cdda166e8b298932695c774ab8f8ac332a92fa49c91f65ce1a01b12e3d056990c954a3c6fa9346a67819bbc76d9cfbebff9810841810ccfdd3a3773cc24ead32665b8e667b1b0b817f0bb3d8d7ca17342e6b2d024762e2ecbf897af9cb15
c3=0x1b48f3de27db0a80ffa291b161ffe9ca6cee79db559c8047579920cb23c130311a366f8561ee5966ee0a72293671c3587074011759de78b837b676303c0179db6cfc6e5d883835738249bc61f8ebc6a6cade877eee27f2f74c510f9ac6c723e53f76a8d45db5d6918cee530db1a2102781a481cd0930875b5f40c61a35e685364c5ec883bf5899238eddc22ba12cb58fcee49e943c58b13f5cd893ff4c02cdb583ea3359cd26b8360a1873498b4d650c580e5f2ea31f2472a7f8d9a5ee30237c4addc4876961ab80f2923e807dbc319d7e4aaec4c63e1402f68d9d11ff0365a70328e62aa5da8f1d1b62035381b1a05744e78ab06d1d69bfd45eb41e4e902338

mod=[n1,n2,n3]
rem=[c1,c2,c3]

res=libnum.solve_crt(rem, mod)

print("\n\nAnswer:")
print(f"\nCipher 1: {c1}, N1={n1}")
print(f"Cipher 2: {c2}, N2={n2}")
print(f"Cipher 3: {c3}, N3={n3}")

print(f"\nWe can solve M^e with CRT to get {res}")
val=libnum.nroot(res,3)
print(f"\nIf we assume e=3, we take the third root to get: {val}")
print("Next we convert this integer to bytes, and display as a string.")
print(f"\nDecipher: {long_to_bytes(val)}")
```

We can run the python script and check the output:

```
$ > python3 rsa_solver.py
Answer:

Cipher 1: 1585790700186...

We can solve M^e with CRT to get 76333906633...

If we assume e=3, we take the third root to get: 91391505128409176043...

Next we convert this integer to bytes, and display as a string.

Decipher: b'Head to the library. Upon entering, politely ask the librarian if they are aware of any extra documents refering to Madame De Maintenon.\x00\x00...
```

So finally it looks we obtain a bigger flag for the first flag we obtained, and it starts with the *"Head to the library"* that we found at the beginning, so it looks like the whole flag is: *"Head to the library. Upon entering, politely ask the librarian if they are aware of any extra documents refering to Madame De Maintenon."*

##### Solving the Challenge

We have now everything we need for solving the challenge, we will write the next four flags in the correct order:

* Head to the library. Upon entering, politely ask the librarian if they are aware of any extra documents refering to Madame De Maintenon.
* Check books on the next shelf
* Search the book for clues
* Turn over the page

We will enter these flags, and we will see what we obtain.

<figure>
<a href="/assets/images/hex-ray-challenge2/33.png"><img src="/assets/images/hex-ray-challenge2/33.png"></a>
</figure>

It looks like this was the final part to solve the challenge, and we received a message with another big clue: 01000000110111000011011000000000. Also the challenge tells us to convert this big clue, with a union of the previous clues we found, and convert it into coordinates with 4 decimals each one like the next: *xx.xxxx, yy.yyyy*. Also those coordinates once they are hashed with MD5 we must obtain the next hash: *fe72f3730186f24d983a1c2ed1bc1da7*. The format for the binary numbers is IEEE-754 Floating Point.

If we use one converter website from the internet, we obtain the next two coordinates: *45.9238, 6.8815*, from the clues: *01000010001101111011001000000101, 01000000110111000011011000000000*.

We can now apply the MD5 hash:

```
$ md5sum
45.9238, 06.8815
f3570036e3f0465cc7ac6abe4c5f4228
```

We can take these values and send them to *marketing@hex-rays.com*, because we have finished the challenge. Also we can go to google maps to look for the place pointed by the coordinates:

<figure>
<a href="/assets/images/hex-ray-challenge2/34.png"><img src="/assets/images/hex-ray-challenge2/34.png"></a>
</figure>


And with this we finish the challenge, and the riddle has been solved!

<figure>
<a href="https://media.tenor.com/Y_o7BH0XTgIAAAAC/jiu-clap.gif"><img src="https://media.tenor.com/Y_o7BH0XTgIAAAAC/jiu-clap.gif"></a>
<figcaption>Detective Jiu solved successfully this case, congratulations!.</figcaption>
</figure>


### Acknowledgements

I want to thank my friend Robert Yates who told me about this second challenge, and also helped me with some discussions about the analysis. I also want to thank the rest of the team from Quarkslab who are helping me to learn and improve a lot at work. All of you, thank you!

### Full text from the challenge

Next I will copy paste the full text from the challenge with the correct answers:

```
You have heard rumours that the diary of Madame de Maintenon contained the secrets to a legendary plot.
Good luck on your journey to uncovering the truth behind this mystery!
You have heard that a rival historian recently discovered a copy of a chapter of the diary of Madame de Maintenon at the local library. But being unable to solve the mystery, returned it in frustration. Having long been fascinated by her history, you can't wait to investigate. What do you do?
Head to the library. Upon entering, politely ask the librarian if they are aware of any extra documents refering to Madame De Maintenon.

You locate the section of the library where the diary was rumoured to have been stored, but its place is empty. After a few minutes browsing, you find it! A single page, but one that holds the key to a fascinating mystery.

The page reads:
_______________
21 October 1684

Dear Diary,

Today, an unsettling discovery came my way. A letter, it was, with ominous tidings of a plot against our cherished Louis XIV. The message was unlike any other, its meaning hidden behind unfamiliar symbols.

Within the letter lay a clue, 01000010, a piece of the puzzle. It hinted at more secrets, and I felt compelled to uncover them. But where to find the next piece?

Yours in devotion,

Madame De Maintenon
_______________

The page was lying on the shelf in the open, maybe it fell from somewhere. You see a few more loose pages sticking out of some other books around you. What happened here?


What do you do?

Check books on the next shelf

What luck! While going through the books on the next shelf over, you find another page stuck under them, similarly weathered to the first one. The message is hard to decipher due to it's age, but after some careful analysis you manage to decode it.

It reads:
_______________
24 October 1684

Beloved Diary,
 
As I delved into the code, a new piece surfaced, 00110111. It whispered of hidden truths, yet it also hinted that there was more to uncover. The puzzle remained incomplete.

Yours eternally,

Madame De Maintenon
_______________

Another clue, what could it mean? And where are the rest?

What do you do?

Search the book for clues

From the lack of dust on the book you found, it's clear these were recently borrowed. Maybe the pages got mixed up with the books when being reshelved?

You look up the name of the last borrower, and look up what other books they may have checked out. There you find the diary records mentioned, as well as one other book. 
Finding that book on the shelves yields another page!

_______________
30 October 1684

Dearest Diary,

Another fragment emerged, 10110010. It was a step closer to the full picture, but it also held a hint. The rest of the location, it suggested, was not far away.

Yours eternally,

Madame De Maintenon
_______________



What do you do?

Turn over the page

Turning the page over, you find the final entry to the diary!

_______________
9 November 1684

Beloved Diary,

Today, the last piece fell into place, 00000101. With it came the realization that the remaining location lay elsewhere, a mystery yet to be unraveled. Our mission is clear, my dear diary; we must decipher the rest to protect our homeland.

Yours in devotion,

Madame de Maintenon
_______________

What does this mean? You've worked so hard but yet still don't have the information you seek? What now?
You have all four pages your rival claimed to have found, and yet are no closer to the truth.
After several hours of fruitlessly searching for meaning in the messages, you give up and turn to leave in defeat.


As you move to leave, the librarian comes running!

'I found this in the back room for you, it was a page we found lying around after procesing the most recent batch of new books but we weren't sure what it was for! But look at the signature!'

She hands you a fifth, almost completely blank new page. The aging of the paper looks near identical to the other four pages you found from the diary!

All the page says on it is:
_______________

The other key:

01000000110111000011011000000000

M d. M
_______________

You thank the librarian, and take your leave. You have much to think on. All these 1's and 0's, how do they encode the location of the final target???

#########################

Congratulations! If you've found all 5 pages of the diary you have everything you need! Convert the values you found into coordinates, (hint: IEEE-754 Floating Point), and send those coordinates in an email to marketing@hex-rays.com!
To locally verify your coordinates, the md5 of the coordinates, with 4 decimal places, (including potential leading zeros) in the form:
xx.xxxx, yy.yyyy
Has an md5 of fe72f3730186f24d983a1c2ed1bc1da7 when pasted as a 16 character string into https://www.md5hashgenerator.com/
```