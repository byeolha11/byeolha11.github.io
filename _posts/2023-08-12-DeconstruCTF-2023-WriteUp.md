---
layout: post
title: DeconstruCTF 2023 WriteUp
subtitle: DeconstruCTF 2023 Solve WriteUp
categories: CTF
tags: DeconstruCTF2023 Cryptography Forensics
---
## Cryptography

### BLURY
```
Description :
Mr. Charlie Ben Conor's security algorithms have been repeatedly urged by the management team to include as much randomization as possible. We believe he lacks understanding of conventional uses of symmetric cyphers, but he has always denied it owing to financial constraints.  
Can you demonstrate the potential consequences of his actions?

Attached file : [ciphertext.txt, encrypt.py]
```
text 파일과 python 파일이 주어졌다.

#### 문제 풀이
글은 뭐라고 하는지 모르겠고, 일단 주어진 파일 중 txt 파일을 먼저 확인하였다.

```
TlRRcUtpb3FLaW9xS2lvcUtpb3FLaW9xS2lvcUtpb3FLaW9xS2pNMlpEUXpZU29xS2lvcUtpb3FLaW9xS2lvcUtpb3FLaW9xS2lvcUtpb3FNVFkxT0dVM0tpb3FLaW9xS2lvcUtpb3FLaW9xS2lvcUtpb3FLaW9xS2lwaVlqSmpaR0ZpWXpBeVlUQTFPR1k0WXpNNU16WmhOV1prTm1Sa1pETmpOVEEwT1RFPQ==
```
맨 뒤에가 '=='으로 끝나는 것을 보니, base64로 인코딩 되어 있는거 같다.

그 다음은 python 파일을 확인해보았다.

<br>
```python
from Crypto.Cipher import AES
import binascii, sys
from flag import flag

key = "3N7g309d6Y7enT**"
IV = flag

message = 'Security is not a joke, mind it. But complete security is a myth'
def encrypt(message,passphrase):
    aes = AES.new(passphrase, AES.MODE_CBC, IV)
    return aes.encrypt(message)
print("Encrypted data: ", binascii.hexlify(encrypt(message,key)).decode())
```
python 코드를 확인하여 보니, AES 암호화를 CBC모드로 암호화 한다.

일단 암호학 문제이고, 주어진 코드를 확인해보니 messge와 암호화를 진행하는 Key가 주어졌다. 근데 Key의 뒤에 두 글자가 **인걸 보아 이걸 알아내야하고, IV의 값이 플래그인거 같다.

주어진 txt 파일은 위 함수를 돌려서 나온 암호문이 들어 있을 것이다.

암호화된 문자열이 Base64로 되어 있는거 같아, cyberchef를 통해 디코딩을 진행했더니 다음과 같은 값이 출력되었다.

![BLURY-1](https://github.com/byeolha11/byeolha11.github.io/assets/40291473/18d176a1-2e20-4c58-ab79-2bf78e0ac7c3)

```
54**************************36d43a**************************1658e7**************************bb2cdabc02a058f8c3936a5fd6ddd3c50491
```

32 바이트로 끊어서 이쁘게 정리해보았다.

```
54**************************36d4
3a**************************1658
e7**************************bb2c
dabc02a058f8c3936a5fd6ddd3c50491
```

흠… 흠

일단 AES CBC 모드가 어떻게 동작하는지 찾아보았다.

![BLURY-2](https://github.com/byeolha11/byeolha11.github.io/assets/40291473/c8333b3d-4dea-4ce8-9856-151a9c4051c3)

이렇게 생기고 이렇게 진행이 된다고 한다….

암호화 로직을 보면 message를 16바이트 씩 끊어서 암호화를 진행한다.

첫 블록 16바이트 ‘Security is not ‘이라는 메시지와 우리가 찾을 flag 값을 xor 연산을 한 뒤 나온 값을 aes 암호화를 진행하면 ‘54**************************36d4’라는 암호문이 나오게 된다.

다음 블록은 위에서 나온 암호문 ‘54**************************36d4’와 다음 메시지 16 바이트 ‘a joke, mind it.’을 동일하게 xor 진행 후 aes 암호화 진행. 이후 반복

message가 ‘Security is not a joke, mind it. But complete security is a myth’ 64 바이트라 딱 16바이트 씩 4블록으로 떨어져서 다행이다. 만약 딱 떨어지지 않는다면 패딩이라는 개념의 임의의 값을 넣어 16바이트를 맞춘다는거 같다.

그럼 반대로 복호화는?

암호문 ‘dabc02a058f8c3936a5fd6ddd3c50491’ 값과 Key를 넣고 aes.decrypt() 로직을 돌리고 나온 값이랑 4번째 블록 message ’curity is a myth’의 값을 xor 하면 세번째 블록의 암호화 값 ‘e7**************************bb2c’이 출력된다는 것이다.

하지만 먼저 문제에서는 key의 뒤 두자리가 주어지지 않았기 떄문에 무차별 대입으로 해당 값을 먼저 찾아야 한다.

```python
from Crypto.Cipher import AES
from binascii import hexlify, unhexlify

def xor(a,b):
    return bytes([a[i] ^ b[i] for i in range(len(a))])

key = '3N7g309d6Y7enT' # 두자리 부족 주어진 값 -> 3N7g309d6Y7enT**
planintext = 'Security is not a joke, mind it. But complete security is a myth'
ciphertext = '54**************************36d4'\
    '3a**************************1658'\
    'e7**************************bb2c'\
    'dabc02a058f8c3936a5fd6ddd3c50491'

key = key.encode()
p0 = planintext[:16].encode()
p1 = planintext[16:32].encode()
p2 = planintext[32:48].encode()
p3 = planintext[48:].encode()
c0 = ciphertext[:32]
c1 = ciphertext[32:64]
c2 = ciphertext[64:96]
c3 = unhexlify(ciphertext[96:])

# Key brouteforcing
key_found, i = False, 0
while not key_found and i <= 0xff:
    j = 0
    while not key_found and j <= 0xff:
        tmp_key = key + bytes([i,j])
        aes = AES.new(tmp_key,AES.MODE_ECB)
        c3_prime = hexlify(xor(aes.decrypt(c3),p3)).decode()
        if c3_prime[:2] == c2[:2] and c3_prime[28:] == c2[28:]:
            key = tmp_key
            print(key)
            print(c3_prime)
            key_found = True
        j += 1
    i +=1
```

2바이트 부족한 Key 값에 문자열 2자리를 붙여주고 문제에서 주어진 암호화 값 ‘e7**************************bb2c’의 앞에 2자리 뒤 4자리가 일치하는 값이 나오는 경우 올바른 키이다.

![BLURY-3](https://github.com/byeolha11/byeolha11.github.io/assets/40291473/2d088153-d95d-4af7-8c3b-c5c29e728a5a)

일치하는 Key 값과 전체 3번째 블록 전체 암호문을 획득했다.

동일한 방법으로 모든 암호문을 구한 결과, 아래와 같은 값을 얻을 수 있다.

```
54453ced1207bb9f67894d2c8ae336d4
3a4911ae86c1f5138c2d8e17e7721658
e764f66e54397534f7d049506acabb2c
dabc02a058f8c3936a5fd6ddd3c50491
```

마지막 최종, 첫번째 블록 암호화 값을 decrypt하고 평문으로 xor 하는 경우 iv의 값을 얻을 수 있으며, 그 값이 플래그 이다.

이후 첫번째 블록 값으로 복호화 시도

```python
iv = xor(aes.decrypt(c0), p0)
```

플래그 확인

![Untitled](https://github.com/byeolha11/byeolha11.github.io/assets/40291473/6ccd2b7e-f5b4-40d3-91a5-25faf3904765)

![image (6)](https://github.com/byeolha11/byeolha11.github.io/assets/40291473/281ce028-80d6-4872-955f-684945018bf8)

## Forensics

### Magicplay
```
Description :

Dwayne's mischevious nephew played around in his pc and corrupted a very important file..  
Help dwayne recover it!

Attached file : [magicplay.zip]
```
압축 파일이 하나 주어졌으며, 압출을 풀어보니 .png의 이미지 파일이 하나 들어있었다.

#### 문제 풀이

![Magicplay-1](https://github.com/byeolha11/byeolha11.github.io/assets/40291473/1175ad82-99f5-4545-a140-99b9701e28b1)

png 파일이 제대로 표시되지 않는다. Hxd 에디터로 확인 해보았다.

![Magicplay-2](https://github.com/byeolha11/byeolha11.github.io/assets/40291473/4de744e5-5414-4115-876d-3919cdc1bb81)

첫 시작 지점의 시그니처가 png가 아니다.

파일 시그니처란, 파일 마다 정해진 시그니처가 존재한다. 해당 시그니처를 통해 파일의 타입을 알 수 있으며, 파일 시그니처는 헤더와 푸더가 있다.

헤더 - 파일의 시작, 푸터 - 파일의 끝

|file Type|Header Signature(Hex)|Footer Signature(Hex)|
|:--------:|:-----:|:-----:|
|JPEG|FF D8 FF E0 <br> FF D8 FF E0|FF D9|
|GIF|47 49 46 38 37 61<br> 47 49 64 38 39 61|00 3B|
|PNG|89 50 4E 47 0D 0A 1A 0A |49 45 4E 44 AE 42 60 82|
|PDF|25 50 44 46 2D 31 2E|25 25 45 4F 46|
|ZIP|50 4B 03 04|50 4B 05 06|
|ALZ|41 4C 5A 01|43 4C 5A 02|
|RAR|52 61 72 21 1A 07|3D 7B 00 40 07 00|

문제로 주어진 파일의 헤더가 원래의 시그니처가 아닌 것은 확인했고, 푸터도 한번 확인해본다. 푸터 시그니처는 파일의 끝을 의미하는데 가끔 문제에서 푸터 시그니처 이후에 텍스트나 파일을 숨겨놓는 경우도 있다.

![Magicplay-4](https://github.com/byeolha11/byeolha11.github.io/assets/40291473/7f0685be-9670-4a6d-ac01-6ab7469ad845)

푸터는 시그니처가 일치하는 것을 확인했다.

![Magicplay-5](https://github.com/byeolha11/byeolha11.github.io/assets/40291473/00972d34-e790-4339-9904-0a5499a4c6dc)

헤더 시그니처를 위에 표에서 확인한 PNG의 올바른 시그니처로 한번 변경해보았다.

![Magicplay-6](https://github.com/byeolha11/byeolha11.github.io/assets/40291473/13817ca7-98c4-442c-8a33-90fcbfa66e03)

근데도 안 열림;;

이때 확인하는 PNG 청크 정보

참고한 블로그 : [URL](https://mineeeee.tistory.com/12)

![Magicplay-7](https://github.com/byeolha11/byeolha11.github.io/assets/40291473/9db45b69-b6af-4216-ac15-7d8ab1d6d3ff)

위 블로그에서 확인한 내용으로 보면 PNG는 정해진 형태의 파일 구조가 존재하고 그 정보가 깨지게 되면 파일이 보이지 않거나, PNG 파일의 사이즈를 조절할 수 있게 된다고 한다.

![Magicplay-8](https://github.com/byeolha11/byeolha11.github.io/assets/40291473/8ca0d8e7-7556-4aec-9520-52b51932a087)

암튼 PNG 파일의 청크 정보에 IGNR이라는 얘는 없으므로, 애를 IHDR로 변경해준다.

![magic_play - 복사본](https://github.com/byeolha11/byeolha11.github.io/assets/40291473/da9908a7-bbc7-4792-b267-ca954e4dba7a)

- 플래그 확인
