---
layout: post
title: HSCTF 2023 WriteUp
subtitle: HSCTF 2023 Solve WriteUp
categories: CTF
tags: HSCTF Reversing Crypto Web
---

## Reversing

### back-to-basics

```
Description :
Try to solve it with your eyes closed

Attached file : [ReverseEngineeringChallenge.java]
```

#### 문제 풀이

뭐라는지 모르겠다... 일단 준 파일을 실행해보았다. 근데, Java가 설치가 안되있는건지 실행되지 않았다.
ida나 ghydra로도 열리지 않아, 일단 hxd로 열어보았다.

![back-to-basics-1](https://github.com/byeolha11/byeolha11.github.io/assets/40291473/a9e206b2-bfb6-4a3c-ad8b-293b238fdf29)

- password 뭐시기가 적혀있다.

<br>

실행 되는 프로그램인가...?<br>
노트북 구석진 곳에 있던 java 디컴파일 프로그램을 통해 열어보았다.

<br>

![back-to-basics-2](https://github.com/byeolha11/byeolha11.github.io/assets/40291473/9b90d208-1dc5-4f18-8308-2be24e8c3f29)

- password가 하드코딩되어 한 글자 씩 비교하고 있다.

<br>

배열의 순서대로 정렬해보니 flag가 나왔다.

<br>

```java
return password.length() == 20 &&
		password.charAt(0) == 'f' &&
		password.charAt(1) == 'l' &&
		password.charAt(2) == 'a' &&
		password.charAt(3) == 'g' &&
		password.charAt(4) == '{' &&
		password.charAt(5) == 'c' &&
		password.charAt(6) == '0' &&
		password.charAt(7) == 'd' &&
		password.charAt(8) == '1' &&
		password.charAt(9) == 'n' &&
		password.charAt(10) == 'g' &&
		password.charAt(11) == '_' &&
		password.charAt(12) == 'i' &&
		password.charAt(13) == '5';
		password.charAt(14) == '_' &&
		password.charAt(15) == 'h' &&
		password.charAt(16) == '4' &&
		password.charAt(17) == 'r' &&
		password.charAt(18) == 'd' &&
		password.charAt(19) == '}' &&
```
- flag{c0ding_i5_h4rd}

### brain-hurt
```
Description :
Rumor has it Godzilla had a stroke trying to read the code

Attached file : [main.py]
```

머리가 아프다는 의미인가...??

주어진 코드는 다음과 같다

```python
import sys

def validate_flag(flag):
    encoded_flag = encode_flag(flag)
    print(encoded_flag)
    expected_flag = 'ZT_YE\\0|akaY.LaLx0,aQR{"C'
    if encoded_flag == expected_flag:
        return True
    else:
        return False

def encode_flag(flag):
    encoded_flag = ""
    for c in flag:
        encoded_char = chr((ord(c) ^ 0xFF) % 95 + 32)
        encoded_flag += encoded_char
    return encoded_flag

def main():
    if len(sys.argv) != 2:
        print("Usage: python main.py <flag>")
        sys.exit(1)
    input_flag = sys.argv[1]
    if validate_flag(input_flag):
        print("Correct flag!")
    else:
        print("Incorrect flag.")

if __name__ == "__main__":
    main()
```
#### 문제 풀이

코드를 쭉 훑어보니, 사용자에게 입력을 받아 인코딩을 진행한다.
그 인코딩된 값이 expected_flag의 값과 일치하면 정답처리 되는거 같다.
해당 키 값을 디코딩할 수 있도록 코드를 작성하였다.

```python
flag = 'ZT_YE\\\\0|akaY.LaLx0,aQR{"C'

decoded_flag = ""

flag_dict = {}

for x in range(130):
    flag_dict[(chr((x ^ 0xFF) % 95 + 32))] = chr(x)
   
print(flag_dict)

for x in flag:
    if x in flag_dict.keys():
        decoded_flag += flag_dict[x]
    else:
        print(f'error : {x}')

print(decoded_flag)
```
<br>

python에서 문자열을 처리할 때의 문제인지, 자릿수과 문자열이 잘 디코딩 되지 않아 '/' 글자를 더 추가하였다.

![brain-hurt-2](https://github.com/byeolha11/byeolha11.github.io/assets/40291473/21af86be-4a0b-4bdc-9fe4-42c9d3473e88)

문자를 추가한 것 때문인지 flag가 틀렸다는 메시지가 표시되었다.

정답 flag는 다음과 같다 -> flag{d1D_U_g3t_tH15_onE?}

### keygen
```
Description :
A file: what's the key?

Attached file : [keygen]
```

#### 문제 풀이

keygen이라는 파일이 하나 주어졌다.

ida를 이용해서 뜯어보니, 아래와 같은 작은 프로그램이었다.

![keygen-1](https://github.com/byeolha11/byeolha11.github.io/assets/40291473/6342e659-f9c9-4d0e-9e07-39f3caf82299)

![keygen-2](https://github.com/byeolha11/byeolha11.github.io/assets/40291473/56341850-d5c9-4724-a691-63e50ca617ce)

사용자가 입력한 문자를 한 글자씩 변환하여 v4 변수에 저장된 값과 비교한다.
모두 일치하면 if문을 통과하여 'Correct'가 출력된다.

v4에 들어가있는 값을 디코딩하는 코드를 작성하였다.

```python
flag = "lfkmq<8=?=>?l'==<2'<;=>'?l<i'<l<9<h9l::::w"

decoded_flag = ""

flag_dict = {}

for x in range(130):
    flag_dict[chr(x ^ 0xA)] = chr(x)
   
print(flag_dict)

for x in flag:
    if x in flag_dict.keys():
        decoded_flag += flag_dict[x]
    else:
        print(f'error : {x}')

print(decoded_flag)
```

![keygen-3](https://github.com/byeolha11/byeolha11.github.io/assets/40291473/87a5bf22-b3c4-4cf7-95c0-a1a758b2cd96)

- 복호화 이후 flag 확인


## Crypto

### double-trouble
```
Description :
The pros solve it by hand.

Attached file : [HSCTF_Cryptography_Challenge.pdf]
```
PDF 파일 내용

```
___________ Salad: a green salad of romaine lettuce and croutons dressed with lemon juice, olive oil,
egg, Worcestershire sauce, anchovies, garlic, Dijon mustard, Parmesan cheese, and black pepper. In its
original form, this salad was prepared and served tableside.

Hvwg gvcizr bch ps hcc vofr.
Wb toqh, W kwzz uwjs wh hc mci fwuvh bck!
Hvs tzou wg hvs tczzckwbu:
OmqemdOubtqdeMdqOaax
Vcksjsf, wh wg sbqcrsr gc mci vojs hc rsqcrs wh twfgh!
Pkovovovovo
Fsasapsf, hvs tzou tcfaoh wg tzou{}
```

#### 문제 풀이

하단의 문자 생긴 게 뭔가 시저 암호 같았다.

맨 밑에 있는 4글자가 왠지 flag{}일거 같아서 tzou{}가 flag{}가 될 수 있는 글자 수를 계산해보았다.

글자 수는 - 13

위에 주어진 문장을 특수문자를 제외한 문자만 -13 연산을 하는 python 프로그램을 작성하여 돌려보았다.

```python
s = 'Fsasapsf, hvs tzou tcfaoh wg tzou{}'
print_str = ""

for x in s:
    # chr(ord(x)-14)
    tmp = ord(x)
    #print(tmp)
    if tmp >= 65 and tmp < 90 :
        tmp = ord(x)-14
        if tmp < 65 :
            tmp2 = 65 - tmp
            tmp = 90 - tmp2 +1
           
    elif tmp >= 97 and tmp <= 122:
        #elif tmp > 90 and tmp < 97:
        tmp = ord(x)-14
        if tmp < 97:
            tmp2 = 97 - tmp
            tmp = 122 - tmp2 +1
    print_str += chr(tmp)

print(print_str)
```
![double-trouble-1](https://github.com/byeolha11/byeolha11.github.io/assets/40291473/6419db7a-aada-4312-b528-229015a84966)

- 실행 결과

잘 출력되었다.

나머지 문자들도 다 돌려서 복호화 해보았다.

```
This should not be too hard.
In fact, I will give it to you right now!
The flag is the following:

AycqypAgnfcpqYpcAmmj

However, it is encoded so you have to decode it first
Bwahahahaha
Remember, the flag format is flag{}
```
 - 잘 출력된거 같은데... flag를 주긴 줬는데... 한번 더 디코딩해야 한단다.

 여기서 부터 삽질이 시작되었다.

20글자로 출력 가능한 암호화가 뭐가 있는지 미친듯이 뒤져봤는... 이걸 발견하고 말았다.

[URL](https://jo-gunhee.github.io/website1/dcode/dcodewebsite.html)

![double-troubl2](https://github.com/byeolha11/byeolha11.github.io/assets/40291473/026ddc9b-cd12-4b7a-b818-92920a0a9601)

자동으로 다 계산해서 결과값을 뿌려준다. 읽을 수 있는 글자가 flag였다.

나는 왜 열심히 python을 짜서 풀었는가...

ps. PDF에 가려진 샐러드의 이름도 시저 샐러드란다;;

## Web

### an-inaccessible-admin-panel

```
Description :
The Joker is on the loose again in Gotham City! Police have found a web application where the Joker had allegedly tampered with. This mysterious web application has login page, but it has been behaving abnormally lately. Some time ago, an admin panel was created, but unfortunately, the password was lost to time. Unless you can find it...

Can you prove that the Joker had tampered with the website?

Default login info: Username: default Password: password123

Attached file : [ ]
```

![an-inaccessible-admin-panel-1](https://github.com/byeolha11/byeolha11.github.io/assets/40291473/0d6874cf-608d-4606-808a-57e99e391537)
- 웹화면

#### 문제 풀이

로그인 외에 기능은 없다, 주어진 ID와 PW로 로그인 시도를 해보았으나, 별 다른 건 없었다.

개발자 도구를 이용하여 해당 웹 사이트의 소스 코드를 확인해보았다.

![an-inaccessible-admin-panel-2](https://github.com/byeolha11/byeolha11.github.io/assets/40291473/ed15b70f-f218-40bb-a8f3-de7a521503f6)

- 주석 처리된 ID와 PW가 보이지만 이미 문제에서 주어진 내용이라 여기도 큰 의미는 없는 거 같고... 로그인 시 전달되는 login.js에 의미있는 데이터가 있는지 확인해보았다.

```js
window.onload = function() {
    var loginForm = document.getElementById("loginForm");
    loginForm.addEventListener("submit", function(event) {
        event.preventDefault();
        var username = document.getElementById("username").value;
        var password = document.getElementById("password").value;

        function fii(num){
            return num / 2 + fee(num);
        }
        function fee(num){
            return foo(num * 5, square(num));
        }
        function foo(x, y){
            return x*x + y*y + 2*x*y;
        }
        function square(num){
            return num * num;
        }

        var key = [32421672.5, 160022555, 197009354, 184036413, 165791431.5, 110250050, 203747134.5, 106007665.5, 114618486.5, 1401872, 20702532.5, 1401872, 37896374, 133402552.5, 197009354, 197009354, 148937670, 114618486.5, 1401872, 20702532.5, 160022555, 97891284.5, 184036413, 106007665.5,
          128504948, 232440576.5, 4648358, 1401872, 58522542.5, 171714872, 190440057.5, 114618486.5, 197009354, 1401872, 55890618, 128504948, 114618486.5, 1401872, 26071270.5, 190440057.5, 197009354, 97891284.5, 101888885, 148937670, 133402552.5, 190440057.5, 128504948, 114618486.5, 110250050, 1401872,
          44036535.5, 184036413, 110250050, 114618486.5, 184036413, 4648358, 1401872, 20702532.5, 160022555, 110250050, 1401872, 26071270.5, 210656255, 114618486.5, 184036413, 232440576.5, 197009354, 128504948, 133402552.5, 160022555, 123743427.5, 1401872, 21958629, 114618486.5, 106007665.5, 165791431.5,
          154405530.5, 114618486.5, 190440057.5, 1401872, 23271009.5, 128504948, 97891284.5, 165791431.5, 190440057.5, 1572532.5, 1572532.5];

        function validatePassword(password){
            var encryption = password.split('').map(function(char) {
                return char.charCodeAt(0);
            });
            var checker = [];
            for (var i = 0; i < encryption.length; i++) {
                var a = encryption[i];
                var b = fii(a);
                checker.push(b);
            }
            console.log(checker);

            if (key.length !== checker.length) {
                return false;
            }

            for (var i = 0; i < key.length; i++) {
                if (key[i] !== checker[i]) {
                    return false;
                }
            }
            return true;
        }
        if (username === "Admin" && validatePassword(password)) {
            alert("Login successful. Redirecting to admin panel...");
            window.location.href = "admin_panel.html";
        }
        else if (username === "default" && password === "password123") {
            var websiteNames = ["Google", "YouTube", "Minecraft", "Discord", "Twitter"];
            var websiteURLs = ["https://www.google.com", "https://www.youtube.com", "https://www.minecraft.net", "https://www.discord.com", "https://www.twitter.com"];
            var randomNum = Math.floor(Math.random() * websiteNames.length);
            alert("Login successful. Redirecting to " + websiteNames[randomNum] + "...");
            window.location.href = websiteURLs[randomNum];
        } else {
            alert("Invalid credentials. Please try again.");
        }
    });
  };

```
- login,js 전체 코드

<br>

![an-inaccessible-admin-panel-3](https://github.com/byeolha11/byeolha11.github.io/assets/40291473/aa825056-365d-4821-a8e5-d4af947fae2e)

- login.js에서 확인해보니 로그인 검증 로직이 존재했다.


username과 password가 하드코딩되어 있고, 입력된 ID, PW가 문제에 주어진 내용과 같으면 디스코드, 유튜브, 마인크래프트, 디스코드, 트위터등의 사이트 중 랜덤으로 리다이렉트 된다.
-> default 계정의 로그인은 의미없다

소스코드에서 의미 있는 데이터는 admin 로그인 ID는 'Admin' 이며 입력된 password는 'validatePassword'라는 함수를 통해 검증 후 로그인되며, 로그인 시 admin_panel.html 페이지로 이동된다.

admin_panel.html가 로그인을 하지 않고도 접근이 가능한지 확인해보았다.

![an-inaccessible-admin-panel-4](https://github.com/byeolha11/byeolha11.github.io/assets/40291473/54fb79f0-9575-4b7f-99d8-2657a31d8a90)

admin_panel.html가 그냥 접근이 되었다. 이번 문제의 flag는 admin 계정의 ID와 password가 flag인가보다.

즉, admin password를 깨야한다.

코드를 분석해보니, 아래와 같은 순서로 비밀번호를 검증하고 있었다.

1. ID : Admin, password를 입력하고 로그인 버튼을 클릭하면
2. validatePassword 함수에 password가 들어간다.
3. 들어간 password를 한 문자씩 잘라서 fii,fee,foo,square 함수에 들어가 각각의 연산을 진행한다.
4. 출력된 값을 key 배열에 있는 값과 비교하여 전부 일치할 경우 Admin계정이 로그인 된다.

그럼 password를 깨는 방법은 두가지
1. key가 주어졌기 때문에 검증하는 구간을 역으로 역산한다.
2. 감사하게도 입력한 값을 console.log로 개발자도구에 로그를 출력해준다. 입력할 수 있는 문자를 모두 출력하도록 하고 key와 같은지 비교하여 password를 찾아낸다.

어떤게 더 편할지 고민하다가 console.log를 이용하여 데이터를 수집하여 key와 매칭시키는 방법으로 진행하기로 했다.

![an-inaccessible-admin-panel-5](https://github.com/byeolha11/byeolha11.github.io/assets/40291473/80a9a615-f73f-495b-8ff3-32ea4b6b9287)

- 치환 안한 특수문자 없이, 한번에 성공하길...
- (없던 특수문자가 있었다... ',', ' ' 두 개를 추가했다.)

이후 간단한 python 코드를 작성했다

```python
#주어진 비밀번호 검증 Key list
key = [32421672.5, 160022555, 197009354, 184036413, 165791431.5, 110250050, 203747134.5, 106007665.5, 114618486.5, 1401872, 20702532.5,
            1401872, 37896374, 133402552.5, 197009354, 197009354, 148937670, 114618486.5, 1401872, 20702532.5, 160022555, 97891284.5,
            184036413, 106007665.5, 128504948, 232440576.5, 4648358, 1401872, 58522542.5, 171714872, 190440057.5, 114618486.5, 197009354,
            1401872, 55890618, 128504948, 114618486.5, 1401872, 26071270.5, 190440057.5, 197009354, 97891284.5, 101888885, 148937670,
            133402552.5, 190440057.5, 128504948, 114618486.5, 110250050, 1401872, 44036535.5, 184036413, 110250050, 114618486.5,
            184036413, 4648358, 1401872, 20702532.5, 160022555, 110250050, 1401872, 26071270.5, 210656255, 114618486.5, 184036413,
            232440576.5, 197009354, 128504948, 133402552.5, 160022555, 123743427.5, 1401872, 21958629, 114618486.5, 106007665.5,
            165791431.5, 154405530.5, 114618486.5, 190440057.5, 1401872, 23271009.5, 128504948, 97891284.5, 165791431.5, 190440057.5, 1572532.5, 1572532.5]

#치환할 문자열 lsit
str_list = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890!@#$%^&*(), '

#Console.log에서 뽑아낸 문자별 password 값
number_list = [20702532.5, 21958629, 23271009.5, 24641330, 26071270.5, 27562535, 29116851.5, 30735972, 32421672.5, 34175753, 36000037.5, 37896374, 39866634.5, 41912715, 44036535.5, 46240040, 48525196.5, 50893997, 53348457.5, 55890618, 58522542.5, 61246319, 64064059.5, 66977900, 69990000.5, 73102545,
97891284.5, 101888885, 106007665.5, 110250050, 114618486.5, 119115447, 123743427.5, 128504948, 133402552.5, 138438809, 143616309.5, 148937670, 154405530.5, 160022555, 165791431.5, 171714872, 177795612.5, 184036413, 190440057.5, 197009354, 203747134.5, 210656255, 217739595.5, 225000060, 232440576.5, 240064097,
7001340.5, 7562525, 8156761.5, 8785322, 9449502.5, 10150623, 10890027.5, 11669084, 12489184.5, 6471960,
1572532.5, 19501088, 1960017.5, 2178594, 2414934.5, 86601683, 2669975, 3896697, 3240020, 3557016.5, 4648358, 1401872]

passwd_dic = {}

# 복사 실수 체크를 위해 list 길이 비교
print(len(str_list))
print(len(number_list))

# key 복호화에 사용할 password dict 생성
for index, value in enumerate(number_list):
    passwd_dic[value] = str_list[index]

 #출력하여 확인
print(passwd_dic)

admin_passwd = ""

#key를 하나씩 비교하며 만든 password dict에 있으면 해당 문자를 저장
for x in key:
    if x in passwd_dic.keys():
        admin_passwd += passwd_dic[x]
    else:
	    #혹시나 없는 경우, 값을 찾기 위해 출력
        print(x)
        admin_passwd += ' '

#복호화된 Key 문자열 출력
print('\n',admin_passwd)
```

![an-inaccessible-admin-panel-6](https://github.com/byeolha11/byeolha11.github.io/assets/40291473/00e0b83d-962c-4a00-8826-ab61a80b474a)

- 정답 flag -> flag{Admin, Introduce A Little Anarchy, Upset The Established Order, And Everything Becomes Chaos!!}
