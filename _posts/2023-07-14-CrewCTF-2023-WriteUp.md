---
layout: post
title: CrewCTF 2023 WriteUp
subtitle: CrewCTF 2023 Solve WriteUp
categories: CTF
tags: CrewCTF Forensics
---

## Forensics

### Attaaaaack1

```
Description :
One of our employees at the company complained about suspicious behavior on the machine, our IR team took a memory dump from the machine and we need to investigate it.

Q1. What is the best profile for the the machine?

회사 직원 중 한 명이 시스템의 의심스러운 동작에 대해 불평했고, IR 팀이 시스템에서 메모리 덤프를 가져와 조사해야 했습니다.

Q1. 기계에 가장 적합한 프로파일은 무엇입니까?

Attached file : [memdump.raw]
```

#### 문제 풀이

메모리 덤프로 보여지는 파일이 주어졌다. 노트북에 설치되어있던 volatility(메모리 분석 tool)을 사용하여 메모리 덤프 파일의 이미지 정보를 확인했다.

```bash
vol_2.6.exe imageinfo -f ./memdump.raw
```


![Attaaaaack1](https://github.com/byeolha11/byeolha11.github.io/assets/40291473/b42d29b4-7065-4869-8cd2-e75a5b40194e)

- 문제에서 요구하는 profile 정보를 찾을 수 있었다.
- flag -> crew{Win7SP1x86_23418}
<br>

### Attaaaaack2
```
Description :
Q2. How many processes were running ? (number)

( doesnt follow format)

Q2. 얼마나 많은 프로세스가 실행되고 있었습니까? (숫자)

(형식을 따르지 않음)
```

#### 문제 풀이

volatility의 pslist 명령어를 통해 덤프된 메모리의 실행중인 프로세스 정보를 확인할 수 있다.

```bash
vol_2.6.exe -f ./memdump.raw --profile=Win7SP1x86_23418 pslit
```

![Attaaaaack2](https://github.com/byeolha11/byeolha11.github.io/assets/40291473/9a0f01ad-ee02-4b23-9d8a-acde6cfa184d)

```php
Offset(V)  Name                    PID   PPID   Thds     Hnds   Sess  Wow64
0x8419c020 System                    4      0     89      536 ------      0
0x962f2020 smss.exe                268      4      2       29 ------      0
0x860a8c78 csrss.exe               352    344      9      462      0      0
0x855dfd20 wininit.exe             404    344      3       76      0      0
0x8550b030 csrss.exe               416    396      9      268      1      0
0x85ea2368 services.exe            480    404      8      220      0      0
0x85ea8610 lsass.exe               488    404      6      568      0      0
0x85eab718 lsm.exe                 496    404     10      151      0      0
0x85eacb80 winlogon.exe            508    396      5      115      1      0
0x85f4d030 svchost.exe             632    480     10      357      0      0
0x85ef0a90 svchost.exe             700    480      8      280      0      0
0x919e2958 svchost.exe             752    480     22      507      0      0
0x85f9c3a8 svchost.exe             868    480     13      309      0      0
0x85fae030 svchost.exe             908    480     18      715      0      0
0x85fb7670 svchost.exe             952    480     34      995      0      0
0x85ff1380 svchost.exe            1104    480     18      391      0      0
0x8603a030 spoolsv.exe            1236    480     13      270      0      0
0x86071818 svchost.exe            1280    480     19      312      0      0
0x860b73c8 svchost.exe            1420    480     10      146      0      0
0x860ba030 taskhost.exe           1428    480      9      205      1      0
0x861321c8 dwm.exe                1576    868      5      114      1      0
0x8613c030 explorer.exe           1596   1540     29      842      1      0
0x841d7500 VGAuthService.         1636    480      3       84      0      0
0x86189d20 vmtoolsd.exe           1736   1596      8      179      1      0
0x8619dd20 vm3dservice.ex         1848    480      4       60      0      0
0x861a9030 vmtoolsd.exe           1884    480     13      290      0      0
0x861b5360 vm3dservice.ex         1908   1848      2       44      1      0
0x861fc700 svchost.exe             580    480      6       91      0      0
0x86261030 WmiPrvSE.exe           1748    632     10      204      0      0
0x86251bf0 dllhost.exe             400    480     15      196      0      0
0x8629e518 msdtc.exe              2168    480     14      158      0      0
0x8629e188 SearchIndexer.         2276    480     12      581      0      0
0x8630b228 wmpnetwk.exe           2404    480      9      212      0      0
0x862cca38 svchost.exe            2576    480     15      232      0      0
0x85351030 WmiPrvSE.exe           3020    632     11      242      0      0
0x853faac8 ProcessHacker.         3236   1596      9      416      1      0
0x843068f8 sppsvc.exe             2248    480      4      146      0      0
0x85f89640 svchost.exe            2476    480     13      369      0      0
0x843658d0 cmd.exe                2112   2876      1       20      1      0
0x84368798 cmd.exe                2928   2876      1       20      1      0
0x84365c90 conhost.exe            1952    416      2       49      1      0
0x84384d20 conhost.exe            2924    416      2       49      1      0
0x84398998 runddl32.exe            300   2876     10     2314      1      0
0x84390030 notepad.exe            2556    300      2       58      1      0
0x84df2458 audiodg.exe            1556    752      6      129      0      0
0x84f1caf8 DumpIt.exe             2724   1596      2       38      1      0
0x84f3d878 conhost.exe            3664    416      2       51      1      0
```
- 출력된 프로세스 정보, git 블로그에서 이쁘게 보일지 Test

- flag -> crew{47}

### Attaaaaack3

```
Q3. i think the user left note on the machine. can you find it ?

flag format : crew{}

Q3. 사용자가 기계에 메모를 남겼다고 생각합니다. 당신은 그것을 찾을 수 있습니까?

플래그 형식: 크루{}
```

#### 문제 풀이

사용자가 기계에 메모를 남겼다고 해서 엄청 삽질을 했다;; 프로세스에 실행중인 notepad.exe를 추출하여 입력된 정보가 없는지 찾아보기도 하고,
 .txt 확장자자 .doc, docx로 되어있는 저장된 파일이 있는지 확인해보았다.

하지만 정답은 클립보드 였다.

volatility에서 덤프된 메모리의 클립보드 내용을 확인할 수 있는 명령어를 제공한다.

```bash
vol_2.6.exe -f ./memdump.raw --profile=Win7SP1x86_23418 clipboard
```

![Attaaaaack3](https://github.com/byeolha11/byeolha11.github.io/assets/40291473/81b0e31a-a6a2-46e4-9c99-b39ca337a7d6)

- flag -> crew{1_l0v3_M3m0ry_F0r3ns1cs_S0_muchhhhhhhhh}

### Attaaaaack4~5
```
Description :
Q4. What is the name and PID of the suspicious process ?
example : crew{abcd.exe_111}

Q5. What is the another process that is related to this process and it's strange ?
example : crew{spotify.exe}

Q4. 의심스러운 프로세스의 이름과 PID는 무엇입니까?
예: crew{abcd.exe_111}

Q5. 이 프로세스와 관련된 다른 프로세스는 무엇이며 이상합니까?
예: crew{spotify.exe}
```

#### 문제 풀이

volatility에서 위에서 확인 했던 pslist 명령어를 사용하여 프로세스 리스트를 확인 할 수도 있지만, volatility에선 pstree라는 명령어도 제공한다.
프로세스를 트리 구조의 형태로 확인할 수 있는 명령어로 의심스러운 프로세스를 확인할 때 사용하기 좋은 명령어이다.

```bash
vol_2.6.exe -f ./memdump.raw --profile=Win7SP1x86_23418 pstree
```

![Attaaaaack4](https://github.com/byeolha11/byeolha11.github.io/assets/40291473/52464134-b847-49fa-b92e-232676cd7309)

![Attaaaaack5](https://github.com/byeolha11/byeolha11.github.io/assets/40291473/e11bce21-77a7-4c34-baed-aa65d49a6496)
- 시스템과 관련된 프로세스는 상단에 묶여있었던거 같고... 상위 프로세스도 표시가 되지 않아 의심하던 중 구글에 검색해보고 프로세스명이 dll이 아니고 ddl인 것을 확인했다.

![Attaaaaack6](https://github.com/byeolha11/byeolha11.github.io/assets/40291473/d08a8ec3-d9fa-4b5a-9b1e-7cc3b3f6da7d)
- 낚일뻔;;

- flag -> crew{runddl32.exe_300}
-            crew{notepad.exe}

### Attaaaaack6
```
Description :
Q6. What is the full path (including executable name) of the hidden executable?

example : crew{C:\Windows\System32\abc.exe}

Q6. 숨겨진 실행 파일의 전체 경로(실행 파일 이름 포함)는 무엇입니까?

예: crew{C:\Windows\System32\abc.exe}
```

#### 문제 풀이

위에서 의심되던 notepad.exe 파일의 pid를 확인한 뒤, memdump 명령어를 사용하여 해당 프로세스의 메모리를 덤프했다.

```bash
vol_2.6.exe -f ./memdump.raw --profile=Win7SP1x86_23418 pslist | findstr notepad
vol_2.6.exe -f ./memdump.raw --profile=Win7SP1x86_23418 memdump -p 2556 -D ./
```

![Attaaaaack7](https://github.com/byeolha11/byeolha11.github.io/assets/40291473/2a7b790d-fff3-45c3-9c7a-cf45ee5b8abe)

이후 string.exe 툴을 사용하여 추출한 notepad.exe에 string 정보만 추출하였다.

```bash
string.exe ../2556.dmp >> 2556.txt
```

![Attaaaaack9](https://github.com/byeolha11/byeolha11.github.io/assets/40291473/89376414-26d3-433e-93cd-9579448ed4b0)

추출된 string 파일 안에서 이전에 찾은 의심 프로세스의 파일 경로를 확인할 수 있었다.

![Attaaaaack8](https://github.com/byeolha11/byeolha11.github.io/assets/40291473/a0126e65-f42c-454e-8f93-df35e501ea9a)

- flag -> crew{C:\Users\0XSH3R~1\AppData\Local\Temp\MSDCSC\runddl32.exe}

### Attaaaaack7~8

```
Description :
Q7. What is the API used by the malware to retrieve the status of a specified virtual key on the keyboard ?

flag format : crew{AbcDef}

Q8. What is the Attacker's C2 domain name and port number ? (domain name:port number)

example : crew{abcd.com:8080}

Q7. 키보드에서 지정된 가상 키의 상태를 검색하기 위해 멀웨어가 사용하는 API는 무엇입니까?

플래그 형식 : crew{AbcDef}

Q8. 공격자의 C2 도메인 이름과 포트 번호는 무엇입니까? (도메인 이름: 포트 번호)

예: crew{abcd.com:8080}
```

#### 문제 풀이

이번에는 악성 파일을 추출해보았다.

```bash
vol_2.6.exe -f ./memdump.raw --profile=Win7SP1x86_23418 procdump -p 300 -D ./
```

![Attaaaaack10](https://github.com/byeolha11/byeolha11.github.io/assets/40291473/d93fb16f-d4ee-4247-99eb-9b2abf8f2a5e)
- 악성 파일 추출

![Attaaaaack12](https://github.com/byeolha11/byeolha11.github.io/assets/40291473/aedb1658-b8ee-43e8-a616-ee7b47c90b4b)
- 추출된 파일을 바이러스토탈에 업로드

추출한 파일을 바이러스토탈에 올려 분석된 결과를 확인했다.

![Attaaaaack11](https://github.com/byeolha11/byeolha11.github.io/assets/40291473/9d7b4b3a-09fb-49aa-a65a-e6a7314d5f0c)
- API 정보 확인

바이러스토탈에서 확인된 API 중 Key 입력과 관련된 것은 GetKeyboardState, GetKeyState 두 가지 인거 같았다.

![Attaaaaack13](https://github.com/byeolha11/byeolha11.github.io/assets/40291473/71f8529c-7de3-412b-9f23-99d3838d25a9)
- 접속 정보 확인

또한, 다음 문제인 C2서버 관련 정보들도 확인할 수 있었다.

- flag -> crew{GetKeyState}
             crew{test213.no-ip.info:1604}

### Attaaaaack9

```
Description :
Q9. Seems that there is Keylogger, can you find it's path ?

example : crew{C:\Windows\System32\abc.def}

Q9. Keylogger가 있는 것 같은데 경로를 찾을 수 있습니까?

예: 크루{C:\Windows\System32\abc.def}
```

#### 문제 풀이

여기까지 진행하면서 마구 추춣했던 파일들을 분석하던 중, 문제에서 이야기하는 keylogger의 이름으로 보이는 파일과 디렉토리를 찾았다.

![Attaaaaack14](https://github.com/byeolha11/byeolha11.github.io/assets/40291473/88b92f40-fe17-47e9-b118-a7c5b9f8d4b1)
- 파일을 어떻게 추출했었는지는 잘 기억이 안남;;

그리고 Attaaaaack6번과 동일한 과정으로 runddl32.exe 파일의 string 정보를 추출하여 분석을 진행하였고, 위에서 의심했던 파일의 경로를 확인할 수 있었다.

![Attaaaaack15](https://github.com/byeolha11/byeolha11.github.io/assets/40291473/106728ba-2a78-4c84-920c-84078d2cb54d)

- flag -> crew{C:\Users\0xSh3rl0ck\AppData\Roaming\dclogs\2023-02-20-2.dc}
