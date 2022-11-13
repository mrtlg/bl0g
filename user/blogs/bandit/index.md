---
title: overthewire - bandit 👋
description: Start using QWER - Simply Awesome Blog Starter. Built using SvelteKit and Love.
summary: 🎉 Write up for all level of bandit
published: '2022-01-13T22:00:00.000+08:00'
updated: '2022-01-13T12:00:00.000+08:00'
cover: ./cover.jpg
coverCaption: Photo by <a href="https://unsplash.com/@nitishm?utm_source=unsplash&utm_medium=referral&utm_content=creditCopyText">Nitish Meena</a> on <a href="https://unsplash.com/s/photos/blur?utm_source=unsplash&utm_medium=referral&utm_content=creditCopyText">Unsplash</a>
tags:
  - [ wargame ]
---

## Level 0

Level này cơ bản là connect tới game bandit bằng SSH với host, port, username và password cho sẵn

```bash
$ ssh bandit0@bandit.labs.overthewire.org -p 2220
```

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled.png)

## Level 0  → Level 1

Level này yêu cầu ta đọc file `readme` ******ở trong home directory để có password cho level 1.

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%201.png)

Password:

```bash
NH2SXQwcBdpmTEzi3bvBHMM9H66vVXjL
```

## Level 1 → Level 2

Level này tương tự như trên, nhưng bây giờ tên file sẽ là `-` , ta sẽ không trực tiếp dùng lệnh `cat -` bởi vì dấu `-` khi ta sử dụng nó với tư cách là argument của lệnh cat, thì nó sẽ có liên quan đến cơ chế STDIN/STDOUT của Linux. Vậy để đọc file này thì ta phải nêu ra đường dẫn tuyệt đối của nó.

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%202.png)

Password:

```bash
rRGizSaX8Mk1RTb1CNQoXTcYZWU6lgzi
```

## Level 2 → Level 3

Bài này yêu cầu ta đọc file chứa password, mà tên file này có chứa dấu cách, nếu ta ghi thẳng ra ví dụ như

```bash
$ cat spaces in this filename
```

Thì ở đây `spaces`, `in`, `this`, `filename` sẽ được cho là những argument truyền vào lệnh cat, và hệ thống sẽ tìm những file có tên là `spaces` `in` `this` và `filename` để cat ra, mục đích ta là cat file có khoảng cách, ta sẽ dùng dấu `\` có tác dụng escape cái character space đó để có vai trò trong cái string “cat spaces in this filename”

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%203.png)

Password:

```bash
aBZ0W5EmUfAf7kHTQeOwd8bauFJ2lAiG
```

## Level 3 → Level 4

Level này bảo file password nằm trong một file bị ẩn nằm trong directory là `inhere`. Để có thể list file ẩn thì ta chỉ cần thêm flag `-a` vào lệnh `ls`.

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%204.png)

Password:

```bash
2EW7BBsr6aMMoJ2HjW067dm8EgX26xNe
```

## Level 4 → Level 5

Level này để file password nằm giữa một đống file chứa những kí tự đặc biệt, để phân biệt và nhận biết loại data chứa trong file, ta có thể dùng lệnh `file`

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%205.png)

*(ở đây vì tên các file có chứa dấu `-` nên áp dụng level trên, ta sẽ dùng đường dẫn tuyệt đối)*

Thấy file `-file07` có data là ASCII text, quá rõ ràng rồi, ta cat ra thôi

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%206.png)

Password:

```bash
lrIWWI6bB37kxfiCQZqUdOIYfr6eEeqR
```

## Level 5 → Level 6

Level này file password sẽ nằm trong một đống file rác nằm trong các thư mục rác và chứa trong thư mục `inhere` và có thuộc tính như sau:

- human-readable
- có size là 1033 bytes
- không thực thi được

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%207.png)

Để làm việc này ta có thể dùng lệnh `find` và sử dụng những flag để phân loại theo thuộc tính như yêu cầu đề bài

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%208.png)

```bash
$ find . -type f -size 1033c -not -executable
./maybehere07/.file2
```

Phân tích một tí về lệnh trên, `find .` để tìm từ thư mục hiện tại là `inhere`, `-type f` để phân loại chỉ tìm đến `file` chứ KHÔNG PHẢI tìm thư mục, `-size 1033c` để chỉ ra size là 1033 bytes, `-not -executable` thì quá rõ là không thực thi được. cat ra là xong

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%209.png)

Password:

```bash
P4L4vucdmLnm8I7Vl7jG1ApGSfjYKqJU
```

## Level 6 → Level 7

Tương tự như bài trên, bài này file password sẽ có thuộc tính như sau:

- sở hữu bởi user `bandit7`
- sở hữu bởi group `bandit6`
- có size 33 bytes

Áp dụng các flag từ lệnh `file` như level trên, ta sẽ tìm file

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2010.png)

Oops, lần này thì ta đã bị một đống Permission denied, cũng dễ hiểu tại vì chúng ta đang ở user `bandit6` mà các directory đi qua để tìm file password thì có sở hữu bởi `bandit7` , tới đây ta có thể dùng 1 trick như sau:

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2011.png)

```bash
$ find / -user bandit7 -group bandit6 -size 33c 2>/dev/null
```

Giải thích một tí, ta sẽ chuyển hướng stderr sang /dev/null, để không phải hiện ra những cái lỗi mà gặp `Permission denied` , ta muốn nó hiện ra path chứa password cơ mà !!

Giờ thì đơn giản rồi, cat file ra thôi

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2012.png)

Password:

```bash
z7WtoNQU2XfjmMtWA8u5rN4vzqu4v99S
```

## Level 7 → Level 8

Level này password nằm trong 1 file như sau

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2013.png)

Và có gợi ý là, password nằm kế bên `millionth`

Bài này thì đơn giản, ta sẽ dùng lệnh `grep`

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2014.png)

Lệnh `grep` có tác dụng sẽ in ra cái dòng mà match cái pattern ta nhập vào lệnh grep

Password:

```bash
TESKZC0XvTetK0S9xNwm25STk5iWrBvP
```

## Level 8 → Level 9

Lần này cũng như level trên, password sẽ chứa trong 1 file mà cái dòng password ấy chỉ xuất hiện đúng 1 lần

Vì là xuất hiện một lần, nên sẽ có những dòng xuất hiện nhiều lần, ta sẽ dùng `sort` để có thể nhìn rõ hơn nó giống như thế nào

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2015.png)

Tiếp theo, ta sẽ dùng `uniq` và với flag `-u` để in ra dòng “unique” nhất, đúng với yêu cầu đề bài

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2016.png)

Password:

```bash
EN632PlfYiZbn3PhVK3XOGSlNInNE00t
```

## Level 9 → Level 10

Bài này thì password nằm trong `data.txt` và trong 1 cái strings mà người đọc được, và phía trước sẽ là một vài dấu `=`

Để chỉ in ra những kí tự người đọc được, ta sẽ dùng lệnh `strings`, và sau đó `grep` tới dấu `=` là tìm được password theo đúng yêu cầu đề bài

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2017.png)

Password:

```bash
G7w8LIi6J3kTb8A7j9LgrywtEUlyyp6s
```

## Level 10 → Level 11

Password lần này sẽ chứa trong file `data.txt`, nội dung của file này chứa đoạn bị mã hóa bằng base64, ta đơn giản chỉ là decode nó ra sử dụng lệnh `base64` và flag `-d` (decode) là được password

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2018.png)

Password:

```bash
6zPeziLdR2RKNdNYFNb6nVCKzphlXHBM
```

## Level 11 → Level 12

Password level này chứa trong file `data.txt` mà toàn bộ kí tự đều bị shift 13 kí tự.

Để có thể shift lại 13 kí tự thì ta có thể dùng lệnh `tr` có tác dụng translate các kí tự, nếu shift theo 13 kí tự thì lúc này chữ A sẽ thành M và Z sẽ thành N

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2019.png)

```bash
$ cat data.txt | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

```bash
JVNBBFSmZwKKOP0XbFXOoW8chDz5yVRv
```

## Level 12 → Level 13

Bài này cho ta 1 file hexdump và bị nén rất nhiều lớp khác nhau, ta sẽ đi từng bước để làm bài này.

Để reverse được cái data hexdump, ta có thể dùng lệnh `xxd` và dùng flag `-r`

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2020.png)

Ta sẽ truyền nó vào 1 file để phân tích tiếp

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2021.png)

`cat` ra thì mình chả hiểu cái type data này là gì cả, mình sẽ tìm hiểu bằng lệnh `file`

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2022.png)

Yes, vậy là ta đã sang đến bước giải nén một loạt lớp nén, đầu tiên sẽ là `gzip`, giải nén bằng `gzip -d`

À trước hết ta phải đổi tên file vừa reverse hexdump ra thì lệnh `gzip` mới hiểu được định dạng file

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2023.png)

Tiếp theo là `bzip2`, từ bước nay ta chỉ cần thêm extension của file và sau đó giải nén là có thể lấy được password

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2024.png)

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2025.png)

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2026.png)

Password

```bash
wbWdlBxEir4CaE8LaPhauuOo6pwRmrDw
```

## Level 13 → Level 14

Password lần này nằm trong `/etc/bandit_pass/bandit14`, và chỉ đọc được bởi user `bandit14`, đề cho ta một SSH key và bảo ta log vào level kế tiếp để có user `bandit14` và đọc được file. Vậy mục đích của Level này là bảo ta kết nối SSH thông qua key.

Hình dạng cái key trông như thế này

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2027.png)

Để kết nối `ssh` thông qua file key này, ta có thể dùng flag `-i` của lệnh `ssh` để cho vào file identity

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2028.png)

```bash
$ ssh bandit14@bandit.labs.overthewire.org -p 2220 -i sshkey.private
```

Connect thành công, cat file password ra thôi

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2029.png)

Password:

```bash
fGrHPx402xGC7U7rXKDaxiWFTOiF0ENq
```

## Level 14 → Level 15

Password level này có thể lấy được từ việc submit cái password của level 13 vào port 30000 ở [localhost](http://localhost), mình có thể đoán được cái port này sẽ được mở tại tcp ở localhost trên port 30000, ta có thể dùng `nc` để connect tới và nhập password.

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2030.png)

Password

```bash
jN2kgmIXJ6fShzhT2avhotn4Zcka6tnt
```

## Level 15 → Level 16

Level này giống level trước, nhưng lần này đề yêu cầu ta kết nối tới [localhost](http://localhost) qua port 30001 bằng cách dùng mã hóa SSL và dùng password của level trước.

Ta sẽ dùng `openssl` và với argument `s_client` để kết nối SSL. 

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2031.png)

```bash
$ openssl s_client -connect localhost:30001 -ign_eof
```

Sau đó nhập password của level trước là lấy được password của level tiếp theo

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2032.png)

```bash
JQttfApK4SeyHwDlI9SXGR50qclOAil1
```

## Level 16 → Level 17

Password lần này lấy giống level trước, nhưng sẽ có nhiều yêu cầu hơn. Đầu tiên là đề sẽ không nêu thẳng port mà ta sẽ kết nối tới mà bắt ta scan ra port ấy (trong khoảng từ 31000 đến 32000), chưa hết, ta phải tìm trong những port đang được listen thì cái nào cho kết nối SSL thì ta sẽ connect tới port đó.

Ta làm thôi, đầu tiên là scan port nè, ta sẽ dùng `nmap` và dùng các flag để dễ detect ra port

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2033.png)

```bash
$ nmap -sV -p 31000-32000 127.0.0.1
```

Trong đó:

- **-sV** : liệt kê service của những port đang OPEN
- **-p** : chọn port trong khoảng

Ta thấy, 31518 và 31790 có dịch vụ SSL, mà cái 31518 có echo gì đó giống những dịch vụ khác (theo đề thì những port khác sẽ tự trả về những gì ta nhập nên có thể đoán được cái port này cũng vậy), nên ta sẽ connect tới **31790**

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2034.png)

```bash
$ openssl s_client localhost:31790
```

Connect thành công, nhập password của level trước thì ta được cái key cho level sau

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2035.png)

## Level 17 → Level 18

Dùng file key có được ở level trước để connect tới Level 17 này.

Ở level này, ta sẽ được cho 2 files tại home directory: `passwords.old` và `[passwords.new](http://passwords.new)`. Password sẽ nằm ở file `passwords.new` và là cái dòng duy nhất thay đổi giữa 2 file trên.

Để tìm xem dòng nào bị thay đổi giữa 2 file mới cũ như này, ta có thể dùng lệnh `diff` 

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2036.png)

Dòng có dấu `<` là chỗ đã bị thay đổi và `>` là dòng được thay thế tại file mới, cũng chính là password á ông dà.

Password:

```bash
hga5tuuCLF6fFzUpnagiMN8ssu9LFrdg
```

## Level 18 → Level 19

Password lần này chứa trong file `readme` tại home, mà có người chỉnh cái `.bashrc` cho ta tự động log out khi connect tới ssh. Nói một tí về cái `.bashrc` thì nó sẽ chứa những config mà người dùng muốn config trên bash shell mỗi khi boot hệ điều hành. Vậy thì ta sẽ làm gì để bypass được chỗ này đây ???

Như đã biết thì trên mỗi terminal, ta có thể chứa nhiều loại shell khác nhau, ngoài `bash` , thì Bourne shell (`sh`) sẽ được config sẵn trên một số hệ điều hành.

Lệnh `ssh` có một flag là `-t` , công dụng của nó trên `man` là như này 

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2037.png)

Đại khái là nó sẽ thay đổi cái pseudo-terminal allocation và execute cái program ấy, vậy ta chỉ cần thêm argument `/bin/sh` là có thể connect tới ssh và dùng `sh` mà không phải qua cái `bash` và bị nó kick một cách đao đớn như z

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2038.png)

Password:

```bash
awhqfNnAbc1naukrpqDYcF95h7HoMTrC
```

## Level 19 → Level 20

Level này cho ta một file `setuid`  tên là `bandit20-do`, thực thi nó bằng việc truyền vào một argument.

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2039.png)

Nhìn vào tên của file thì ta có thể hình dung là, khi thực thi file này, nó sẽ cho ta dùng những lệnh với tư cách là user `bandit20`. Cùng test bằng việc chạy `id` nha.

So sánh khi ta chạy lệnh `id` trên user `bandit19` và trên file `setuid` nha

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2040.png)

Đó đó, các bạn thấy nó đã ra một euid là `bandit20` á, nếu level cho lằng nhằng như này thì chỉ có thể là cái file password chỉ được đọc bởi `bandit20`, cùng thử nha

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2041.png)

Rõ ràng, password chỉ được đọc bởi `bandit20`, dùng cái file kia để đọc nào

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2042.png)

```bash
VxCazJaVykI6W36BkBU0mJTCM8rR95XT
```

## Level 20 → Level 21

Lần này cho một file `setuid` như level trên, và công dụng của nó là tạo một kết nối đến `[localhost](http://localhost)` và ở port mà mình sẽ truyền vào khi thực thi file `setuid` vừa nêu, sau khi kết nối nó sẽ đọc một dòng text, nếu nó là password của level trước thì sẽ cho ta password để đến level tiếp theo.

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2043.png)

Vậy thì yêu cầu lần này đơn giản rồi, nó muốn kết nối và giao tiếp với `[localhost](http://localhost)` làm mình nhớ đến việc dùng `nc` và giao tiếp với nhau.

Đầu tiên ta sẽ tạo một listener với port bất kì trên `[localhost](http://localhost)` dùng `nc`

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2044.png)

```bash
$ nc -lnvp 4444
```

Sau đó dùng file `setuid` và truyền vào port mà mình cho lắng nghe ở `nc`, ở đây là **4444**

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2045.png)

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2046.png)

Ta thấy listener đã nhận được kết nối từ port **40016.**

Giờ chỉ cần truyền password của level trước là ra pass tiếp theo 

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2047.png)

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2048.png)

```bash
NvEJF7oVjkddltPSrdKEFOllh9V1IBcq
```

## Level 21 → Level 22

Level này có description như sau, thật ra lúc đầu đọc mình cũng chả hiểu gì

- *“A program is running automatically at regular intervals from **cron**, the time-based job scheduler. Look in **/etc/cron.d/** for the configuration and see what command is being executed.”*

Lúc này mình mới đi tìm hiểu thử `cron` là cái gì

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2049.png)

Okay, qua mấy dòng trên là mình cũng hiểu sơ sơ rồi, giờ thì theo đề bài mà mình sẽ xem trong `/etc/cron.d/` có gì    

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2050.png)

Có nhiều file nè, mà mình đang quan tâm cái `bandit22` tại nó là level tiếp theo nên `cat` ra để xem sao

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2051.png)

Okay, như lúc tìm hiểu thì nó dùng để chạy các tác vụ ngầm gì gì đấy, rất có thể những dòng lệnh trong file này đã được chạy lúc boot, mình sẽ đi tìm hiểu cái `@reboot` hay cái `* * * * *` kia là gì

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2052.png)

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2053.png)

Okay vậy là mình đã học thêm được cái `crontab` rồi, giờ quay lại bài thôi, lúc boot thì hệ thống sẽ truyền `usr/bin/cronjob_bandit22.sh` sang /dev/null, cùng xem file `sh` này có gì

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2054.png)

Nó set quyền 644 cho file `/tmp/<gì gì đấy>` và cat pass của bandit22 vô file trên, 644 là lệnh mà chủ sở hữu có quyền đọc và ghi còn user hay group khác chỉ được đọc, vậy chỉ cần đọc cái file `/tmp/<gì gì đấy>` là có pass rùi 

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2055.png)

```bash
WdDozAdTM2z9DiFEQ2mGlwngMfj4EZff
```

## Level 22 → Level 23

Tương tự level trên, ta lại phải đi đọc `/etc/cron.d` và phân tích, cùng làm nào, lần này sẽ là `/cronjob_bandit2`

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2056.png)

Không khác gì level trước, phân tích thẳng bash script thôi 😞

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2057.png)

```bash
#!/bin/bash

myname=$(whoami)
mytarget=$(echo I am user $myname | md5sum | cut -d ' ' -f 1)

echo "Copying passwordfile /etc/bandit_pass/$myname to /tmp/$mytarget"

cat /etc/bandit_pass/$myname > /tmp/$mytarget
```

Phân tích một tí cái bash script này: 

- Đầu tiên sẽ set biến `myname` thành output của lệnh `whoami`
- Set biến `target` từ việc echo một string có chứa biến `myname`, md5  nó và cut string từ lệnh `md5sum` đến dấu cách đầu tiên.
- In ra “Copying …”
- Và truyền output của password đến `/tmp/$mytarget`

Password ta cần tìm là của `bandit23`, dựa vào bash script trên, ta sẽ tự thực thi lệnh như file đấy để lấy được tên file chứa password của `bandit23`

Mỗi khi connect tới level nào đó và `whoami` thì tên user sẽ có định dạng như kiểu `bandit23`, nên biến `myname` ta sẽ cho là ***“bandit23”**,* giờ chỉ cần lấy được output của `$mytarget` là được

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2058.png)

```bash
8ca319486bfbbc3663ea0fbe81326349
```

Okay, đọc `/tmp/8ca319486bfbbc3663ea0fbe81326349` thôi

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2059.png)

Password:

```bash
QYw0Y2aiA672PsMmh9puTQuhoz8SyR2G
```

## Level 23 → Level 24

Tiếp tục một bài về `crontab`, những bước đầu tiên thì như nhau thôi. Như thường lệ, ta sẽ đọc file `/usr/bin/cronjob_bandit24.sh`

```bash
#!/bin/bash

myname=$(whoami)

cd /var/spool/$myname/foo
echo "Executing and deleting all scripts in /var/spool/$myname/foo:"
for i in * .*;
do
    if [ "$i" != "." -a "$i" != ".." ];
    then
        echo "Handling $i"
        owner="$(stat --format "%U" ./$i)"
        if [ "${owner}" = "bandit23" ]; then
            timeout -s 9 60 ./$i
        fi
        rm -f ./$i
    fi
done
```

Đọc hiểu tí về script này:

- Đầu tiên nó sẽ gán output của lệnh `whoami` vào biến `myname`
- Sau đó `cd` đến `/var/spool/$myname/foo`
- Sau đó in ra dòng như trong script
- Duyệt tất cả các file trong thư mục, và nếu sở hữu của file là `bandit23` thì sẽ thực thi file sau khi timeout 90 giây
- Xóa file

Vậy thì nhiệm vụ của ta sẽ là viết một file bash script và cho chứa trong `/var/spool/$myname/foo` mà ở đây myname sẽ là bandit24 để chương trình thực thi.

Nội dung của file script thì sẽ là câu lệnh truyền password của `bandit24` trong `/etc/bandit_pass/bandit24` (format này thì ta có thể tự suy từ những level trước), truyền sang một file nào đó bên ngoài để ta đọc. Đề có gợi ý ta tạo một thư mục bên ngoài để dễ quản lý, mình sẽ tạo trong `/tmp`  

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2060.png)

Sau đó, mình sẽ viết một bash script với nội dung sau

```bash
#!/bin/bash
cat /etc/bandit_pass/bandit24 > /tmp/tmp_ne/pw
```

Một script đơn giản như mình đã nói ý tưởng từ trước, truyền thẳng pass của bandit24 vào `/tmp/tmp_ne/pw`, tất nhiên trước đó mình đã cấp quyền `777` cho directory `tmp_ne` để `bandit24` sau khi thực thi file thì có thể truyền được mà không bị Permission Denied. Đừng quên cấp `777` cho cả file bash script luôn.

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2061.png)

Sau đó chỉ cần copy qua `/var/spool/bandit24/foo` và đợi 60 giây rồi check file `pw`

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2062.png)

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2063.png)

Password:

```bash
VAfGXJ1PBSsPSnvsjI8p759leLZ9GGar
```

## Level 24 → Level 25

Ở level này, đề bảo chúng ta có một daemon đang lắng nghe ở port **30002** và bảo nếu ta đưa nó pass của bandit24 và 4 digit pincode, nó sẽ trả cho ta password của bandit25. Thử xem kết nối như nào đã

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2064.png)

Okay vậy ta cần phải viết một cái script để bruteforce nhè nhẹ rồi.

Vì ở **30002** khi ta gõ sai sẽ bảo ta gõ tiếp chứ không ngắt kết nối, nên ta có thể truyền một file chứa sẵn password và những số pincode từ 0000 đến 9999 để bruteforce thẳng, file đấy có thể tạo từ bash script như sau

```bash
#!/bin/bash
for i in {0..9999}
do
			echo VAfGXJ1PBSsPSnvsjI8p759leLZ9GGar $i >> no.txt
done
```

Sau đó chạy nc đến và truyền file `no.txt` 

```bash
$ nc localhost 30002 < no.txt
```

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2065.png)

Password:

```bash
p7TaowMYrmu23Ol8hiZh9UvD0O9hpx8d
```

## Level 25 → Level 26

Đề lần này bảo ta vào bandit26 rất dễ nhưng shell của bandit26 không phải là ***/bin/bash*** và bảo ta tìm hiểu về nó và tìm cách break out nó, giờ ta xem trong bandit25 có gì đã

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2066.png)

Một file sshkey, ta sẽ dùng key này để connect tới bandit26

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2067.png)

Vừa vào thì level đã đá ta ra ngoài rồi, lúc này thì mình cũng chưa hiểu gì hết, nhưng theo yêu cầu của đề thì để xem thử `bandit26` dùng shell gì, quay lại với `bandit25` và đọc ***/etc/passwd*** 

```bash
$ cat /etc/passwd | grep bandit26
```

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2068.png)

Oops, ***/usr/bin/showtext*** là cái gì kia :)), ta đi tìm hiểu nó thử

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2069.png)

Một shell script có nội dung như trên, ta sẽ phân tích nó

- Dòng đầu là shebang như thường
- Dòng tiếp theo là set cái terminal emulation là `linux`
- Tiếp theo là thực thi lệnh `more ~/text.txt`
- Cuối cùng là exit

Mấy lệnh khác thì ta có thể hình dung hoặc đoán được ý nghĩa, nhưng còn `more` là gì, theo `man`, `more` là:

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2070.png)

Đại khái là nó sẽ hiển thị nội dung của file trên giao diện dòng lệnh theo trang.

Để vào giao diện của `more`, ta phải đổi lại size của cửa sổ terminal sao cho không chứa hết nội dung của file được `more`, ở đây thì ta sẽ chỉnh sao cho chữ bandit làm từ `figlet` kia nhỏ hơn cửa sổ như sau thì khi kết nối sẽ vô được giao diện của `more`

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2071.png)

Sau đó nhấn `h` sẽ vào được giao diện ***help*** của `more`

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2072.png)

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2073.png)

Những lệnh khác thì trông có vẻ chưa có ý tưởng phải làm gì với nó, nhưng với `v` thì sẽ chạy `/usr/bin/vi` là text editor `vim` mà mình yêu thích dùng bởi nó có command mode rất mạnh, vô nó thôi

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2074.png)

Vào vi thành công, giờ ta có thể vào command mode để đọc password nào, dùng lệnh `:e /etc/bandit_pass/bandit26` để đọc pass của 26 nào

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2075.png)

Password:

```bash
c7GvcKlw9mC7aUQaPx7nwFstuAIBw1o1
```

## Level 26 → Level 27

Description nó như sau

```bash
Good job getting a shell! Now hurry and grab the password for bandit27!
```

Uầy, vậy thì ở level trước mình chỉ mới đọc file pass từ vim thôi, mình cần lấy được shell cơ, mà bước này thì cũng đơn giản, quay lại từ chỗ vào được vim nha, thay vì mở file pass thì ta sẽ set lại biến SHELL thành ***/bin/bash*** là có thể dùng bash mà không phải ***showtext*** nữa

```bash
:set shell=/bin/bash
```

Sau đó thực thi `:shell` là có thể vô được ***/bin/bash*** 

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2076.png)

Một file `bandit27-do` rất giống với file setuid giống level ở phía trên trên, kiểm tra thì đúng như vậy

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2077.png)

Dùng nó để đọc pass của `bandit27` thôi

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2078.png)

Password:

```bash
YnQpBuifNMas1hcUFk70ZmqkhUU2EuaS
```

## Level 27 → Level 28

Lần này level cho ta một link git repo có chứa password, bảo ta clone về và tìm password.

Mình clone tại home thì không có quyền nên mình sẽ clone trong `tmp`

```bash
$ git clone ssh://bandit27-git@localhost/home/bandit27-git/repo
```

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2079.png)

Khi mình dùng lệnh này, output trả về rằng không kết nối được do dùng đang cố gắng kết nối tới port 22 mặc định của `ssh`, mà ta cần connect tại port 2220, nên phải thêm tại url clone là

```bash
ssh://bandit27-git@localhost:2220/home/bandit27-git/repo
```

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2080.png)

Thành công clone `repo` về rồi, đọc README là có file password

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2081.png)

Password:

```bash
AVanL161y9rsbcJIsFHuw35rjaOM19nR
```

## Level 28 → Level 29

Level lần này giống trước, ta sẽ clone cái repo về và xem trong README thử nha

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2082.png)

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2083.png)

Quào, có vẻ password đã bị READACTED, kiểm tra trong log thử

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2084.png)

Thấy có commit tại master để ***“fix info leak”*** có thể là chỉnh cái password kia, ta sẽ diff 2 cái commit gần nhất để xem sự thay đổi như thế nào

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2085.png)

Ố dề, vậy là suy đoán của ta đã đúng, lấy pass thôi

Password:

```bash
tQKvmcwNYcFS6vmPHIUSI3ShmsrQZK8S
```

## Level 29 → Level 30

Tiếp tục là một bài về `git` , làm những bước như bài trước thôi

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2086.png)

Kiểm tra thử commit log

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2087.png)

Oops, đọc message thì có thể đoán ta không lấy được gì từ đây cả, bế tắc à?? Không, đây chỉ là commit log từ branch master, thử xem còn branch khác không

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2088.png)

Quào, một đống luôn, thử checkout tới lần lượt từng cái và xem thử có commit nào chứa pass không, đầu tiên là vào `remotes/origin/dev` nha

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2089.png)

Kiểm tra commit log

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2090.png)

Okay, ta thấy khá nhiều commit, thử xem 2 cái gần nhất

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2091.png)

Yes, đúng ý luôn, lấy pass thôi

Password:

```bash
xbhV3HpNGlTIdnjUrdAlPzc2L6y9EOnS
```

## Level 30 → Level 31

Tiếp tục lại là một bài về `git`, làm như những bước ban đầu của level trên, check `git log` và check các branch khác.

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2092.png)

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2093.png)

Chả có gì đặc biệt cả, vậy biết đi tìm pass ở đâu đây?? Hmmm

Sau một hồi tra cứu các thứ, đọc lại `man` và thử, thì mình phát hiện ra chức năng `tag` trong git.

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2094.png)

Chưa rõ ràng nhỉ, search Google thôi

***“Tag là chức năng đặt tên một cách đơn giản của Git, nó cho phép ta xác định một cách rõ ràng các phiên bản mã nguồn (code) của dự án. Ta có thể coi tag như một branch không thay đổi được. Một khi nó được tạo (gắn với 1 commit cụ thể) thì ta không thể thay đổi lịch sử commit ấy được nữa.”***

Yes, học thêm một chức năng mới của git rồi, dùng nó thôi

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2095.png)

Có một tag `secret`, show nó ra thì được password quá đẹp

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2096.png)

Password:

```bash
OoffzGDlzhAlerFJ2cAiz1D41JW1Mhmt
```

## Level 31 → Level 32

LẠI là một bài về `git`, làm như nãy giờ thôi nào kkk. Đọc file README thì có nội dung như sau

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2097.png)

Nó bảo ta lần nảy phải push lên remote repo cái file key.txt với nội dung ***“May I come in?”*** từ branch master, vậy ta sẽ làm thôi.

Đầu tiên là tạo file `key.txt` với nội dung như yêu cầu

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2098.png)

Hiện tại đã ở branch `master` nên ta không cần checkout sang chỗ khác, stage và commit lên thôi

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%2099.png)

Ủa gì z, `.gitignore` đã chặn file của ta rồi, đọc thử nó nè

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%20100.png)

Chính xác, nó ignore những file có extension `txt`, vậy ta cần thêm flag `-f` (force) để “ép” git add vào vùng staging

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%20101.png)

Add được rồi nè, commit rồi push thôi

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%20102.png)

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%20103.png)

Password:

```bash
rmCBvG56y58BXzv98yZGdO7ATVL5dW8y
```

## Level 32 → Level 33

Description lần này rất ngắn gọn

```bash
After all this git stuff its time for another escape. Good luck!
```

Là một cái ***jail*** sao? Connect thử

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%20104.png)

Chính xác luôn, những bài jail như này thì mình phải thoát được cái xàm xàm của challenge và thực thi lệnh tùy thích, ở đây là nó sẽ tự động VIẾT HOA những từ mà ta nhập vào.

Với bài này thì mình đã từng gặp ở một event CTF rồi (chắc bài đó lấy ý tưởng từ đây), thì thằng terminal của Linux sẽ define sẵn một vài variable, mà những variable đó define với tên được viết hoa tất cả luôn, nó có thể chứa những config nào đó của terminal hoặc những config của linux. Một vài ví dụ:

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%20105.png)

Test thử trên challenge nè

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%20106.png)

Hiểu ý tưởng rồi, ngoài những biến khởi tạo sẵn mà mình đã show ở trên, ta còn có `$0` .

`$0` sẽ là tên của chương trình mà cụ thể là cái shell, chạy thử trên máy thường

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%20107.png)

Ở đây mình dùng shell `zsh` nên output ra shell `zsh`, khi ta dùng lệnh `file` thì thấy nó là một file ELF thực thi được, vậy quay lại challenge và cho chạy `$0` thôi

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%20108.png)

Hí hí xong gòi nha, đọc pass thôi

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%20109.png)

Password:

```bash
odHo63fHiFqcWWJG9rLiLDtPm45KzUKy
```

Ngoài lề tí, lúc mình làm tới gần cuối thì bạn mình có hỏi, sao ta không xài $SHELL luôn, thì ta thử dùng $SHELL nha

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%20110.png)

Nó đã đưa mình vô jail lại, vậy là cái biến SHELL này đã thực thi một shell khác, cụ thể là cái này

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%20111.png)

Còn `$0` của nó là `sh`

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%20112.png)

## Level 34

![Untitled](https://raw.githubusercontent.com/mtiennnnn/mtiennnnn/gh-pages/_posts/2017/bandit%2097d0d45daa614ecdb5e6053f78d83139/Untitled%20113.png)
