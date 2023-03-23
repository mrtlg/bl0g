---
title: HackTheBox Apocalypse 2023
description: HoxTheBack
summary: Write up
cover: ./cover.jpg
published: '2023-03-23T20:00:00.000+07:00'
updated: '2023-03-23T20:00:00.000+07:00'
toc: false
tags:
  - [ ctf ]
---

Lâu rồi không viết gì (do lười), vừa rồi có cái HTB Apocalypse 2023 diễn ra vài ngày mà mình hơi bận nên chưa kịp chơi, nay có tí thời gian rảnh, cũng là ngày cuối của event nên mình vào ngồi nghịch ra được vài bài nên sẵn tiện làm sống lại cái blog này luôn (chắc sống được hôm nay thôi)

# Gunhead

Một bài cho giao diện web như sau

![](https://i.imgur.com/6P8EY0B.png)

Trong đó có cái terminal nhỏ nhỏ xinh xinh kia, mình vào xem có gì luôn

![](https://i.imgur.com/yucuhHd.png)

Nhập `/help` thì thấy có các lệnh có thể sử dụng trên web, nhìn sơ qua có thể đoán được bài này có thể Command Injection bằng cái lệnh ping kia.

Thật vậy, khi đọc source 

![](https://i.imgur.com/iMi4PtE.png)

Dễ thấy lệnh ping được thực thi từ hàm `shell_exec` - là một hàm có thể chạy được lệnh hệ thống. Tuy nhiên thì cũng như comment của đoạn code này nói, ip mà người dùng nhập vào hoàn toàn không dược sanitize nên chỗ này Command Injection rất dễ

```
/ping 1; cat /*
```

![](https://i.imgur.com/WwDEVb1.png)


# Drobots
Lần này là một bài dùng python flask, mới vào có trang đăng nhập sau

![](https://i.imgur.com/pAQWN5T.png)

Hmm, vậy phải làm việc với database đồ các thứ rồi, đọc source xem thử web có route như nào và xử lí đăng nhập ra sao

```python=
# database.py
def login(username, password):
    # We should update our code base and use techniques like parameterization to avoid SQL Injection
    print(username, file=sys.stderr)
    print(password, file=sys.stderr)
    user = query_db(f'SELECT password FROM users WHERE username = "{username}" AND password = "{password}" ', one=True)
    print(f'SELECT password FROM users WHERE username = "{username}" AND password = "{password}"',file=sys.stderr)
    if user:
        token = createJWT(username)
        return token
    else:
        return False
```

```python=
# routes.py
from flask import Blueprint, render_template, request, session, redirect
from application.database import login
from application.util import response, isAuthenticated

web = Blueprint('web', __name__)
api = Blueprint('api', __name__)

flag = open('/flag.txt').read()

@web.route('/')
def signIn():
    return render_template('login.html')

@web.route('/logout')
def logout():
    session['auth'] = None
    return redirect('/')

@web.route('/home')
@isAuthenticated
def home():
    return render_template('home.html', flag=flag)

@api.route('/login', methods=['POST'])
def apiLogin():
    if not request.is_json:
        return response('Invalid JSON!'), 400
    
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')
    
    if not username or not password:
        return response('All fields are required!'), 401
    
    user = login(username, password)
    
    if user:
        session['auth'] = user
        return response('Success'), 200
        
    return response('Invalid credentials!'), 403
```

Theo như trong `routes.py`, Web chỉ có login mà không có register. Flag được render ngay tại `/home` nếu user login là hợp lệ. Cộng thêm đoạn query xử lí đăng nhập trong `database.py` không an toàn và có thể dễ dàng SQLi. Vậy ta chỉ cần inject làm sao vô được tài khoản của user có trong database là có thể đọc được flag.

User nào thì trong `entrypoint.sh` có 
![](https://i.imgur.com/7jHvLGl.png)

Là admin, vậy việc còn lại là dễ rồi, sqli thôi.

```
{"username":"admin","password":"\" or 1=1 -- -"}
```

![](https://i.imgur.com/1jxI9fK.png)

# Orbital

Tiếp tục là một bài mà trang chủ cho ta một form đăng nhập

![](https://i.imgur.com/nlBvwjq.png)

Như bài trước, mình đi đọc code để hiểu luồng và cách xử lí đăng nhập của Web

```python=
# database.py
def login(username, password):
    # I don't think it's not possible to bypass login because I'm verifying the password later.
    user = query(f'SELECT username, password FROM users WHERE username = "{username}"', one=True)

    if user:
        passwordCheck = passwordVerify(user['password'], password)

        if passwordCheck:
            token = createJWT(user['username'])
            return token
    else:
        return False

```

```python=
# routes.py
@web.route('/')
def signIn():
    return render_template('login.html')

@web.route('/logout')
def logout():
    session['auth'] = None
    return redirect('/')

@web.route('/home')
@isAuthenticated
def home():
    allCommunication = getCommunication()
    return render_template('home.html', allCommunication=allCommunication)

@api.route('/login', methods=['POST'])
def apiLogin():
    if not request.is_json:
        return response('Invalid JSON!'), 400
    
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')
    
    if not username or not password:
        return response('All fields are required!'), 401
    
    user = login(username, password)
    
    if user:
        session['auth'] = user
        return response('Success'), 200
        
    return response('Invalid credentials!'), 403

@api.route('/export', methods=['POST'])
@isAuthenticated
def exportFile():
    if not request.is_json:
        return response('Invalid JSON!'), 400
    
    data = request.get_json()
    communicationName = data.get('name', '')

    try:
        # Everyone is saying I should escape specific characters in the filename. I don't know why.
        return send_file(f'/communications/{communicationName}', as_attachment=True)
    except:
        return response('Unable to retrieve the communication'), 400

```

Qua file `routes.py`, ta thấy có path `/login` cũng như `/export` là có thứ để exploit, tuy nhiên để vào được export ta phải là verified user. Vậy bước đầu của bài này là ta phải đăng nhập được.

Quay lại với `database.py`, query vẫn chưa có gì an toàn hơn so với query ở bài trên, khác ở chỗ bài này query chỉ cho format string với username, còn password được bê đi chỗ khác để kiểm tra cụ thể là tại hàm `passwordVerify`, cùng xem nó kiểm tra như nào

```python=
def passwordVerify(hashPassword, password):
    md5Hash = hashlib.md5(password.encode())

    if md5Hash.hexdigest() == hashPassword: return True
    else: return False

```

Nhìn sơ qua thì có thể hiểu rằng password của ta nhập vào sẽ được md5 sau đó so sánh với hashPassword. Vậy có thể suy ra được password của các user trong database được lưu dưới dạng md5.

Cũng như bài trước, bảng uses chỉ có một account là `admin`

![](https://i.imgur.com/OxuYEl6.png)

Và cũng như bài trước, ta tiến hành SQLi thôi (query quá dễ dãi). 

```
SELECT username, password FROM users WHERE username = "{username}"
```

Để ý đoạn query này select 2 phần tử, vậy how about ta inject một đoạn union select username là admin còn phần tử 2 sẽ là một đoạn md5 hash nào đó tuỳ ý ta -> lúc này ta đã set lại password cho admin. Vậy có payload cuối

![](https://i.imgur.com/S0NPXU7.png)

![](https://i.imgur.com/Y0C20wB.png)

Có account để thành verified user rồi, ta sẽ dùng được path `/export`

```python=
def exportFile():
    if not request.is_json:
        return response('Invalid JSON!'), 400
    
    data = request.get_json()
    communicationName = data.get('name', '')

    try:
        # Everyone is saying I should escape specific characters in the filename. I don't know why.
        return send_file(f'/communications/{communicationName}', as_attachment=True)
    except:
        return response('Unable to retrieve the communication'), 400

```

Đây là xử lí cho việc nhấn export từ các file ở /home, file communication sẽ được tải về, tuy nhiên tại chỗ `send_file`, không có cơ chế sanitize hay bất cứ cái gì filter nên ta hoàn toàn có thể tải bất cứ file nào từ server về, vậy tìm file flag mà tải thôi. 

![](https://i.imgur.com/El1cl00.png)

Việc còn lại đơn giản

![](https://i.imgur.com/fuh4vku.png)

# Didactic Octo Paddle

Lần này là một bài nodejs, xem trang chủ như nào nè

![](https://i.imgur.com/3104VVB.png)

Lại login này, lại như bài trước, đọc code xử lí thôi

![](https://i.imgur.com/4VRAzWi.png)

![](https://i.imgur.com/WHG7Rgt.png)

![](https://i.imgur.com/U2a68zb.png)

Điểm giống ở bài nay so với những bài so với bài trước là chỉ có một user `admin` là có sẵn trong database, nhưng lần này thay vì xử lí theo dạng gọi query thì bài này xử lí kiểu dùng JWT, và có thêm cái mới là chức năng đăng kí tại `/register`, thử đăng kí rồi đăng nhập nào

![](https://i.imgur.com/p2RVrG4.png)

![](https://i.imgur.com/SXjvVTL.png)

Chả có gì thú vị, mua mấy cái xẻng add vào cart rồi vào /cart xem cũng chả có gì vui TvT

![](https://i.imgur.com/KQfcmLZ.png)


Ngoài ra trong routes còn có path `/admin` khá thú vị, nhìn là biết có chuyện vui trong này.

![](https://i.imgur.com/M0F4NYY.png)

Thử truy cập

![](https://i.imgur.com/yB0hLKI.png)

Chắc chắn rồi, vậy có thể hình dung được thằng JWT nó đóng vai trò kiểm tra account rồi đây, đi phân tích nó xử lí như nào

```javascript=
const AdminMiddleware = async (req, res, next) => {
    try {
        const sessionCookie = req.cookies.session;
        if (!sessionCookie) {
            return res.redirect("/login");
        }
        const decoded = jwt.decode(sessionCookie, { complete: true });

        if (decoded.header.alg == 'none') {
            return res.redirect("/login");
        } else if (decoded.header.alg == "HS256") {
            const user = jwt.verify(sessionCookie, tokenKey, {
                algorithms: [decoded.header.alg],
            });
            if (
                !(await db.Users.findOne({
                    where: { id: user.id, username: "admin" },
                }))
            ) {
                return res.status(403).send("You are not an admin");
            }
        } else {
            const user = jwt.verify(sessionCookie, null, {
                algorithms: [decoded.header.alg],
            });
            if (
                !(await db.Users.findOne({
                    where: { id: user.id, username: "admin" },
                }))
            ) {
                return res
                    .status(403)
                    .send({ message: "You are not an admin" });
            }
        }
    } catch (err) {
        return res.redirect("/login");
    }
    next();
};
```

Có khá nhiều if else, chỉ nhiều bước kiểm tra:
- Đầu tiên nó decode jwt session của mình để kiểm tra các header.
- Nếu header alg có giá trị "none" thì redirect về trang đăng nhập luôn, có thể hiểu chỗ này để né việc tấn công bằng algorithm none trong jwt, nhưng mà liệu chặn mỗi chữ "none" là đủ :v.
- Nếu alg là HS256 thì thực hiện kiểm tra như thường với tokenKey nào đó. Nếu username kiểm tra theo ID là admin thì được coi cái path `/admin`, không thì in ra dòng You are not an admin như cái hình trên.
- Đoạn sau chỉ là xử lí mấy cái ngoại lệ bên ngoài, không cần chú ý tới.

Vậy chắc chắn ta sẽ khai thác thằng JWT kia, như mình nói ở trên, liệu filter mỗi "none" là đã đủ :v. Ta có thể dễ dàng bypass chỗ này bằng cách dùng "None" hay "nonE" hay viết hoa chỗ nào cũng được, cùng thử nào, mình ném nó vào JWT.io

![](https://i.imgur.com/YkVKXh4.png)

Ta thấy tại payload, id là 2 vì đây là account ta tạo, id = 1 thì là admin. Giờ mình đổi alg trên header thành "None", id dưới payload thành 1 và bỏ luôn phần signature vì algorithm "None" thì không cần nó

![](https://i.imgur.com/Rek4ICY.png)

Ném vào Repeater thì thấy ta forge thành công

![](https://i.imgur.com/3qwX1h7.png)

![](https://i.imgur.com/zs3yoXT.png)


Tới đây thì làm gì nữa nhỉ, đọc lại chỗ routes tại `/admin`, ta còn để ý một chỗ hay ho nữa đó là chỗ này

![](https://i.imgur.com/FKCgbxD.png)

jsrender template ra các username, dễ hiểu khi mà trang web hiện như vậy á. Mà dạng render template này thì chỉ có thể nghĩ ngay tới ssti thôi, ta thử đăng kí account có username là đoạn ssti để test

```
{{:7*7}}
```

![](https://i.imgur.com/MfGUQ6L.png)

![](https://i.imgur.com/PnEzdqQ.png)

Vậy rõ ràng rồi, cái jsrender này mình chả rành nên thôi làm script kiddie tìm mấy payload của mấy anh trên mạng đọc flag luôn

![](https://i.imgur.com/OX7hE8O.png)


![](https://i.imgur.com/UJJXzZc.png)


> Hết rồi á :<. Hơi tiếc vì còn 3 bài chưa làm được, nào làm được chắc mình cũng thêm vô cho nó xôm. Cảm ơn bạn đã đọc đến đây :3
