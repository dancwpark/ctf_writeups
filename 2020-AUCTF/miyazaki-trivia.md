I participated in AUCTF 2020, which was hosted by Auburn University Ethical Hacking Club (AUECH). It was designed to be friendly towards new CTFers so I thought I'd take a crack at it over the weekend as part of a smooth transition. 
I made a team (something to do with coffee) of one and tried some challenges.

The first challenge that I tried (besides some fun trivia type questions) was `Miyazaki Trivia`, the first web challenge.

There are two things I should mention before I go into the write-up.
* I used to hate web challenges (for no real reason).
* I spent way too much time thinking the title was a hint at Miyazaki films... like My Neighbor Totoro...

Anyways! On to the pretty simple write-up.

## Miyazaki Trivia
The web challenge pointed to a webiste (shocker). The site is no longer available but all the source code is available at AUEHC's github page.
`https://github.com/auehc/AUCTF-2020/tree/master/Web/web1`
All the page said was 

`Find this special file.`

Looking at the page source, this is literally all it was.

{% gist 74ccb711284704047a5cdda971f565f9 %}

After thinking for a bit, I remembered from however many years ago that this probably meant the `robots.txt` file. You can read more about `robots.txt` at this [site](https://www.robotstxt.org/robotstxt.html).

I used `wget` to download the file.

`wget challenges.auctf.com:30022/robots.txt`

Reading the file, I saw

-
VIDEO GAME TRIVIA: What is the adage of Byrgenwerth scholars?

MAKE a GET request to this page with a header named 'answer' to
submit your answer.
-


My first thought was, Byrgenwerth does not sound like anything that would be in Totoro's or Kiki's universe. Luckily, I have a friend who is very much obsessed with Bloodborne. He told me that the adage is `fear the old blood`. 

So with this knowledge, I crafted the `GET` request using `telnet`. 

{% gist c1c850ba8576654b54b41bdf797d3ec2 %}

Doing this returned the flag and message!

`Master Willem was right.auctf{f3ar_z_olD3_8l0dD}`

