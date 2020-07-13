# Beginner's Crypto
* Solved after the CTF ended :(
  * I needed to see this [post](https://stackoverflow.com/questions/7622/are-the-shift-operators-arithmetic-or-logical-in-c) sooner...
  * One of the answers includes an arithmetic version of left and right shift.
* I need to practice more crypto...

Using rewritten version that doesn't read input from file.

## First assert
`assert(len(x))<=50)`; where `x` is a string (presumably). 

This means that each unit of length of `x` is a byte (char). However,
to easily deal with integers, we can transform this constraint.

The below is pseudocode!

`len(str((int) x)) <= 2**(50*8) = 2**400`

## Second assert
`assert(str(int.from_bytes(x, "utf-8"), byteorder='big') << 10000).endswith(...)`

Assuming we already did the `(int)` conversion to change `x` to `xint`, we get

`assert(str(xint<<10000).endswith(...))`

An interesting property about left shift is that `x<<y` = `x*(2**y)`. Also, this is not relevant, but `x>>y` = `x/(2**y)`!

This means that our assertion is:

`assert(str(xint*(2**10000)).ends(with...))`

## Putting it together
Let's call our given ending sequence `R`. We will also call `L` = `len(str(R))`. 

We know that 

Eq 1: `(xint * 2**10000) % 10**L = R`. 

And knowing `L=175`, `(xint * 2*10000) % 10**175 = R`.

So, let's try to reverse this!

To reverse this, we would generally multiply both sides by the inverse of `2**10000 % 10**175`. 
However, it is not possible to find the inverse because the gcd of `2**10000` and `10**175` is not 1! 
[reasoning](https://www.geeksforgeeks.org/multiplicative-inverse-under-modulo-m/)

But, we can massage the right hand terms of `Eq 1` a bit (find the gcd and divide, basically).

`(xint * 2**10000)%10**175`
`= ((xint * 2**10000)%10**175)%5**175)`
`= (xint*2**10000)%5**175)`

We can find the inverse of `2**10000 % 5**175`!
Then, we multiply by the inverse:

`(xint * 2**10000 * inverse = R * inverse) % 5**175`

`(xint = solution) % 5**175`

Keep in mind that `5**175 > 2**400`, meaning the solution we get will not be cut off in a weird way.
After getting the solution, we can convert the integer to bytes, then to a string. Plug into the challenge
and make sure that we pass both assertions!

I tried to use `Sage`... but couldn't wrap my head around it... I ended up just using `Python`. The script is
included in the write-up repository.

