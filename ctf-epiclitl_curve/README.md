# Epiclit'l' Curve

A medium/hard crypto challenge for the crazy madmen mathematicians out there.

> I like high-school math. Three variables, one constant, one equation. What can go wrong?
>
> Good luck solving this one! The source is provided below.

## How to run

The image was tested with podman, but should work fine with docker as well.

0. Clone the repo and cd to the root folder of the particular challenge
1. Build the image: `podman build -t ctf-epiclitl_curve:latest .`
2. Run the image: `podman rm -f ctf-epiclitl_curve:latest; podman run --name ctf-epiclitl_curve -it --rm -p 1337:1337 -e BACKEND_PORT=1337 ctf-epiclitl_curve:latest`

Connect on port 1337.

<details>
<summary>Writeup (Spoiler)</summary>

Let us connect to the service first:

```
[steve@todo ctf-epiclitl_curve]$ nc localhost 1337
I got a simple challenge for you! You are in control of x, y, and z. They need to be positive integers with at most 200 digits. Supply some values that satisfy the following equation:

x/(y+z) + y/(x+z) + z/(x+y) = 10
\frac{x}{y+z} + \frac{y}{x+z} + \frac{z}{x+y} = 10 (the same, but in LaTeX format)

We would appreciate if you wouldn't DoS the public instance with a high number of connections or requests. The source is provided for you to run your own instance.

You have 30 seconds to send your answer. Good luck!

Enter the value for x: 1
Enter the value for y: 2
Enter the value for z: 3
Nope, that was not the correct answer. The correct answer was 10, but you supplied ~1.70000000
```

The challenge seems rather simple at first. We need to find three positive integers that satisfy the given equation. We are in control of `x`, `y`, and `z` and we gotta arrange them in a way that the equation holds true. Whenever the left side of the equation is equal to 10, we win. Once we double-check the source code, we can confirm that this is really all it does:

```go
	xF := new(big.Float).SetInt(x)
	yF := new(big.Float).SetInt(y)
	zF := new(big.Float).SetInt(z)

	sum := new(big.Float).Add(
		new(big.Float).Quo(xF, new(big.Float).Add(yF, zF)),
		new(big.Float).Add(
			new(big.Float).Quo(yF, new(big.Float).Add(xF, zF)),
			new(big.Float).Quo(zF, new(big.Float).Add(xF, yF)),
		),
	)

	four := new(big.Float).SetFloat64(10)
	tolerance := new(big.Float).SetFloat64(1e-10) // that's 0.0000000001, so should be okay
	diff := new(big.Float).Sub(sum, four)
	absDiff := new(big.Float).Abs(diff)
	if absDiff.Cmp(tolerance) < 0 {
		fmt.Fprint(conn, flagText)
    }
```

### Method 1: The Cryptographer Way - Cooler :)

Let's go back to our equation:


$\frac{x}{y+z} + \frac{y}{x+z} + \frac{z}{x+y} = 10$

It's not immediately clear how can we arrange the numbers in a way that the equation holds true. z3 for example doesn't seem to be able to solve this equation in my experience once we specify that we only accept whole and positive numbers only. Brute forcing is also no option, since we have three variables and `math/big` suggests that we are probably dealing with very large numbers.

Thankfully there is a Quora post and a mathoverflow thread that presents a very similar equation and a detailed walkthrough on it. [Quora post](https://www.quora.com/How-do-you-find-the-positive-integer-solutions-to-frac-x-y+z-+-frac-y-z+x-+-frac-z-x+y-4) and the [mathoverflow thread](https://mathoverflow.net/a/227722)

They both describe a method to solve the equation $\frac{x}{y+z} + \frac{y}{x+z} + \frac{z}{x+y} = 4$. We can multiply by a common multiple of the denominators to get rid of the fractions and get a polynomial. Then we can get a [Diophantine equation](https://en.wikipedia.org/wiki/Diophantine_equation).

At this point we should notice that the equation is homogeneous. This means that we can scale the solution by a constant and it will still be a solution.

If we follow the Quora post, we end up with the following equation in our case:

$y^2 = x^3 + 517x^2 + 416x$

Or in Weierstrass form for SageMath:

```py
N = 10
e = 4 * N**2 + 12 * N - 3
f = 32 * (N + 3)

eq = EllipticCurve([0, e, 0, f, 0])
```

Once we have the curve defined, we can utilize SageMath's built-in functions to find the rank of the curve and its generators. These generators correspond to points on the curve that can generate all other points through addition. So we can use:

```py
rank = eq.rank()
generators = eq.gens()
```

Now we can take the first generator and apply the [chord and tangent](https://www.quora.com/What-is-an-intuitive-explanation-for-the-group-law-for-addition-of-elliptic-curves) method to find the other points on the curve. This will work and give us a valid solution, because of the homogeneity of the equation. But it still won't satisfy the constraints of positive integers. This means that we effectively need to repeat the technique until we finally get a solution that satisfies the constraints.

This will do the job:

```py
def find_original_point(P, N):
    a, b = P[0], P[1]
    x = (8 * (N + 3) - a + b) / (2 * (N + 3) * (4 - a))
    y = (8 * (N + 3) - a - b) / (2 * (N + 3) * (4 - a))
    z = (-4 * (N + 3) - (N + 2) * a) / ((N + 3) * (4 - a))
    lcm_denominator = lcm(denominator(x), lcm(denominator(y), denominator(z)))
    return [x * lcm_denominator, y * lcm_denominator, z * lcm_denominator]
```

Once we repeat it enough times, we can get to the solution. I have prepared a [poc.sage](./poc.sage) script that calculates the required values for a given `N` and submits the results to the backend. If we run it, we can see:

```
[steve@todo ctf-epiclitl_curve]$ python3 ./poc.sage.py 
P: (-416 : 4160 : 1)
Original point: [9, -7, 19]
m=1 didn't yield in positive values
m=2 didn't yield in positive values
m=3 didn't yield in positive values
m=4 didn't yield in positive values
m=5 didn't yield in positive values
m=6 didn't yield in positive values
m=7 didn't yield in positive values
m=8 didn't yield in positive values
m=9 didn't yield in positive values
m=10 didn't yield in positive values
m=11 didn't yield in positive values
m=12 didn't yield in positive values
x = 269103113846520710198086599018316928810831097261381335767926880507079911347095440987749703663156874995907158014866846058485318408629957749519665987782327830143454337518378955846463785600977
y = 4862378745380642626737318101484977637219057323564658907686653339599714454790559130946320953938197181210525554039710122136086190642013402927952831079021210585653078786813279351784906397934209
z = 221855981602380704196804518854316541759883857932028285581812549404634844243737502744011549757448453135493556098964216532950604590733853450272184987603430882682754171300742698179931849310347
[+] Opening connection to localhost on port 1337: Done
[+] Receiving all data: Done (688B)
[*] Closed connection to localhost port 1337
Congratulations! You somehow found a possible answer to an almost impossible equation.

All credits go to these amazing people, who figured out the hard math and made it possible for me to understand this problem:
- http://publikacio.uni-eszterhazy.hu/2858/1/AMI_43_from29to41.pdf
- https://www.quora.com/How-do-you-find-the-positive-integer-solutions-to-frac-x-y+z-+-frac-y-z+x-+-frac-z-x+y-4
- https://mathoverflow.net/a/227722
- https://www.youtube.com/watch?v=Ct3lCfgJV_A
- https://www.simonsfoundation.org/event/from-moonshine-to-black-holes-number-theory-in-mathematics-and-physics/ (from roughly 20m to 26m)

Flag: HCSC24{IF_l1f3_g1v3s_y0u_4_b4n4n4_3qu4t10n_y0u_sh0uld_s0lv3_1t}
```

And we got the flag! `HCSC24{IF_l1f3_g1v3s_y0u_4_b4n4n4_3qu4t10n_y0u_sh0uld_s0lv3_1t}`.

### Method 2: The Hacker Way - Less cool, but easier

For this to work, we need to notice that the checker accepts floating point numbers with a certain tolerance:

```go
	tolerance := new(big.Float).SetFloat64(1e-10) // that's 0.0000000001, so should be okay
	diff := new(big.Float).Sub(sum, four)
	absDiff := new(big.Float).Abs(diff)
	if absDiff.Cmp(tolerance) < 0 {
		fmt.Fprint(conn, flagText)
	}
```

This opens up a whole new world of possibilities. Even z3 is capable of solving this equation, if we allow it to work with floating point numbers. Or a simple [limit](https://en.wikipedia.org/wiki/Limit_(mathematics)) implementation should also suffice. The implementation for this one is left as an exercise to the reader.

### Update from the author: The unintended solution

When the challenge was designed, it felt pretty hard to solve at first. Unless one finds the paper, its a little too complex. The competition this was made for was intended for all kinds of age groups from the age of 16, therefore in the hope that the challenge will get more solves, I introduced the tolerance check. I assumed that it still remains hard to solve, but won't immediately give away the flag to brute forcers. Apparently I was wrong and many people managed to solve it using a simple binary search.

Although this was not the intended solution, I still believe it didn't make the challenge too easy and the people who solved it this way also deserve the flag.

</details>