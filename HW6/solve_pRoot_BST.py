'''
Finds pth root of an integer x.  Uses Binary Search logic.  Start with a lower
bound l and go up until upper bound u.  Break the problem into halves depending
on the search logic.  The search logic says whether the mid (which is the mid
value of l and u) raised to the power to p is less than x or it is greater than
x.  Once we reach a mid that when raised to the power p is equal to x, we
return mid + 1. 

Author: Shayan Akbar
	sakbar at purdue edu

'''
def solve_pRoot(p, x): #O(lgn) solution

    #Upper bound u is set to as follows:
    #We start with the 2**0 and keep increasing the power so that u is 2**1, 2**2, ...
    #Until we hit a u such that u**p is > x
    u = 1
    while u ** p <= x: u *= 2

    #Lower bound set to half of upper bound
    l = u // 2

    #Keep the search going until upper u becomes less than lower l
    while l < u:
        mid = (l + u) // 2
        mid_pth = mid ** p
        if l < mid and mid_pth < x:
            l = mid
        elif u > mid and mid_pth > x:
            u = mid
        else:
            # Found perfect pth root.
            return mid
    return mid + 1

if __name__ =="__main__":
	M = 2527218983141387892892192083364657153147185924330479587283506755328968780293055094359061145415704814360865424801792
	p = 3
	print (M,p)
	print (solve_pRoot(p,M))

	M= 3515784477360882682736221667420017433267540440986262838454288242663141783089613991029778117576450753139629805362333
	p = 3
	print (M,p)
	print (solve_pRoot(p,M))
