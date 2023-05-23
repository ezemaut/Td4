def val(pos):
    nums = []
    for ip in pos:
        nums = ip.split('.')
        if len(nums) == 4:
            for number in nums:
                if number.isnumeric():
                    if int(number) < 1 or int(number) > 255:
                     return False
                else: return False
        else: return False
    return True



def validacion(inp:list): 
    ips = []
    for input in inp:
        ips.append(input.split(':')[1])
    return val(ips)

    
                    
    

ip = ['algo:1.1.1.1']
ips = ['algo:1.1.1.1','otro:2.1.2.2']
s = ['3.3.3.3.3']


print(validacion(ips))
print(val(s))