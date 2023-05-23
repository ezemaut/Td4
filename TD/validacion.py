

def validacion(inp:list): 
    ips = []
    for input in inp:
        ips.append(input.split(':')[1])

    nums = []
    for ip in ips:
        nums = ip.split('.')
        if len(nums) == 4:
            for number in nums:
                if number.isnumeric():
                    if int(number) < 1 or int(number) > 255:
                     return False
                else: return False
        else: return False
                    
    return True

ip = ['algo:1.1.1.1']
ips = ['algo:1.1.1.1','otro:2.1.2.2']


print(validacion(ips))