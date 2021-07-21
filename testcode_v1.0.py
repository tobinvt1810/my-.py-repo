import dns.resolver
import ssl
import socket
import whois

domain=input("Enter the domain : ")

#---------------------------------------------------------------------------
#checking domain
w=whois.whois(domain)
if(w["domain_name"]==None):
    print("Domain does not exists!")
    exit()

#---------------------------------------------------------------------------
#checking SPF

try:
    temp=True
    result=dns.resolver.resolve(domain,"TXT")
    for i in result:
        if('v=spf1' in i.to_text()):
            print("\n*The domain contains SPF record!")
            print(' ',i.to_text())

except:
    print("\n*The domain does not contain SPF record")

#---------------------------------------------------------------------------
#checking TLS
context=ssl.create_default_context()
try :
    with socket.create_connection((domain, 443)) as sock:
        with context.wrap_socket(sock,  server_hostname=domain) as ssock:
            print("\n*The domain uses",ssock.version())
except:
    print("\n*The domain does not use TLS.")

#---------------------------------------------------------------------------
#checking MTA-STS
flag=True
try:
    result=dns.resolver.resolve('_mta-sts.'+domain,"TXT")
except:
    print("\n*The domain does not contain MTA-STS record")
    flag=False
if(flag):
    print("\n*The domain contains MTA-STS record!\n",result[0])

#---------------------------------------------------------------------------
#checking DMARC
flag=True
try:
    result=dns.resolver.resolve('_dmarc.'+domain,"TXT")
except:
    print("\n*The domain does not contain DMARC record\n")
    flag=False
if(flag):
    print("\n*The domain contains DMARC record!\n",result[0],'\n')
    
 #---------------------------------------------------------------------------
        #checking DANE
 
        import subprocess
        result=subprocess.Popen(["dig","_443._tcp."+domain,"tlsa","+dnssec","+short"], stdout=subprocess.PIPE)
        result=result.communicate()[0].decode()
        result.strip('\n')
        if(result==''):
            dane_result="*The domain does not contain DANE record"
        else:
            dane_result="*The domain contains DANE record! --- "+str(result)
 
        return render(request,"result.html", {'spf_result':spf_result, 'tls_result':tls_result, 'mtasts_result':mtasts_result, 'dmarc_result':dmarc_result, 'dkim_result':dkim_result, 'dane_result':dane_result})
