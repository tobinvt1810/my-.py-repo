from django.shortcuts import render

# Create your views here.
domain=""

def home(request):
    return render(request,'home.html')

def result(request):
    import dns.resolver
    import ssl
    import socket
    import whois

    global domain
    domain=request.GET["domain"]

    #---------------------------------------------------------------------------
    #checking domain

    w=whois.whois(domain)
    if(w["domain_name"]==None):
        return render(request,"invalid_domain.html")
    else:


        #---------------------------------------------------------------------------
        #checking SPF

        try:
            spf_result="*The domain does not contain SPF record"
            result=dns.resolver.resolve(domain,"TXT")
            for i in result:
                if('v=spf1' in i.to_text()):                  
                    spf=str(i)
                    spf_result="The domain contains SPF record <br><br>"+spf+"<br>"

                    spf=spf.strip('\"')
                    spf=list(spf.split())
                    msg="**Describes the Version of SPF.**"
                    spf_result=spf_result+"<br>Version : "+(spf[0].strip('v='))+"<br>"+msg+"<br>"

                    temp_include=[]
                    for j in spf:
                        if('include' in j):
                            temp_include.append(j.strip('include:'))
                    temp=(', '.join(map(str,temp_include)))
                    msg="**If the tag contains 'include' or 'redirect' there is a chance for recursive lookups and if it leads to more than 10 lookups it can lead to the failure of SPF authentication.**"
                    spf_result=spf_result+"<br>Include : "+temp+"<br>"+msg+"<br>"

                    all_mechanism={'+all':"Pass",'-all':"Fail",'~all':"Soft fail",'?all':"Neutral"}
                    temp=(spf[len(spf)-1]+" : "+all_mechanism[spf[len(spf)-1]])
                    if('~all' in temp):
                        msg="**It will cause non-matching messages to be marked as spam.**"
                        spf_result=spf_result+"<br>"+temp+"<br>"+msg+"<br>"
                    elif('-all' in temp):
                        msg="**Allow a sender to tell the user to reject mail that does match the record**"
                        spf_result=spf_result+"<br>"+temp+"<br>"+msg+"<br>"

                    
                    break

        except:
            pass


        #---------------------------------------------------------------------------
        #checking TLS

        context=ssl.create_default_context()
        try :
            with socket.create_connection((domain, 443)) as sock:
                with context.wrap_socket(sock,  server_hostname=domain) as ssock:
                    tls_result="The domain uses "+ssock.version()+"<br>"
        except:
            tls_result="The domain does not use TLS<br>"


        #---------------------------------------------------------------------------
        #checking MTA-STS

        try:
            result=dns.resolver.resolve('_mta-sts.'+domain,"TXT")
            temp=str(result[0])
            mtasts_result="The domain contains MTA-STS record  <br>"+temp+"<br>"
            
            temp=temp.strip('\"')
            temp=list(temp.split(';'))
            temp.pop(2)
            for i in temp:
                if("v=" in i):
                    msg="**Specifies the MTA-STS version.**"
                    mtasts_result=mtasts_result+"<br>Version : "+(temp[0].strip('v='))+"<br>"+msg+"<br>"
                elif("id=" in i):
                    msg="**Specifies the ID of MTA-STS.**"
                    mtasts_result=mtasts_result+"<br>ID : "+(temp[1].strip(' id='))+"<br>"+msg+"<br>"
            #mtasts_result=mtasts_result+"<br>Version : "+(temp[0].strip('v='))
            #mtasts_result=mtasts_result+"<br>ID : "+(temp[1].strip(' id='))

        except:
            mtasts_result="The domain does not contain MTA-STS record"
            

        #---------------------------------------------------------------------------
        #checking DMARC

        try:
            result=dns.resolver.resolve('_dmarc.'+domain,"TXT")
            temp=str(result[0])
            dmarc_result="The domain contains DMARC record <br>"+temp+"<br>"

           # temp=temp.strip('\"')
            temp=list(temp.split(';'))

            for i in temp:
                if("v=" in i):
                    msg="**Specifies the DMARC version.**"
                    dmarc_result=dmarc_result+"<br>Version :"+i.strip('v=')+"<br>"+msg+"<br>"
                
                elif("pct=" in i):
                    msg="**Specifies the percentage of email messages subjected to filtering.**"
                    dmarc_result=dmarc_result+"<br>Percentage of message filtering :"+i.strip(' pct=')+"<br>"+msg+"<br>"
                
                elif("ruf=" in i):
                    msg="**Mailbox to which forensic reports should be sent.** "
                    dmarc_result=dmarc_result+"<br>URI for forensic reports :"+i.strip(' ruf=')+"<br>"+msg+"<br>"
                
                elif("rua=" in i):
                    msg="**Mailbox to which aggregate reports should be sent.** "
                    dmarc_result=dmarc_result+"<br>URI of aggregate reports :"+i.strip(' rua=')+"<br>"+msg+"<br>"

                elif("sp=" in i):
                    msg="**Represents the requested handling policy for subdomains.**"
                    dmarc_result=dmarc_result+"<br>Policy for subdomains of the OD :"+i.strip(' sp=')+"<br>"+msg+"<br>"
                
                elif("p=reject" in i):
                    msg="**If the validation fails it will reject the mail.**"                          
                    dmarc_result=dmarc_result+"<br>Policy for organizational domain :"+i.strip(' p=')+"<br>"+msg+"<br>"

                elif("p=quarantine" in i):
                    msg="**Accept the mail but place it somewhere else other than the recipient’s inbox like Junk or Spam.**"                          
                    dmarc_result=dmarc_result+"<br>Policy for organizational domain :"+i.strip(' p=')+"<br>"+msg+"<br>"
                
                elif("p=none" in i):
                    msg="**Treat the mail the same as it would be without any DMARC validation.**"                          
                    dmarc_result=dmarc_result+"<br>Policy for organizational domain :"+i.strip(' p=')+"<br>"+msg+"<br>"
                

                elif("adkim=" in i):
                    msg="**Optional tag to represent the alignment mode for the DKIM protocol.**"
                    dmarc_result=dmarc_result+"<br>Alignment mode for DKIM :"+i.strip(' adkim=')+"<br>"+msg+"<br>"
                
                elif("aspf=" in i):
                    msg="**Optional tag to represent the alignment mode for SPF.**"
                    dmarc_result=dmarc_result+"<br>Alignment mode for SPF :"+i.strip(' aspf=')+"<br>"+msg+"<br>"
                
                elif("rf=" in i):
                    msg="Forensic reporting format"
                    dmarc_result=dmarc_result+"<br>Forensic reporting format :"+i[4:]+"<br>"+msg+"<br>"

        except:
            dmarc_result="The domain does not contain DMARC record"
       

        #---------------------------------------------------------------------------
        #checking DANE

        import subprocess
        result=subprocess.Popen(["dig","_443._tcp."+domain,"tlsa","+dnssec","+short"], stdout=subprocess.PIPE)
        result=result.communicate()[0].decode()
        result.strip('\n')
        if(result==''):
            dane_result="The domain does not contain DANE record"
        else:
            dane_result="The domain contains DANE record! <br>"+str(result)+"<br>"

        return render(request,"result.html", {'spf_result':spf_result, 'tls_result':tls_result, 'mtasts_result':mtasts_result, 'dmarc_result':dmarc_result, 'dane_result':dane_result }) 


############################################################################################################################################################################################################################

def final(request):
    
    import dns.resolver
    selector=request.GET["selector"]
    domain=request.GET["domain"]


    try:
        result=dns.resolver.resolve(selector+'._domainkey.'+domain,"TXT")
        temp=str(result[0])
        dkim_result="The domain contains DKIM record! ---<br>"+temp+"<br>"

        temp=temp.strip('\"')
        temp=list(temp.split(';'))
        for i in temp:
            if("v=" in i):
                dkim_result=dkim_result+"<br>Version : "+i.strip('v=')
            elif("k=" in i):
                dkim_result=dkim_result+"<br>Key type : "+i.strip(' k=')
            elif("p=" in i):
                dkim_result=dkim_result+"<br>Public key : "+i.strip(' p=')

    except:
        dkim_result="The domain does not contain DKIM record or the selector does not match"
    
    return render(request,"final.html",{'dkim_result':dkim_result})        