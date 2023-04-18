#*******************************************************************************#
# BinaryCookieReader: Written By Satishb3 (http://www.securitylearn.net)        # 
# For any bug fixes contact me: satishb3@securitylearn.net                      #
#                                                                               #
# Updated for Python3 by bensh                                                  #
#                                                                               #
# Usage: python3 BinaryCookieReader.py /path/to/Cookie.Binarycookies            #
#                                                                               #
# Safari browser and iOS applications store the persistent cookies in a binary  #
# file names Cookies.binarycookies.BinaryCookieReader is used to dump all the   #
# cookies from the binary Cookies.binarycookies file.                           #
#                                                                               #
#*******************************************************************************#

import sys, io
from struct import unpack
from io import StringIO
from time import strftime, gmtime

if len(sys.argv)!=2:
	print("\nUsage: python3 BinaryCookieReader.py [Full path to Cookies.binarycookies file] \n")
	print("Example: python3 BinaryCookieReader.py /tmp/ios/Cookies.binarycookies")
	sys.exit(0)
	
FilePath=sys.argv[1]

try:
	binary_file=open(FilePath,'rb')
except IOError as e:
	print('File Not Found :'+ FilePath)
	sys.exit(0)
   
file_header=binary_file.read(4).decode()                         

if str(file_header)!='cook':
	print("Not a Cookies.binarycookie file")
	sys.exit(0)
	
num_pages=unpack('>i',binary_file.read(4))[0]             

page_sizes=[]
for np in range(num_pages):
	page_sizes.append(unpack('>i',binary_file.read(4))[0]) 
	
pages=[]
for ps in page_sizes:
	pages.append(binary_file.read(ps))                
	
for page in pages:
	page=io.BytesIO(page)                                    
	page.read(4)                                        
	num_cookies=unpack('<i',page.read(4))[0]              
	
	cookie_offsets=[]
	for nc in range(num_cookies):
		cookie_offsets.append(unpack('<i',page.read(4))[0]) 

	page.read(4)                                          

	cookie=''
	for offset in cookie_offsets:
		page.seek(offset)                                   
		cookiesize=unpack('<i',page.read(4))[0]         
		cookie=io.BytesIO(page.read(cookiesize))          
		
		cookie.read(4)                                   
		
		flags=unpack('<i',cookie.read(4))[0]             
		cookie_flags=''
		if flags==0:
			cookie_flags=''
		elif flags==1:
			cookie_flags='Secure'
		elif flags==4:
			cookie_flags='HttpOnly'
		elif flags==5:
			cookie_flags='Secure; HttpOnly'
		else:
			cookie_flags='Unknown'
			
		cookie.read(4)                                      
		
		urloffset=unpack('<i',cookie.read(4))[0]         
		nameoffset=unpack('<i',cookie.read(4))[0]      
		pathoffset=unpack('<i',cookie.read(4))[0]         
		valueoffset=unpack('<i',cookie.read(4))[0]     
		
		endofcookie=cookie.read(8)                    
		                        
		expiry_date_epoch= unpack('<d',cookie.read(8))[0]+978307200         
		expiry_date=strftime("%a, %d %b %Y ",gmtime(expiry_date_epoch))[:-1] 
				
		create_date_epoch=unpack('<d',cookie.read(8))[0]+978307200          
		create_date=strftime("%a, %d %b %Y ",gmtime(create_date_epoch))[:-1]
		#print create_date
		
		cookie.seek(urloffset-4)                         
		url=''
		u=cookie.read(1)
		while unpack('<b',u)[0]!=0:
			url=url+u.decode()
			u=cookie.read(1)
				
		cookie.seek(nameoffset-4)                       
		name=''
		n=cookie.read(1)
		while unpack('<b',n)[0]!=0:

			name=name+n.decode()
			n=cookie.read(1)
				
		cookie.seek(pathoffset-4)                      
		path=''
		pa=cookie.read(1)
		while unpack('<b',pa)[0]!=0:
			path=path+pa.decode()
			pa=cookie.read(1)
				
		cookie.seek(valueoffset-4)                      
		value=''
		va=cookie.read(1)
		while unpack('<b',va)[0]!=0:
			value=value+va.decode()
			va=cookie.read(1)
		

		print('Cookie: \n\t'+name+'='+value+'; \n\tdomain='+url+'; \n\tpath='+path+'; '+'\n\texpires='+expiry_date+'; \n\t'+cookie_flags)
		
binary_file.close()
