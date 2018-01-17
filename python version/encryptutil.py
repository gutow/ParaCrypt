import os as os
import random as random
import array as array
import time as time
import math as math

def keylist(keyfile,offset=0,nbytes=4096,chunksize=65535):
    """
	Function generates a list of arrays. Each array contains an array of integers
	that provide addresses relative to the offset of bytes with values equal to
	the list index (0 to 255).
	keyfile      file object from which the keylist will be built.
	offset       integer value for the starting offset at which bytes are read.
	nbytes       number of bytes to be read from the file. The default is 4096
	             and probably should not be any smaller than that because it is
	             hard to get a good distribution of bytes from a typical file
	             (even one that is quite random).
	chunksize   size of chunks read in from the file during keylist generation.
	             larger sizes are faster, but require more RAM. The default is
	             65kbytes and is probalby reasonable.
	"""
    #That keyfile exists and its size should already be checked.
    #Still throw error if offset is bigger than keyfile length.
    if ((offset+nbytes) >=os.stat(keyfile.name).st_size):
        raise EOFError("Offset too large to read requested number of bytes from file: "+keyfile.name)
    #We're good so initialize the array of byte addresses
    keys = [array.array('Q') for i in range(0,256)]
    #Start at offset and record offset from this offset for each byte type.
    #Do this until the requested number of bytes are encrypted. To avoid large memory usage do in
    #65kB chuncks. However, final list of addresses can be quite large
    #(8 bytes per offset). Will need 8X memory as section of keyfile size.
    # Maybe a temporary keyfile should be written? At what size do I do this?
    # Could actually keep a separate keyfile for each byte value. Then just open
    # 256 file streams and read as necessary. This could be adaptive to some fraction
    # of available memory. Not implimented at present.
    keyfile.seek(offset)
    try:
        bytechunk = keyfile.read(chunksize)
        totalcount=0
        count=0
        chunkoffset=0
        while bytechunk:
#           print(bytechunk)
            position=count+chunkoffset
            byte = bytechunk[count:count+1]
            while byte and (totalcount<nbytes):
                int_val=int.from_bytes(byte,byteorder='big')
#               print (int_val)
                keys[int_val].append(position)
                count+=1
                position+=1
                totalcount+=1
                byte=bytechunk[count:count+1]
            bytechunk=keyfile.read(chunksize)
            count=0
            chunkoffset+=chunksize
    finally:
        #Randomize the order of the addresses to generate a more random encrypted file.
        #Need to be careful here because each list can be large enough that all permutations
        #will not fit in the sequence of the Mersenne Twister random number generator. Will
        #deal with this by reseeding periodically. Will use a time interval so it will
        #only be loosely coupled to the number of cycles.
        timept = time.perf_counter()
        random.seed()
        for key in keys:
            cycles = 0
            keylen=len(key)
            if (keylen < 1):
                raise IndexError('Not enough bytes read from key file. Some bytes have no key.')
            rangelen=keylen-1
            while (cycles < keylen):
                rand1 = random.randint(0,rangelen)
                #if (rand1>=keylen):
                    #print('rand1='+str(rand1),end='')
                    #print('rangelen='+str(rangelen),end='')
                    #print(' keylen='+str(keylen))
                    #raise IndexError('Random index out of range.')
                temp = key[cycles]
                key[cycles]=key[rand1]
                key[rand1]=temp
                if (time.perf_counter() > timept+33):
                    random.seed()
                    timept= time.perf_counter()
                cycles+=1
        return(keys)
        
def headerbytes(filetoencrypt, filetoencryptname, keyfileoffset, keys, bytesinkeys):
    """
    filetoencrypt     fileobject for the openned file that will be encrypted.
    filetoencryptname string object (may be utf-8) encoding file name because the 'name' attribute
                        of file objects does not reliably reproduce all characters in file names.
    keyfileoffset     byte offset to be added to the address from the key.
    keys              list (256 elements) of arrays of addresses-offset for each possible byte value.
    bytesinkeys       number of bytes encoded in the keys.
    """
    #Figure out the minimum number of bytes to encode the offset. Encode the full address of a byte
    #of that value in 8 bytes. This will be the first 8 bytes of the encrypted data.
    headerbytes=b''
    if keyfileoffset==0:
        bytesforoffset=1
    else:
        bytesforoffset=math.ceil(math.log(keyfileoffset)/math.log(256))
    #print ('offset base 10: '+str(keyfileoffset)+' bytes to encode: '+str(bytesforoffset))
    encoded_bytesforoffset=((keys[bytesforoffset])[0] + keyfileoffset).to_bytes(8,byteorder='big')
    #print ('encoded bytesforoffset'+str(encoded_bytesforoffset))
    headerbytes+=encoded_bytesforoffset
    #Next 8 bytes tell how many bytes are used to specify the address of each byte of the offset.
    #In case it is the same number as the bytes for the offset we will use index 1 instead of 0.
    bytesperoffsetbyte = math.ceil(math.log(bytesinkeys+keyfileoffset)/math.log(256))
    #print ('bytes in keys: '+str(bytesinkeys)+' bytes to encode each byte of offset: '+str(bytesperoffsetbyte))
    encoded_bytesperoffsetbyte =((keys[bytesperoffsetbyte])[1]+keyfileoffset).to_bytes(8,byteorder='big')
    headerbytes+=encoded_bytesperoffsetbyte
    #Next bytesforoffset*bytesperoffsetbyte bytes encrypt the offset.
    offsetinbytes = keyfileoffset.to_bytes(bytesforoffset,byteorder='big')
    #print (str(offsetinbytes))
    for i in range(0,bytesforoffset):
        tempbyte= offsetinbytes[i:i+1]
        int_val=int.from_bytes(tempbyte,byteorder='big')
        #print(str(i)+','+str(tempbyte)+','+str(int_val))
        encoded_tempbyte=((keys[int_val])[i+2]+keyfileoffset).to_bytes(bytesperoffsetbyte,byteorder='big')
        #print('encoded byte '+str(i)+' of offset: '+str(encoded_tempbyte))
        headerbytes+=encoded_tempbyte
    #Next bytesforoffset*bytesperoffsetbyte encrypts the number of bytes used to encrypt the address relative to
    #the offset.
    bytesperrelativeaddress = math.ceil(math.log(bytesinkeys)/math.log(256))
    #print('Bytes per relative address: '+str(bytesperrelativeaddress))
    bytesperrelativeinbytes=bytesperrelativeaddress.to_bytes(bytesforoffset,byteorder='big')
    for i in range(0,bytesforoffset):
        tempbyte = bytesperrelativeinbytes[i:i+1]
        int_val=int.from_bytes(tempbyte,byteorder='big')
        #print(str(i)+','+str(tempbyte)+','+str(int_val))
        encoded_tempbyte=((keys[int_val])[i+bytesforoffset]+keyfileoffset).to_bytes(bytesperoffsetbyte,byteorder='big')
        #print('encoded byte '+str(i)+' of offset: '+str(encoded_tempbyte))
        headerbytes+=encoded_tempbyte
    #Next bytesperrelativeaddress encrypts the relative address of a byte containing the number of bytes
    #in the filename including the extension (assumed to be unicode, but no checking done). This does limit
    #the filename to about 250 bytes (about 2 lines of text in ascii, less if unicode).
    encryptname = os.path.split(filetoencryptname)[1]
    #print (encryptname)
    encodedname=encryptname.encode()
    bytesinname = len(encodedname)
    #print ('bytes in filename: '+str(bytesinname))
    encoded_tempbyte = ((keys[bytesinname])[bytesforoffset+4]).to_bytes(bytesperrelativeaddress,byteorder='big')
    headerbytes+=encoded_tempbyte
    #Next bytesperrelativeaddress*bytesinname bytes encrypt the filename.
    for i in range(0,bytesinname):
        tempbyte = encodedname[i:i+1]
        int_val=int.from_bytes(tempbyte,byteorder='big')
        #print(str(i)+','+str(tempbyte)+','+str(int_val))
        encoded_tempbyte=((keys[int_val])[i+bytesinname]).to_bytes(bytesperrelativeaddress,byteorder='big')
        headerbytes+=encoded_tempbyte
    #Next bytesperrelativeaddress encrypts the number of bytes representing the number of bytes of data
    #encrypted for the file.
    bytesinfile=os.stat(filetoencrypt.name).st_size
    bytesforsize = math.ceil(math.log(bytesinfile)/math.log(256))
    bytesinfileinbytes=bytesinfile.to_bytes(bytesforsize,byteorder='big')
    #print('bytes in file: '+str(bytesinfile)+' bytes to encode: '+str(bytesforsize))
    encoded_tempbyte = ((keys[bytesforsize])[bytesinname+4]).to_bytes(bytesperrelativeaddress,byteorder='big')
    headerbytes+=encoded_tempbyte
    #Next bytesperrelativeaddress*bytesforsize bytes encrypts the number of bytes of encrypted data.
    for i in range(0,bytesforsize):
        tempbyte=bytesinfileinbytes[i:i+1]
        int_val=int.from_bytes(tempbyte,byteorder='big')
        #print(str(i)+','+str(tempbyte)+','+str(int_val))
        encoded_tempbyte=((keys[int_val])[i]).to_bytes(bytesperrelativeaddress,byteorder='big')
        headerbytes+=encoded_tempbyte
    #End of header.
    #print('Bytes in header: '+str(len(headerbytes)))
    return(headerbytes)
    
def encryptbytechunk(keys, nextkeyindeces, bytesperrelativeaddress, nextbytendiness, bytechunk):
    """
    keys                        list of encryption key relative addresses
    nextkeyindeces              array of next index to use for encryption
    bytesperrelativeaddress     bytes used to encrypt relative address
    nextbyteendiness            'big' or 'little' encryption alternates. Decryption
                                will not work if start with wrong value.
    bytechunk                   a chunk of bytes to encrypt
    """
    timept = time.perf_counter()
    random.seed()
    encryptedbytechunk=b''
    chunksize=len(bytechunk)
    #print('Size of chunk to encrypt: '+str(chunksize))
    count = 0
    #print(str(bytechunk))
    tempbyte=bytechunk[count:count+1]
    while count<chunksize:
        int_val=int.from_bytes(tempbyte,byteorder='big')
#        if int_val==255:
#            print(str(tempbyte)+','+str(int_val))
        keyindex = nextkeyindeces[int_val]
#        if int_val==255:
#            print('keyindex: '+str(keyindex))
        keylen=len(keys[int_val])
#        if int_val==255:
#            print('keylen: '+str(keylen))
        if (nextkeyindeces[int_val]>=keylen):
#            print('Using random selection for value: '+str(int_val))
            if (time.perf_counter() > timept+5):
#                print('Reseeding random number generator')
                random.seed()
                timept= time.perf_counter()
            #reset the nextkeyindeces
            keyindex=random.randint(0,(keylen-1))
            nextkeyindeces[int_val]=keyindex
#        if int_val==255 :
#            print (str(count),end="")
        encryptedbytechunk+=((keys[int_val])[keyindex]).to_bytes(bytesperrelativeaddress,byteorder=nextbytendiness)
#        if int_val==255:
#            print(' OK, ',end='')
        nextkeyindeces[int_val]+=1
        if nextbytendiness=='big':
            nextbytendiness='little'
        else:
            nextbytendiness='big'
        count+=1
        tempbyte=bytechunk[count:count+1]
#        if int.from_bytes(tempbyte,byteorder='big')==255:
#            print(str(count)+' '+str(tempbyte.hex())+' ',end='')
#    print(str(count))
    return(nextkeyindeces, nextbytendiness, encryptedbytechunk)
    
def encryptfile(toencrypt,filetoencryptname,encryptkeyfile):
    """
	toencrypt         filetype object openned in binary mode with the data to be encrypted.
    filetoencryptname string object (may be utf-8) encoding file name because the 'name' attribute
                        of file objects does not reliably reproduce all characters in file names.
                        THIS SHOULD NOT INCLUDE THE PATH.
	encryptkeyfile    filetype object used to generate the encryption key (is the key).
	The returned file should be renamed or embedded in another file and deleted.
	"""
    encrfile=open('.tmpcrypt.ecr','wb')
    inputsize=os.stat(toencrypt.name).st_size
    #print('Encrypting file of '+str(inputsize)+' bytes')
    keyfilesize = os.stat(encryptkeyfile.name).st_size
    #print('using a the keyfile of '+str(keyfilesize)+' bytes.')
    #The ideal minimum keysize is at least 1.5*inputsize. Better is to be the
    #full range of the number of bytes that can be encoded by the minimum number
    #of bytes used to encode the relative offset. This potentially
    #makes the key very long, but all bytes will appear completely random.
    idealminkeysize=256**(math.ceil(math.log(inputsize*1.5)/math.log(256)))-1
    if keyfilesize > idealminkeysize:
        random.seed()
        offset=random.randint(0,(keyfilesize-idealminkeysize))
        nbytes=idealminkeysize
    else:
        #use all the bytes in the file.
        nbytes=keyfilesize-1
        offset = 0
        if (keyfilesize < (1.5*inputsize)):
            print('WARNING: Chosen key is shorter than 1.5*length of')
            print('    the file being encrypted. This is not ideal.')
    #print('Generating '+str(nbytes)+' bytes of encryption data...')
#    print('Using keyfile: '+str(encryptkeyfile.name))
    keys=keylist(encryptkeyfile,offset,nbytes,chunksize=65535)
    header=headerbytes(toencrypt, filetoencryptname, offset, keys, nbytes)
    #print('Writing '+str(len(header))+' bytes of encrypted file header...')
    encrfile.seek(0)
    encrfile.write(header)
    nextkeyindeces=[]
    for i in range(0,256):
        nextkeyindeces.append(0)
    #print('next keyindeces length: '+str(len(nextkeyindeces))+'. element 255: '+str(nextkeyindeces[255]))
    #print('Encrypting file...')
    #read through file to end and encrypt on the fly and write to the tempfile.
    startendiness='big'
    toencrypt.seek(0)
    bytechunk = toencrypt.read(65535)
    #print('Chunk of '+str(len(bytechunk))+' bytes.')
    bytesperrelativeaddress = math.ceil(math.log(nbytes)/math.log(256))
    count=0
    while bytechunk:
        #print('Encrypting chunk:'+str(count))
        nextkeyindeces,startendiness,encrchunk=encryptbytechunk(keys, nextkeyindeces, bytesperrelativeaddress, startendiness, bytechunk)
        #print(encrchunk)
        encrfile.write(encrchunk)
        bytechunk=toencrypt.read(65535)
        count+=1
        #print('Chunk of '+str(len(bytechunk))+' bytes.')
    padsize = int(round((min(1000, offset/2))))
    padsize = max(padsize,1)
    if padsize==1:
        #pick one random byte from key file
        padstart = random.randint(1,(keyfilesize-1))
    else:
        padstart= random.randint(1, (padsize-1))
    encryptkeyfile.seek(padstart)
    pad = encryptkeyfile.read(padsize)
    encrfile.write(pad)
    return (encrfile)