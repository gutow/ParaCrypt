###
#    This is part of the ParaCrypt package which provides one-time-pad encryption
#    using a combination of preshared files and a password or time-varying 
#    password.
#    Copyright (C) 2018 Jonathan Gutow
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see https://www.gnu.org/licenses/.
###
import os
import math

def decryptbytechunk(encryptkeyfile, offset, bytesperrelativeaddress, nextbytendiness, bytechunk):
    """
    encryptkeyfile              filetype object with bytes at offset+relative address that have the actual value
    offset                      offset from zero upon which the relative addresses are based.
    bytesperrelativeaddress     bytes used for relative address
    nextbyteendiness            'big' or 'little' encryption alternates. Decryption
                                will not work if start with wrong value.    
    bytechunk                   a chunk of bytes to decrypt. Must be a multiple of bytesperrelative address long.
      raises IndexError if bytechunk size not consistent with bytesperrelativeaddress.
    """
    if (len(bytechunk)%bytesperrelativeaddress!=0):
        raise IndexError('Length of bytechunk: '+str(len(bytechunk))+' is not a multiple of bytes per address" '+str(bytesperrelativeaddress))
    decrypted=b''
    count=0
    tempbytes=bytechunk[count:count+bytesperrelativeaddress]
    while tempbytes:
        relative=int.from_bytes(tempbytes,byteorder=nextbytendiness)
        address=offset+relative
        encryptkeyfile.seek(address)
        decrypted+=encryptkeyfile.read(1)
        count+=bytesperrelativeaddress
        if nextbytendiness=='big':
            nextbytendiness='little'
        else:
            nextbytendiness='big'
        tempbytes=bytechunk[count:count+bytesperrelativeaddress]        
#    print('Chunk decryption complete')
    return (nextbytendiness, decrypted)
    
def decryptheaderbytechunk(encryptkeyfile, offset, bytesperrelativeaddress, bytechunk):
    """
    encryptkeyfile              filetype object with bytes at offset+relative address that have the actual value
    offset                      offset from zero upon which the relative addresses are based.
    bytesperrelativeaddress     bytes used for relative address
    nextbyteendiness            'big' or 'little' encryption alternates. Decryption
                                will not work if start with wrong value.    
    bytechunk                   a chunk of bytes to decrypt. Must be a multiple of bytesperrelative address long.
      raises IndexError if bytechunk size not consistent with bytesperrelativeaddress.
    """
    if (len(bytechunk)%bytesperrelativeaddress!=0):
        raise IndexError('Length of bytechunk: '+str(len(bytechunk))+' is not a multiple of bytes per address" '+str(bytesperrelativeaddress))
    decrypted=b''
    count=0
    tempbytes=bytechunk[count:count+bytesperrelativeaddress]
    while tempbytes:
        relative=int.from_bytes(tempbytes,byteorder='big')
        #print('relative :'+str(relative))
        #print('offset :'+str(offset))
        address=offset+relative
        #print ('address :'+str(address))
        encryptkeyfile.seek(address)
        decrypted+=encryptkeyfile.read(1)
        count+=bytesperrelativeaddress
        tempbytes=bytechunk[count:count+bytesperrelativeaddress]        
#    print('Chunk decryption complete')
    return decrypted
    
def decryptheader(encryptedfile, encryptkeyfile):
    """
    encryptedfile     encrypted file type object. The header must be at the beginning of the file.
                      If the encrypted data is embedded within some kind of file this must be
                      a file like object (byte stream) where the zero byte is the beginning of
                      the encrypted data.
    encryptkeyfile    filetype object used to encrypt this data.
    """
    bytesread=b''   
    encryptedfile.seek(0)
    #First 8 bytes point to a byte indicating the number of bytes 
    #to encode the offset (bytesforoffset).
    bytesread=encryptedfile.read(8)
    #print('encoded bytes for offset: '+str(bytesread))
    tempaddress = int.from_bytes(bytesread,byteorder='big')
    #print('address referred to: '+str(tempaddress))
    encryptkeyfile.seek(tempaddress)
    bytesread=encryptkeyfile.read(1)
    bytesforoffset = int.from_bytes(bytesread,byteorder='big')
    #print('bytes for offset: '+str(bytesforoffset))
    #2nd 8 bytes point to a byte indicating the number of bytes used to encode the
    #address of each byte of the offset (bytesperoffsetbyte).
    bytesread=encryptedfile.read(8)
    #print('encoded bytes per offset byte: '+str(bytesread))
    tempaddress = int.from_bytes(bytesread,byteorder='big')
    #print('address referred to: '+str(tempaddress))
    encryptkeyfile.seek(tempaddress)
    bytesread=encryptkeyfile.read(1)
    #print('Read from this address: '+str(bytesread))
    bytesperoffsetbyte = int.from_bytes(bytesread,byteorder='big')
    #print('bytes per offset byte: '+str(bytesperoffsetbyte))
    #Next bytesforoffset*bytesperoffsetbyte bytes encrypt the offset.
    bytesread=encryptedfile.read(bytesforoffset*bytesperoffsetbyte)
    offset = int.from_bytes(decryptheaderbytechunk(encryptkeyfile, 0, 
        bytesperoffsetbyte, bytesread),byteorder='big')
    #Next bytesforoffset*bytesperoffsetbyte encrypts the number of bytes used to 
    #encrypt the address relative to the offset (bytesperrelativeaddress).
    bytesread=encryptedfile.read(bytesforoffset*bytesperoffsetbyte)
    bytesperrelativeaddress =  int.from_bytes(decryptheaderbytechunk(encryptkeyfile, 0, 
        bytesperoffsetbyte, bytesread),byteorder='big')
    #Next bytesperrelativeaddress encrypts the relative address of a byte containing the number of bytes
    #in the filename including the extension (assumed to be unicode, but no checking done). This does limit
    #the filename to about 250 bytes (about 2 lines of text in ascii, less if unicode).
    bytesread=encryptedfile.read(bytesperrelativeaddress)
    bytesinname=int.from_bytes(decryptheaderbytechunk(encryptkeyfile, offset, 
        bytesperrelativeaddress, bytesread),byteorder='big')    
    #Next bytesperrelativeaddress*bytesinname bytes encrypt the filename.
    bytesread=encryptedfile.read(bytesperrelativeaddress*bytesinname)
    filename=decryptheaderbytechunk(encryptkeyfile, offset, bytesperrelativeaddress, bytesread)
    #Next bytesperrelativeaddress encrypts the number of bytes representing the number of bytes of data
    #encrypted for the file (bytesforsize).
    bytesread=encryptedfile.read(bytesperrelativeaddress)
    bytesforsize=int.from_bytes(decryptheaderbytechunk(encryptkeyfile, offset, 
        bytesperrelativeaddress, bytesread),byteorder='big')    
    #Next bytesperrelativeaddress*bytesforsize bytes encrypts the number of bytes of encrypted data.
    bytesread=encryptedfile.read(bytesperrelativeaddress*bytesforsize)
    bytesofdata=int.from_bytes(decryptheaderbytechunk(encryptkeyfile, offset, 
        bytesperrelativeaddress, bytesread),byteorder='big')
    bytesinheader = encryptedfile.tell()
    #return full filename, offset, bytes per relative address, bytes of data, number of bytes in header
    #(so we can seek to the beginning of the data independent of this routine).
    return(filename, offset, bytesperrelativeaddress, bytesofdata, bytesinheader)
    
def decryptfile(decryptlocation, encryptedfile, encryptkeyfile):
    """
    decryptlocation   path to directory to store the decrypted file in.
    encryptedfile     encrypted file type object. The header must be at the beginning of the file.
                      If the encrypted data is embedded within some kind of file this must be
                      a file like object (byte stream) where the zero byte is the beginning of
                      the encrypted data.
    encryptkeyfile    filetype object used to encrypt this data.
    """
    #print('Decrypting header info...')
    filename, offset, bytesperrelativeaddress, bytesofdata, bytesinheader = decryptheader(encryptedfile, encryptkeyfile)
    #TODO: Check that a file with the same name does not exist in the current
    # working directory. If so update file name with trailing integer to 
    # differentiate it. Will have to check up through the integers as well.
    filenamedecoded=filename.decode()
    chunksize = 32767*bytesperrelativeaddress
    print('Decrypting file into \''+filenamedecoded+'\'...')
    fullpath = os.path.join(decryptlocation,filenamedecoded)
    decrypted=open(fullpath,'wb')
    encryptedfile.seek(bytesinheader)
    bytechunk = encryptedfile.read(chunksize)
    startendiness='big'
    #print('read first chunk')
    ndecrypted=0
    while bytechunk:
        #print('decrypting chunk...')
        startendiness, decryptedchunk=decryptbytechunk(encryptkeyfile, offset, bytesperrelativeaddress, startendiness, bytechunk)
        chunklength = len(decryptedchunk)
        ndecrypted += chunklength
        if ndecrypted > bytesofdata:
            decryptedchunk=decryptedchunk[:(chunklength-ndecrypted+bytesofdata)]
            ndecrypted = ndecrypted-chunklength+len(decryptedchunk)
        decrypted.write(decryptedchunk)
        #print('wrote decrypted chunk')
        bytechunk = encryptedfile.read(chunksize)
        #print('read another chunk')
        if (len(bytechunk)%bytesperrelativeaddress!=0): #we are at the end of the file/ Fix length.
            truncateto = int(math.trunc(len(bytechunk)/bytesperrelativeaddress))*bytesperrelativeaddress
            bytechunk=bytechunk[:truncateto]
    print("Encrypted  # of bytes: "+str(bytesofdata)+". Actuall # decrypted: "+str(ndecrypted)+".")
    decrypted.close()
    return('Decryption complete.')