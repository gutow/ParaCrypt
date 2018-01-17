#These utilities are used to take a key file stream and generate a
#stream of randomized values based on the key and a password. The idea is
#that the random value for a particular address can be regenerated using
#the same key file and password.
import random as random
import os as os
from math import trunc

def randomizekeychunk(seedvalue,bytechunk):
    '''
    seedvalue      is a seed value string, bytes or number > 32 bits for the random number generator 
                   (mersene twister assumed).
                   This is best based on either the password provided by the user or the required number of bytes
                   from the previous randomized chunk in the keyfile.
    bytechunk      is the bytes to be randomized by Xoring with the random bytes from the random number generator.
    '''
    newbytechunk=b''
    random.seed(a=seedvalue, version=2)
    count=0
    thisbyte=bytechunk[0:1]
    while thisbyte:
        tempint=int.from_bytes(thisbyte,byteorder='big')
        tempint=(random.randint(0,255))^tempint
        newbytechunk+=tempint.to_bytes(1,byteorder='big')
        count+=1
        thisbyte=bytechunk[count:count+1]
    return(newbytechunk)

def randomizefile(torandomize, seedvalue):
    '''
    torandomize    file type object to randomize and write to a temporary random file.
    seedvalue        initial seedvalue (user password > 32 bits, 4 bytes, 12+ better)
    returns        the randomized file as a file object.
    '''
    #uses randomizekeychunk. Because that function uses the Mersene Twister, it needs
    #to be reseeded more often than every 623 values to avoid the pattern being
    #recognizable. Will aim for less than 512 before each reseeding. Will use the
    #file being randomized.
    rndfile=open('.rndtmp.tmp','w+b')
    torandomize.seek(0)
    #first chunk uses seedvalue: chunk length = max(128, last byte of seedvalue + middle byte of 
    # seedvalue)
    seedvalue=seedvalue.encode('utf-8')
    seedlength=len(seedvalue)
    midseed=trunc(seedlength/2)
    lastbyte = int.from_bytes(seedvalue[(seedlength-1):seedlength],byteorder='big')
    midbyte =  int.from_bytes(seedvalue[midseed:(midseed+1)],byteorder='big')
    chunksize=max(128,(lastbyte+midbyte))
    bytechunk = torandomize.read(chunksize)
    rndfile.seek(0)
    while bytechunk:
        randomized=randomizekeychunk(seedvalue,bytechunk)
        rndfile.write(randomized)
    #each chunk after first: seedvalue = 16 bytes from previous chunk starting at min(last byte of previous
    # chunk, previous chunk length - 32 bytes). chunk length = max(128, last byte of previous chunk + middle
    # previous chunk.
        lastbyte = int.from_bytes(randomized[chunksize-1:chunksize],byteorder='big')       
        seedstart=min(lastbyte,(chunksize-32))
        seedvalue = randomized[seedstart:(seedstart+16)]
        midchunk = trunc(chunksize/2)
        midbyte=int.from_bytes(randomized[midbyte:(midbyte+1)],byteorder='big')
        chunksize = max(128, (lastbyte+midbyte))
        bytechunk=torandomize.read(chunksize)
    rndfile.flush()
    return(rndfile)

def secureerasefile(toerase):
    '''
    Use this function instead of depending on tempfile, which is only dependable on *nix. Some people
    may want to use these encryption tools on one of the NROSs (not real operating systems).
    
    toerase    filetype object to be securely erased. Will be overwritten with '0' and then erased.
    
    returns result string on success.
    '''
    filebytes=os.stat(toerase.name).st_size
    steps=filebytes/256
    stepsleft = filebytes - 256*trunc(steps)
    zeroedbytes=b''
    for k in range(0,255):
        zeroedbytes+=b'0'
    toerase.seek(0)
    for k in range(0,trunc(steps)):
        toerase.write(zeroedbytes)
    for k in range(0,(stepsleft-1)):
        toerase.write(b'0')
    tempfd=toerase.name
    toerase.close()
    os.remove(tempfd)
    return('File Securely Erased')
    