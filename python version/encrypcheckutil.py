#Utilities for checking randomness of a file

from scipy.optimize import curve_fit as curve_fit
from numpy import exp as exp
import numpy as np
import os as os
from Cryptodome.Cipher import AES as AES

def exp_for_fit(x,y0,A,tau):
    y = np.empty(x.size)
    for i in range (0,x.size):
        y[i]=(y0+A*exp(-x[i]/tau))        
    return (y)
    
def gauss_for_fit(x,y0,A,tau):
    y = np.empty(x.size)
    for i in range (0,x.size):
        y[i]=y0+A*exp(-(x[i]/tau)**2)        
    return (y)

def line_for_fit(x,b,m):
    y = np.empty(x.size)
    for i in range(0,x.size):
        y[i]=b+m*x[i]
    return(y)
    
def fit_to_exp(xdata,ydata, verbose=False):
    npoints = len(ydata)
    stop = npoints-1
    tailpts = int(np.ceil(npoints/10))
    start = stop - tailpts
    guessy0 = sum(ydata[start:stop])/tailpts
    guessA=ydata[0]-guessy0
    guesstau=np.abs(xdata[1]/np.log(np.abs((ydata[1]-guessy0)/guessA)))
    popt,pcov=curve_fit(exp_for_fit,xdata,ydata,p0=(guessy0,guessA,guesstau))
    if verbose:
        print('Start: '+str(start)+' Stop: '+str(stop))
        print ('guessy0 :'+str(guessy0))
        print ('guessA: '+str(guessA))
        print ('guesstau: '+str(guesstau))
        print('fit: y='+str(popt[0])+'+'+str(popt[1])+'*exp(-x/'+str(popt[2])+')')
        print('covariance:\n'+str(pcov))
    return (popt,pcov)

def fit_to_gauss(xdata,ydata, verbose=False):
    npoints = len(ydata)
    stop = npoints-1
    tailpts = int(np.ceil(npoints/10))
    start = stop - tailpts
    guessy0 = sum(ydata[start:stop])/tailpts
    guessA=ydata[0]-guessy0
    guesstau=np.sqrt(np.abs(xdata[1]**2/np.log(np.abs((ydata[1]-guessy0)/guessA))))
    popt,pcov=curve_fit(gauss_for_fit,xdata,ydata,p0=(guessy0,guessA,guesstau))
    if verbose:
        print('Start: '+str(start)+' Stop: '+str(stop))
        print ('guessy0 :'+str(guessy0))
        print ('guessA: '+str(guessA))
        print ('guesstau: '+str(guesstau))
        print('fit: y='+str(popt[0])+'+'+str(popt[1])+'*exp(-(x/'+str(popt[2])+')**2)')
        print('covariance:\n'+str(pcov))
    return (popt,pcov)
    
def fit_to_line(xdata,ydata, verbose=False):
    npoints = len(ydata)
    stop = npoints-1
    tailpts = int(np.ceil(npoints/10))
    start = stop - tailpts
    mguess = (ydata[stop]-ydata[0])/(xdata[stop]-xdata[0])
    bguess = ydata[tailpts]-mguess*xdata[tailpts]
    popt,pcov=curve_fit(line_for_fit,xdata,ydata,p0=(bguess,mguess))
    if verbose:
        print('Start: '+str(start)+' Stop: '+str(stop))
        print ('bguess :'+str(bguess))
        print ('mguess: '+str(mguess))
        print('fit: y='+str(popt[0])+'+'+str(popt[1])+'*x')
        print('covariance:\n'+str(pcov))
    return (popt,pcov)
    
def rmsdev (set1, set2):
    """
    set1     a list of numbers (would an array be faster)
    set2     a list of numbers of the same length as set 1
    returns  rms difference between the two sets
    """
    len1=len(set1)
    len2=len(set2)
    if len1!=len2:
        raise IndexError('Sets must be of same length!')
    sum = 0
    for i in range(0,len1):
        sum+=(set1[i]-set2[i])**2
    return (sum/len1)**0.5
    
def slurpfilebytesasarray(filepath):
    '''
    filepath     The path to the file can be relative to current directory.
    returns a np integer array of byte values.
    '''
    f = open(filepath,'br')
    print('Reading file: '+f.name)
    filesize = os.stat(filepath).st_size
    print ('File size: '+str(filesize))
    bytechunk = f.read(65535)
    values=np.empty(filesize,dtype=int)
    count=0
    chunkoffset=0
    while bytechunk:
#       print(bytechunk)
        byte = bytechunk[0:1]
        count=1
        while byte:
            int_val=int.from_bytes(byte,byteorder='big')
#           print (int_val)
            values[(count+chunkoffset-1)]=int_val
            byte=bytechunk[count:count+1]
            count+=1
        bytechunk=f.read(65535)
        chunkoffset+=65535
    f.close()
    return values
    
def rmsdevautocorr(values):
    '''
    values     numpy integer array of bytes
    returns    (xvalues,yvalues)
        yvalues=rmsdev and xvalues=offset of array versus itself
        This function samples a maximum of 512 offsets with the maximum offset
        being len(values)/2. The first 256 offsets are spaced one (1) apart. The
        remaining offsets are randomly sampled from each of 256 constant sized
        intervals that fill out the remaining offsets to len(values)/2.
    '''
    n = len(values)
    offsetmax = int(np.ceil(n/2))
    stepsize = int(np.floor((offsetmax-256)/256))
    yvalues=np.empty(512)
    xvalues=np.empty(512,dtype=int)
    #print ('len x and y arrays: '+str(len(yvalues)))
    yvalues[0]=0
    xvalues[0]=0
    for i in range (1,256):
        shifted = np.roll(values,i)
        yvalues[i]=rmsdev(values,shifted)
        xvalues[i]= i
    for i in range (1,257):
        offset = np.random.randint(i*stepsize,(i+1)*stepsize-1)
        if offset > offsetmax:
            offset = offsetmax
        shifted = np.roll(values,offset)
        yvalues[255+i]=rmsdev(values,shifted)
        xvalues[255+i]=offset
    return (xvalues,yvalues)
    
def envelope(x,y):
    '''
    x       xdata
    y       ydata
    returns (upperenvx, upperenvy, lowerenvx, lowerenvy)
    Uses discrete (digital) derivatives to find local max and min. Maxes go into upperenv
      and min go into lowerenv. First and last points of the data set determine slopes, and
      are kept as part of the envelope, despite the fact that they might not be a max or min.
    '''
    size = len(x)
    upperenvx = np.empty(size)
    upperenvy = np.empty(size)
    lowerenvx = np.empty(size)
    lowerenvy = np.empty(size)
    upperenvx[0]=x[0]
    upperenvy[0]=y[0]
    lowerenvx[0]=x[0]
    lowerenvy[0]=y[0]
    uppercount = 1
    lowercount = 1
    for i in range(1,(size-1)):
        lslope = (y[i]-y[i-1])/(x[i]-x[i-1])
        rslope = (y[i+1]-y[i])/(x[i+1]-x[i])
        if (lslope*rslope < 0):
            if (rslope < 0):
                upperenvx[uppercount]=x[i]
                upperenvy[uppercount]=y[i]
                uppercount+=1
            else:
                lowerenvx[lowercount]=x[i]
                lowerenvy[lowercount]=y[i]
                lowercount+=1
    upperenvx[uppercount]=x[size-1]
    upperenvy[uppercount]=y[size-1]
    lowerenvx[lowercount]=x[size-1]
    lowerenvy[lowercount]=y[size-1]
    upperenvx.resize(uppercount+1)
    upperenvy.resize(uppercount+1)
    lowerenvx.resize(lowercount+1)
    lowerenvy.resize(lowercount+1)
    return(upperenvx, upperenvy, lowerenvx, lowerenvy)

def smoothenv(x,y,npass=2):
    '''
    x     xdata
    y     ydata
    npass number of passes with the envelope function to produce a smoothed envelope.
    returns (upperenvx, upperenvy, lowerenvx, lowerenvy)
    Uses discrete (digital) derivatives to find local max and min. Maxes go into upperenv
      and min go into lowerenv. First and last points of the data set determine slopes, and
      are kept as part of the envelope, despite the fact that they might not be a max or min.    
    '''
    upperenvx, upperenvy, lowerenvx, lowerenvy=envelope(x,y)
    for i in range(1,npass):
        #print ('Starting pass '+str(i)+'.')
        upperenvx, upperenvy, lowerupperx, loweruppery=envelope(upperenvx,upperenvy)
        upperlowerx, upperlowery, lowerenvx, lowerenvy=envelope(lowerenvx,lowerenvy)
    return (upperenvx, upperenvy, lowerenvx, lowerenvy)
    
def AESencrypt(fileobj, filename, key):
    '''
    fileobj      file type object open in binary read mode that is to be encrypted
    filename     string version of the file name (no path) so that we can get
                 any special characters.
    key          32 byte random key (this needs to be cryptographically good).
         returns a file object pointing to the encrypted data in a temporary file.
    '''
    cipher = AES.new(key, AES.MODE_CFB)
    encrypted=open('.tmpcrypt.ecr','wb')
    encrypted.write(cipher.iv)
    fileobj.seek(0)
    bytes=fileobj.read(256)
    while bytes:
        encrypted.write(cipher.encrypt(bytes))
        bytes=fileobj.read(256)
    fileobj.close()
    return (encrypted)
    
def AESdecrypt(todecrypt,key):
    '''
    todecrypt     filelike object open in binary read mode
    key           32 byte decryption key
         returns a file object pointing to the decrypted data in a temporary file.
    '''
    cipher = AES.new(key, AES.MODE_CFB)
    decrypted=open('.tempdecr.AES','wb')
    todecrypt.seek(0)
    initvec = cipher.decrypt(todecrypt.read(16))
    bytes = todecrypt.read(256)
    while bytes:
        decrypted.write(cipher.decrypt(bytes))
        bytes=todecrypt.read(256)
    todecrypt.close()
    return(decrypted)