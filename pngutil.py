#This is not yet in function form. It was just a test jupyter script.
#Test png writer
import random as random
import zlib as zlib
png_sig = b'\x89PNG\r\n\x1a\n'
imageheadertype=b'IHDR'
datablocktype=b'IDAT'
endtype=b'IEND'
height=60
width=60
datasize=height*width*4
bitdepth=b'\x08' #8 bits, datasize wrong if 16 bits
colortype=b'\x06' # type 6, truecolor with alpha
compressionmethod=b'\x00' #0 only allowed
filtermethod=b'\x00' #0 only allowed
interlacemethod=b'\x00'#0 no interlace

def randbyte():
    return((random.randint(0,255)).to_bytes(1,byteorder='big'))

def chunkcrcgen(chunktype,chunkdata):
    return((zlib.crc32((chunktype+chunkdata))).to_bytes(4,byteorder='big'))

databytes =b''
for i in range(0,datasize):
    databytes+=randbyte()
#print(databytes)

f=open('test_rnd_png_short.png','bw')
#Write the signature
f.write(png_sig)

#Write the image header
chunkdata=b''
#print(str(int.from_bytes(chunkdata,byteorder='big')))
chunkdata+=width.to_bytes(4,byteorder='big') #width
chunkdata+=height.to_bytes(4,byteorder='big') #height
chunkdata+=bitdepth #bit depth
chunkdata+=colortype #color type
chunkdata+=compressionmethod #compression methode
chunkdata+=filtermethod #filter method
chunkdata+=interlacemethod #interlace method
CRC = chunkcrcgen(imageheadertype,chunkdata)
f.write(b'\x00\x00\x00\x0d'+imageheadertype+chunkdata+CRC)

#write the data (for now less than 2 G)
compr=zlib.compress(databytes,0) #no compression
CRC = chunkcrcgen(datablocktype,compr)
print(len(compr))
f.write(len(compr).to_bytes(4,byteorder='big')+datablocktype+compr+CRC)

#write the end statement
CRC=chunkcrcgen(endtype,b'')
f.write(b'\x00\x00\x00\x00'+endtype+CRC)

f.close()