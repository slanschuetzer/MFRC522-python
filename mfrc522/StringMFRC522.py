# Code by Simon Monk https://github.com/simonmonk/
# Adaption by Stefan Lanschützer https://github.com/slanschuetzer/

# Just needed a possibility to store more data onto my mifare-classic-cards, than fits on one sector.
# In fact i only need to store one big string (c-like terminated by 0x00)
# This library seemed to be easily adaptable to my needs.

from . import MFRC522
import RPi.GPIO as GPIO
import logging, sys
  
class StringMFRC522:

  READER = None
  
  KEY = [0xFF,0xFF,0xFF,0xFF,0xFF,0xFF]
  #BLOCK_ADDRS = [4, 5, 6, 8, 9, 10, 12, 13, 14, 16, 17, 18, 20, 21, 22, 24, 25, 26, 28, 29, 30, 32, 33, 34,
  #               36, 37, 38, 40, 41, 42, 44, 45, 46, 48, 49, 50, 52, 53, 54, 56, 57, 58, 60, 61, 62]
  BLOCK_ADDRS = [4, 5, 6, 8, 9, 10]
  
  def __init__(self):
    self.READER = MFRC522()
    logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
  
  def read(self):
      id, text = self.read_no_block()
      while not id:
          id, text = self.read_no_block()
      return id, text

  def read_id(self):
    id = self.read_id_no_block()
    while not id:
      id = self.read_id_no_block()
    return id

  def read_id_no_block(self):
      (status, TagType) = self.READER.MFRC522_Request(self.READER.PICC_REQIDL)
      if status != self.READER.MI_OK:
          return None
      (status, uid) = self.READER.MFRC522_Anticoll()
      if status != self.READER.MI_OK:
          return None
      return self.uid_to_num(uid)
  
  def read_no_block(self):
    (status, TagType) = self.READER.MFRC522_Request(self.READER.PICC_REQIDL)
    if status != self.READER.MI_OK:
        return None, None
    (status, uid) = self.READER.MFRC522_Anticoll()
    if status != self.READER.MI_OK:
        return None, None
    id = self.uid_to_num(uid)
    self.READER.MFRC522_SelectTag(uid)
    curr_block = self.BLOCK_ADDRS[0]
    curr_auth = curr_block - curr_block % 4 + 3
    status = self.READER.MFRC522_Auth(self.READER.PICC_AUTHENT1A, curr_auth, self.KEY, uid)
    data = []
    text_read = ''
    if status == self.READER.MI_OK:
        for block_num in self.BLOCK_ADDRS:
            logging.debug('Reading Block %d oldAuth %d requiredAuth %d',block_num, curr_auth, (block_num - block_num % 4 + 3))
            if curr_auth != block_num - block_num % 4 + 3:
                status = self.READER.MFRC522_Auth(self.READER.PICC_AUTHENT1A, curr_auth, self.KEY, uid)
                # self.READER.MFRC522_Read(curr_auth)
                if status != self.READER.MI_OK:
                  return None, None
            block = self.READER.MFRC522_Read(block_num) 
            if block:
                data += block
        if data:
             text_read = ''.join(chr(i) for i in data)
    self.READER.MFRC522_StopCrypto1()
    return id, text_read
    
  def write(self, text):
      id, text_in = self.write_no_block(text)
      while not id:
          id, text_in = self.write_no_block(text)
      return id, text_in

  def write_no_block(self, text):
      (status, TagType) = self.READER.MFRC522_Request(self.READER.PICC_REQIDL)
      if status != self.READER.MI_OK:
          return None, None
      (status, uid) = self.READER.MFRC522_Anticoll()
      if status != self.READER.MI_OK:
          return None, None
      id = self.uid_to_num(uid)
      self.READER.MFRC522_SelectTag(uid)
      curr_block = self.BLOCK_ADDRS[0]
      curr_auth = curr_block - curr_block % 4 + 3
      status = self.READER.MFRC522_Auth(self.READER.PICC_AUTHENT1A, curr_auth, self.KEY, uid)
      self.READER.MFRC522_Read(curr_auth)
      if status == self.READER.MI_OK:
          data = bytearray()
          data.extend(bytearray(text.ljust(len(self.BLOCK_ADDRS) * 16,chr(0)).encode('ascii')))
          i = 0
          for block_num in self.BLOCK_ADDRS:
            # TODO: here we should authenticate to the new sector on sector-change.

            if curr_auth != block_num - block_num % 4 + 3:
                status = self.READER.MFRC522_Auth(self.READER.PICC_AUTHENT1A, curr_auth, self.KEY, uid)
                self.READER.MFRC522_Read(curr_auth)
                if status != self.READER.MI_OK:
                  return None, None

            #self.READER.MFRC522_Write(block_num, data[(i*16):(i+1)*16])
            i += 1
      self.READER.MFRC522_StopCrypto1()
      return id, text[0:(len(self.BLOCK_ADDRS) * 16)]
      
  def uid_to_num(self, uid):
      n = 0
      for i in range(0, 5):
          n = n * 256 + uid[i]
      return n
